#!/usr/bin/env python3
"""
Convert full Process Monitor TSV log to enhanced SIEM CSV format
Preserves all ProcMon fields for complete provenance graph analysis
"""

import csv
import re
from datetime import datetime

# Read the TSV file
def parse_procmon_tsv(tsv_file_path):
    """Parse Process Monitor TSV format log"""

    output_rows = []
    seen_entries = set()  # To deduplicate similar events

    with open(tsv_file_path, 'r', encoding='utf-8') as f:
        # Skip BOM if present
        content = f.read()
        if content.startswith('\ufeff'):
            content = content[1:]

        lines = content.strip().split('\n')

        # Find header
        header_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('Time of Day\t'):
                header_idx = i
                break

        # Parse header
        header = lines[header_idx].split('\t')

        # Process data lines
        for line in lines[header_idx + 1:]:
            if not line.strip():
                continue

            parts = line.split('\t')
            if len(parts) < 6:
                continue

            # Extract fields
            time_str = parts[0].strip()
            process_name = parts[1].strip()
            pid = parts[2].strip()
            operation = parts[3].strip()
            path = parts[4].strip()
            result = parts[5].strip()
            detail = parts[6].strip() if len(parts) > 6 else ''

            # Only process SUCCESS operations on actual files
            if result not in ['SUCCESS']:
                continue

            # Filter for file operations (not just metadata queries)
            relevant_operations = [
                'CreateFile', 'ReadFile', 'WriteFile', 'QueryDirectory',
                'SetDispositionInformationFile', 'SetRenameInformationFile',
                'DeleteFile', 'FileSystemControl'
            ]

            if operation not in relevant_operations:
                continue

            # Skip operations that are just reading attributes/metadata
            if 'Read Attributes' in detail and 'Read Data' not in detail:
                # Only skip pure attribute reads, not file opens with read intent
                if operation == 'CreateFile' and 'Desired Access: Read Attributes' in detail:
                    # Check if it's ONLY reading attributes
                    if 'Read Data' not in detail and 'Read Control' not in detail:
                        continue

            # Skip directory operations unless it's QueryDirectory with file results
            if operation == 'QueryDirectory':
                # Only include if it lists actual files
                if not any(keyword in detail for keyword in ['.docx', '.txt', 'credentials', 'Confidential']):
                    continue

            # Extract filename from path
            if '\\' in path:
                filename = path.split('\\')[-1]
            else:
                filename = path

            # Skip if it's just a directory (unless QueryDirectory)
            if not filename or filename in ['SensitiveDocs', 'SensitiveDocs_copy', '.', '..']:
                if operation != 'QueryDirectory':
                    continue

            # Only include operations on files in SensitiveDocs folder
            if 'SensitiveDocs' not in path:
                continue

            # Skip if file doesn't have extension (likely directory)
            if '.' not in filename and operation != 'QueryDirectory':
                continue

            # Create unique key to reduce duplicates (keep some for provenance)
            # We want to keep CreateFile and ReadFile events separately
            unique_key = f"{time_str}_{pid}_{operation}_{filename}"

            # For CreateFile, only keep significant ones
            if operation == 'CreateFile':
                # Keep only file opens that involve reading/writing data
                if not any(keyword in detail for keyword in ['Read Data', 'Write Data', 'Append Data', 'Execute', 'Read Control']):
                    continue

            # Parse time (format: MM:SS.s)
            match = re.match(r'(\d+):(\d+)\.\d+', time_str)
            if not match:
                continue

            minutes = int(match.group(1))
            seconds = int(match.group(2))

            # Create ISO timestamp (using today's date + time from log)
            # Using 09:XX:00 format (hour 09 for morning)
            timestamp = f"2025-11-25T09:{minutes:02d}:{seconds:02d}"

            # Determine if this is a honeyfile
            is_honeyfil = False
            honeyfile_keywords = ['credentials', 'confidential', 'secret', 'password', 'backup']

            for keyword in honeyfile_keywords:
                if keyword.lower() in filename.lower() or keyword.lower() in path.lower():
                    is_honeyfil = True
                    break

            # Map operation to simpler action
            action_map = {
                'CreateFile': 'open',
                'ReadFile': 'read',
                'WriteFile': 'write',
                'QueryDirectory': 'list',
                'SetDispositionInformationFile': 'delete',
                'SetRenameInformationFile': 'rename',
                'DeleteFile': 'delete'
            }
            action = action_map.get(operation, operation.lower())

            # Create row with ALL ProcMon fields preserved
            row = {
                'timestamp': timestamp,
                'user': process_name,  # Using process name as user
                'action': action,
                'file_path': path,
                'ip_address': '127.0.0.1',  # Local access
                'is_honeyfil': 'true' if is_honeyfil else 'false',
                'process_name': process_name,
                'pid': pid,
                'operation': operation,
                'result': result,
                'detail': detail
            }

            output_rows.append(row)

    return output_rows

def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python convert_full_procmon.py <input_tsv_file> [output_csv_file]")
        print("\nExample:")
        print("  python convert_full_procmon.py procmon_raw.tsv procmon_enhanced.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'procmon_enhanced.csv'

    print(f"Parsing Process Monitor log: {input_file}")
    rows = parse_procmon_tsv(input_file)

    # Write to CSV
    if rows:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['timestamp', 'user', 'action', 'file_path', 'ip_address',
                         'is_honeyfil', 'process_name', 'pid', 'operation', 'result', 'detail']
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        print(f"\n✓ Successfully converted {len(rows)} events to {output_file}")

        # Analysis summary
        honeyfil_events = sum(1 for row in rows if row['is_honeyfil'] == 'true')
        unique_files = len(set(row['file_path'] for row in rows))

        print(f"\n📊 Analysis Summary:")
        print(f"   Total Events: {len(rows)}")
        print(f"   Honeyfile Events: {honeyfil_events}")
        print(f"   Unique Files Accessed: {unique_files}")

        # List honeyfiles accessed
        honeyfiles = set(row['file_path'] for row in rows if row['is_honeyfil'] == 'true')
        if honeyfiles:
            print(f"\n🍯 Honeyfiles Detected:")
            for hf in sorted(honeyfiles):
                filename = hf.split('\\')[-1]
                count = sum(1 for row in rows if row['file_path'] == hf)
                print(f"   🚨 {filename} ({count} accesses)")
    else:
        print("❌ No events found to convert")

if __name__ == '__main__':
    main()
