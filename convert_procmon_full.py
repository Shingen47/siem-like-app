#!/usr/bin/env python3
"""
Enhanced Process Monitor to CSV converter
Preserves all ProcMon fields including process details, operations, and results
"""

import csv
import re
from datetime import datetime

def parse_procmon_log(log_content):
    """Parse Process Monitor TSV log with full details"""
    logs = []
    lines = log_content.strip().split('\n')

    # Skip header line
    if not lines:
        return logs

    header = lines[0].split('\t')

    for line in lines[1:]:
        if not line.strip():
            continue

        parts = line.split('\t')
        if len(parts) < 6:
            continue

        time_str = parts[0].strip()
        process_name = parts[1].strip()
        pid = parts[2].strip()
        operation = parts[3].strip()
        path = parts[4].strip()
        result = parts[5].strip()
        detail = parts[6].strip() if len(parts) > 6 else ''

        # Parse time (format: MM:SS.s)
        match = re.match(r'(\d+):(\d+)\.(\d+)', time_str)
        if not match:
            continue

        minutes = int(match.group(1))
        seconds = int(match.group(2))
        milliseconds = int(match.group(3)) * 100

        # Create ISO timestamp
        timestamp = f"2025-11-25T00:{minutes:02d}:{seconds:02d}.{milliseconds:03d}"

        # Determine if this is a file operation we care about
        file_operations = ['CreateFile', 'ReadFile', 'WriteFile', 'QueryDirectory',
                          'SetInformationFile', 'QueryInformationFile', 'CloseFile']

        # Check if it's a honeyfil
        is_honeyfil = 'false'
        if 'credentials' in path.lower() or 'confidential' in path.lower() or 'secret' in path.lower():
            is_honeyfil = 'true'

        # Extract file path (last part of path)
        file_name = path.split('\\')[-1] if '\\' in path else path

        # Only process successful operations on actual files
        if result == 'SUCCESS' and operation in file_operations:
            # Skip directory-only operations
            if file_name in ['SensitiveDocs', 'SensitiveDocs_copy', '.', '..']:
                continue

            log_entry = {
                'timestamp': timestamp,
                'process_name': process_name,
                'pid': pid,
                'operation': operation,
                'path': path,
                'result': result,
                'detail': detail,
                'user': process_name,  # For dashboard compatibility
                'action': operation.lower().replace('file', ''),
                'file_path': path,
                'ip_address': '127.0.0.1',
                'is_honeyfil': is_honeyfil
            }
            logs.append(log_entry)

    return logs

def save_enhanced_csv(logs, filename='procmon_full.csv'):
    """Save logs with all ProcMon fields"""
    if not logs:
        print("No logs to save")
        return

    fieldnames = ['timestamp', 'process_name', 'pid', 'operation', 'path',
                  'result', 'detail', 'user', 'action', 'file_path',
                  'ip_address', 'is_honeyfil']

    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for log in logs:
            writer.writerow(log)

    print(f"✓ Saved {len(logs)} events to {filename}")

    # Print statistics
    operations = {}
    honeyfils = set()
    processes = set()

    for log in logs:
        op = log['operation']
        operations[op] = operations.get(op, 0) + 1
        processes.add(f"{log['process_name']} (PID: {log['pid']})")

        if log['is_honeyfil'] == 'true':
            honeyfils.add(log['path'].split('\\')[-1])

    print(f"\n📊 Statistics:")
    print(f"  - Total events: {len(logs)}")
    print(f"  - Unique processes: {len(processes)}")
    print(f"  - Honeyfils accessed: {len(honeyfils)}")
    print(f"\n📁 Operations breakdown:")
    for op, count in sorted(operations.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {op}: {count}")

    if honeyfils:
        print(f"\n🍯 Honeyfiles detected:")
        for hf in sorted(honeyfils):
            print(f"  - {hf}")

# Example usage
if __name__ == '__main__':
    # This would normally read from your ProcMon export
    print("Enhanced Process Monitor Log Converter")
    print("=" * 60)
    print("\nTo use: Provide your ProcMon TSV export")
    print("The converter will extract full details including:")
    print("  - Process names and PIDs")
    print("  - All file operations")
    print("  - Operation results and details")
    print("  - Honeyfile detection")
