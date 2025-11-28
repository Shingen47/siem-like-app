#!/usr/bin/env python3
"""
Filter Process Monitor logs to keep only significant events
Removes noise while preserving at least 50 important events
"""

import csv
import re
from collections import defaultdict

def parse_procmon_tsv_complete(tsv_content):
    """Parse complete Process Monitor TSV and filter intelligently"""

    lines = tsv_content.strip().split('\n')

    # Find header
    header_idx = 0
    for i, line in enumerate(lines):
        if 'Time of Day\t' in line:
            header_idx = i
            break

    events = []
    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue

        parts = line.split('\t')
        if len(parts) < 6:
            continue

        event = {
            'time': parts[0].strip(),
            'process': parts[1].strip(),
            'pid': parts[2].strip(),
            'operation': parts[3].strip(),
            'path': parts[4].strip(),
            'result': parts[5].strip(),
            'detail': parts[6].strip() if len(parts) > 6 else ''
        }
        events.append(event)

    return events

def filter_significant_events(events):
    """Filter to keep only significant events"""

    significant = []
    seen_operations = defaultdict(set)  # Track what we've seen per file

    # Priority operations (always keep first occurrence)
    priority_ops = {'QueryDirectory', 'ReadFile', 'WriteFile', 'CreateFile'}

    # Operations to skip (pure noise)
    skip_ops = {'CloseFile', 'QueryBasicInformationFile', 'QueryStandardInformationFile'}

    for event in events:
        if event['result'] != 'SUCCESS':
            continue

        operation = event['operation']
        path = event['path']

        # Skip pure noise operations
        if operation in skip_ops:
            continue

        # Extract filename
        if '\\' in path:
            filename = path.split('\\')[-1]
        else:
            filename = path

        # Key for tracking duplicates
        key = f"{operation}_{path}"

        # Keep if it's a priority operation and first time seeing it
        if operation in priority_ops:
            if key not in seen_operations[path]:
                # For CreateFile, only keep if it has meaningful access
                if operation == 'CreateFile':
                    detail = event['detail']
                    # Skip if only reading attributes
                    if 'Read Attributes' in detail and 'Read Data' not in detail and 'Read Control' not in detail:
                        continue

                significant.append(event)
                seen_operations[path].add(key)
                continue

        # Keep QueryDirectory if it shows honeyfiles
        if operation == 'QueryDirectory':
            detail = event['detail']
            if any(keyword in detail for keyword in ['credentials', 'Confidential', '.docx', '.txt']):
                if key not in seen_operations[path]:
                    significant.append(event)
                    seen_operations[path].add(key)
                    continue

        # Keep operations on honeyfiles (but deduplicate)
        is_honeyfile = any(keyword in path.lower() for keyword in ['credentials', 'confidential'])
        if is_honeyfile:
            # For honeyfiles, keep multiple accesses but limit duplicates
            if len([e for e in significant if e['path'] == path and e['operation'] == operation]) < 3:
                significant.append(event)

    return significant

def convert_to_csv_format(events):
    """Convert filtered events to enhanced CSV format"""

    output_rows = []

    for event in events:
        time_str = event['time']

        # Parse time (format: MM:SS.s)
        match = re.match(r'(\d+):(\d+)\.\d+', time_str)
        if not match:
            continue

        minutes = int(match.group(1))
        seconds = int(match.group(2))

        # Create ISO timestamp
        timestamp = f"2025-11-25T09:{minutes:02d}:{seconds:02d}"

        # Determine if honeyfile
        path = event['path']
        is_honeyfil = any(keyword in path.lower() for keyword in ['credentials', 'confidential', 'secret', 'password'])

        # Map operation to action
        action_map = {
            'CreateFile': 'open',
            'ReadFile': 'read',
            'WriteFile': 'write',
            'QueryDirectory': 'list',
            'SetDispositionInformationFile': 'delete',
            'SetRenameInformationFile': 'rename'
        }
        action = action_map.get(event['operation'], event['operation'].lower())

        row = {
            'timestamp': timestamp,
            'user': event['process'],
            'action': action,
            'file_path': path,
            'ip_address': '127.0.0.1',
            'is_honeyfil': 'true' if is_honeyfil else 'false',
            'process_name': event['process'],
            'pid': event['pid'],
            'operation': event['operation'],
            'result': event['result'],
            'detail': event['detail']
        }
        output_rows.append(row)

    return output_rows

# Read the pasted TSV content
tsv_content = """Time of Day	Process Name	PID	Operation	Path	Result	Detail
09:03.4	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy	SUCCESS	Desired Access: Read Data/List Directory, Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:03.4	Explorer.EXE	4736	QueryDirectory	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy	SUCCESS	FileInformationClass: FileIdBothDirectoryInformation, 1: ., 2: .., 3: Confidential-Report.docx, 4: Confidential-Report.txt, 5: credentials.txt, 6: SensitiveDocs
09:03.4	Explorer.EXE	4736	QueryDirectory	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy	NO MORE FILES	FileInformationClass: FileIdBothDirectoryInformation
09:03.4	Explorer.EXE	4736	CloseFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy	SUCCESS
09:06.1	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs	SUCCESS	Desired Access: Read Data/List Directory, Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:06.1	Explorer.EXE	4736	QueryDirectory	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs	SUCCESS	FileInformationClass: FileIdBothDirectoryInformation, 1: ., 2: .., 3: Confidential-Report.docx, 4: Confidential-Report.txt, 5: credentials.txt
09:06.1	Explorer.EXE	4736	ReadFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs	SUCCESS	Offset: 0, Length: 4,096, I/O Flags: Non-cached, Paging I/O, Priority: Normal
09:08.5	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:08.7	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Read Control, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, Disallow Exclusive, Attributes: n/a, ShareMode: Read, Write, AllocationSize: n/a, OpenResult: Opened
09:08.7	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:08.8	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Read Control, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, Disallow Exclusive, Attributes: n/a, ShareMode: Read, Write, AllocationSize: n/a, OpenResult: Opened
09:08.9	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:09.1	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:09.2	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:11.7	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:11.9	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Read Control, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, Disallow Exclusive, Attributes: n/a, ShareMode: Read, Write, AllocationSize: n/a, OpenResult: Opened
09:11.9	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:11.9	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:12.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:12.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:12.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:15.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Read Control, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, Disallow Exclusive, Attributes: n/a, ShareMode: Read, Write, AllocationSize: n/a, OpenResult: Opened
09:15.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:15.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:15.1	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:15.1	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
"""

# Parse events
events = parse_procmon_tsv_complete(tsv_content)
print(f"Total events parsed: {len(events)}")

# Filter to significant events
significant = filter_significant_events(events)
print(f"Significant events after filtering: {len(significant)}")

# Convert to CSV format
csv_rows = convert_to_csv_format(significant)

# If we don't have 50 events, relax filtering
if len(csv_rows) < 50:
    print("\nNeed more events, including additional operations...")
    # Include more CreateFile events with Read Control access
    for event in events:
        if event['result'] == 'SUCCESS' and event['operation'] == 'CreateFile':
            detail = event['detail']
            if 'Read Control' in detail or 'Read Attributes' in detail:
                # Add if not already in significant
                if event not in significant:
                    significant.append(event)
                    if len(significant) >= 50:
                        break

    csv_rows = convert_to_csv_format(significant)

print(f"Final event count: {len(csv_rows)}")

# Write to CSV
with open('procmon_filtered_50.csv', 'w', newline='', encoding='utf-8') as f:
    fieldnames = ['timestamp', 'user', 'action', 'file_path', 'ip_address',
                 'is_honeyfil', 'process_name', 'pid', 'operation', 'result', 'detail']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in csv_rows:
        writer.writerow(row)

print(f"\n✓ Created procmon_filtered_50.csv with {len(csv_rows)} events")

# Show summary
honeyfil_count = sum(1 for row in csv_rows if row['is_honeyfil'] == 'true')
print(f"\n📊 Summary:")
print(f"   Total Events: {len(csv_rows)}")
print(f"   Honeyfile Events: {honeyfil_count}")
print(f"   Unique Files: {len(set(row['file_path'] for row in csv_rows))}")
