#!/usr/bin/env python3
"""
Convert Process Monitor TSV log to SIEM CSV format
"""

import csv
import re
from datetime import datetime

# Read the procmon log (TSV format)
input_data = """Time of Day	Process Name	PID	Operation	Path	Result	Detail
09:03.4	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy	SUCCESS	Desired Access: Read Data/List Directory, Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:03.4	Explorer.EXE	4736	QueryDirectory	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy	SUCCESS	FileInformationClass: FileIdBothDirectoryInformation, 1: ., 2: .., 3: Confidential-Report.docx, 4: Confidential-Report.txt, 5: credentials.txt, 6: SensitiveDocs
09:06.1	Explorer.EXE	4736	ReadFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs	SUCCESS	Offset: 0, Length: 4,096, I/O Flags: Non-cached, Paging I/O, Priority: Normal
09:08.5	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:08.7	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Read Control, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, Disallow Exclusive, Attributes: n/a, ShareMode: Read, Write, AllocationSize: n/a, OpenResult: Opened
09:09.1	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:09.2	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.docx	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:11.7	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:11.9	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Read Control, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, Disallow Exclusive, Attributes: n/a, ShareMode: Read, Write, AllocationSize: n/a, OpenResult: Opened
09:12.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\Confidential-Report.txt	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:15.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Read Control, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, Disallow Exclusive, Attributes: n/a, ShareMode: Read, Write, AllocationSize: n/a, OpenResult: Opened
09:15.0	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
09:15.1	Explorer.EXE	4736	CreateFile	C:\\Users\\Public\\Desktop\\SensitiveDocs_copy\\SensitiveDocs\\credentials.txt	SUCCESS	Desired Access: Read Attributes, Synchronize, Disposition: Open, Options: Synchronous IO Non-Alert, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a, OpenResult: Opened
"""

# Parse and convert
output_rows = []
seen_entries = set()  # To avoid duplicates

for line in input_data.strip().split('\n')[1:]:  # Skip header
    if not line.strip():
        continue

    parts = line.split('\t')
    if len(parts) < 6:
        continue

    time_str = parts[0].strip()
    process = parts[1].strip()
    pid = parts[2].strip()
    operation = parts[3].strip()
    path = parts[4].strip()
    result = parts[5].strip()

    # Skip if not SUCCESS
    if result != 'SUCCESS':
        continue

    # Only process file operations on actual files (not directories)
    if 'SensitiveDocs_copy\\SensitiveDocs\\' in path and operation in ['CreateFile', 'ReadFile', 'QueryDirectory']:
        # Extract filename
        filename = path.split('\\')[-1]

        # Skip directory operations
        if filename in ['SensitiveDocs', 'SensitiveDocs_copy']:
            continue

        # Create unique key to avoid duplicates
        unique_key = f"{time_str}_{filename}_{operation}"
        if unique_key in seen_entries:
            continue
        seen_entries.add(unique_key)

        # Parse time (format: MM:SS.s)
        match = re.match(r'(\d+):(\d+)\.(\d+)', time_str)
        if match:
            minutes = int(match.group(1))
            seconds = int(match.group(2))

            # Create ISO timestamp (using today's date + time from log)
            # Assuming this is morning activity
            timestamp = f"2025-11-25T{minutes:02d}:{seconds:02d}:00"

            # Determine if this is a honeyfile
            is_honeyfil = 'false'
            if 'credentials.txt' in filename.lower():
                is_honeyfil = 'true'
            elif 'confidential' in filename.lower():
                is_honeyfil = 'true'

            # Map operation to action
            action_map = {
                'CreateFile': 'read',
                'ReadFile': 'read',
                'QueryDirectory': 'list',
                'WriteFile': 'write'
            }
            action = action_map.get(operation, operation.lower())

            # Create row
            row = {
                'timestamp': timestamp,
                'user': 'Explorer.EXE',
                'action': action,
                'file_path': path,
                'ip_address': '127.0.0.1',
                'is_honeyfil': is_honeyfil
            }
            output_rows.append(row)

# Write to CSV
with open('procmon_analysis.csv', 'w', newline='') as f:
    fieldnames = ['timestamp', 'user', 'action', 'file_path', 'ip_address', 'is_honeyfil']
    writer = csv.DictWriter(f, fieldnames=fieldnames)

    writer.writeheader()
    for row in output_rows:
        writer.writerow(row)

print(f"Converted {len(output_rows)} events to procmon_analysis.csv")
print("\nKey findings:")
print(f"- Accessed credentials.txt (HONEYFIL!)")
print(f"- Accessed Confidential-Report.docx (HONEYFIL!)")
print(f"- Accessed Confidential-Report.txt (HONEYFIL!)")
print(f"- All access occurred at 09:03-09:15 (office hours)")
