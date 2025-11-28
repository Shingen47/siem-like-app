#!/usr/bin/env python3
"""
Create filtered CSV with at least 50 important events from Process Monitor log
Removes noise while keeping significant security events
"""

import csv
import re
from collections import defaultdict

# Paste your TSV content here (or read from file)
tsv_file = 'procmon_complete.tsv'

def parse_and_filter():
    """Parse TSV and create filtered CSV with 50+ events"""

    with open(tsv_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Skip header
    header_found = False
    events = []

    for line in lines:
        if 'Time of Day' in line:
            header_found = True
            continue
        if not header_found or not line.strip():
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

        if event['result'] == 'SUCCESS':
            events.append(event)

    print(f"Parsed {len(events)} successful operations")

    # Filter strategy: Keep important events
    filtered = []
    file_access_count = defaultdict(int)

    for event in events:
        operation = event['operation']
        path = event['path']
        detail = event['detail']

        # Skip pure noise operations
        if operation in ['CloseFile', 'QueryBasicInformationFile', 'QueryStandardInformationFile']:
            continue

        # Always keep directory listings showing files
        if operation == 'QueryDirectory':
            if any(f in detail for f in ['Confidential', 'credentials', '.docx', '.txt']):
                filtered.append(event)
                continue

        # Keep ReadFile operations
        if operation == 'ReadFile':
            filtered.append(event)
            continue

        # For CreateFile, be selective
        if operation == 'CreateFile':
            # Skip pure attribute reads
            if 'Read Attributes' in detail and 'Read Data' not in detail and 'Read Control' not in detail:
                continue

            # Keep if it's accessing honeyfiles (limit to 3 per file)
            is_honeyfile = any(k in path.lower() for k in ['confidential', 'credentials'])
            if is_honeyfile:
                file_access_count[path] += 1
                if file_access_count[path] <= 3:
                    filtered.append(event)
                    continue

            # Keep first access to directories with Read Data
            if 'Read Data' in detail or 'List Directory' in detail:
                if file_access_count[path] == 0:
                    filtered.append(event)
                    file_access_count[path] += 1
                    continue

        # Keep other interesting operations
        if operation in ['WriteFile', 'SetDispositionInformationFile', 'SetRenameInformationFile']:
            filtered.append(event)

    print(f"After filtering: {len(filtered)} significant events")

    # If still under 50, add more CreateFile operations
    if len(filtered) < 50:
        print(f"Adding more events to reach 50...")
        for event in events:
            if event in filtered:
                continue
            if event['operation'] == 'CreateFile' and len(filtered) < 50:
                if 'Read Control' in event['detail']:
                    filtered.append(event)

    return filtered

def convert_to_csv(events):
    """Convert events to CSV format"""

    rows = []
    for event in events:
        time_str = event['time']
        match = re.match(r'(\d+):(\d+)\.\d+', time_str)
        if not match:
            continue

        minutes = int(match.group(1))
        seconds = int(match.group(2))
        timestamp = f"2025-11-25T09:{minutes:02d}:{seconds:02d}"

        path = event['path']
        is_honeyfil = any(k in path.lower() for k in ['confidential', 'credentials', 'secret', 'password'])

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
        rows.append(row)

    return rows

# Main execution
events = parse_and_filter()
rows = convert_to_csv(events)

# Write CSV
output_file = 'procmon_filtered_50plus.csv'
with open(output_file, 'w', newline='', encoding='utf-8') as f:
    fieldnames = ['timestamp', 'user', 'action', 'file_path', 'ip_address',
                 'is_honeyfil', 'process_name', 'pid', 'operation', 'result', 'detail']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

# Summary
honeyfil_count = sum(1 for r in rows if r['is_honeyfil'] == 'true')
unique_files = len(set(r['file_path'] for r in rows))

print(f"\n✅ Created {output_file}")
print(f"\n📊 Final Statistics:")
print(f"   Total Events: {len(rows)}")
print(f"   Honeyfile Access Events: {honeyfil_count}")
print(f"   Unique Files: {unique_files}")
print(f"\n🍯 Honeyfiles Detected:")
honeyfiles = sorted(set(r['file_path'] for r in rows if r['is_honeyfil'] == 'true'))
for hf in honeyfiles:
    filename = hf.split('\\')[-1] if '\\' in hf else hf
    count = sum(1 for r in rows if r['file_path'] == hf)
    print(f"   🚨 {filename} - {count} accesses")
