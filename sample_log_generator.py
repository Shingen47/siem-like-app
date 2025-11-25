#!/usr/bin/env python3
"""
Sample Log Generator for SIEM Dashboard Testing
Generates realistic user activity logs with honeyfile access and anomalies
"""

import json
import random
from datetime import datetime, timedelta

# Configuration
USERS = [
    'john.doe', 'jane.smith', 'bob.wilson', 'alice.johnson',
    'mike.brown', 'sarah.davis', 'tom.anderson', 'emily.white'
]

NORMAL_FILES = [
    '/home/user/documents/report.pdf',
    '/home/user/documents/presentation.pptx',
    '/home/user/projects/code.py',
    '/home/user/downloads/data.csv',
    '/var/log/application.log',
    '/etc/config/settings.json',
    '/home/user/documents/meeting_notes.txt',
    '/home/user/projects/database_backup.sql'
]

HONEYFILS = [
    '/home/user/confidential/passwords.txt',
    '/home/user/secret_keys/api_keys.txt',
    '/home/admin/honeyfil_decoy.pdf',
    '/var/backup/confidential_2023.zip',
    '/root/.ssh/decoy_private_key',
    '/home/user/finance/trap_salaries.xlsx'
]

ACTIONS = ['read', 'write', 'execute', 'delete', 'copy']

OFFICE_HOURS_START = 8
OFFICE_HOURS_END = 18

def generate_ip():
    """Generate a random IP address"""
    return f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"

def generate_log_entry(timestamp, user, is_anomaly=False, is_honeyfil=False):
    """Generate a single log entry"""

    if is_honeyfil:
        file_path = random.choice(HONEYFILS)
    else:
        file_path = random.choice(NORMAL_FILES)

    entry = {
        'timestamp': timestamp.isoformat(),
        'user': user,
        'action': random.choice(ACTIONS),
        'file_path': file_path,
        'ip_address': generate_ip(),
        'is_honeyfil': is_honeyfil
    }

    return entry

def generate_logs(num_events=200, days=7):
    """Generate sample logs"""
    logs = []
    start_date = datetime.now() - timedelta(days=days)

    # Generate normal activity
    for _ in range(int(num_events * 0.7)):  # 70% normal activity
        # Random timestamp during office hours
        day_offset = random.randint(0, days)
        hour = random.randint(OFFICE_HOURS_START, OFFICE_HOURS_END)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        timestamp = start_date + timedelta(
            days=day_offset,
            hours=hour,
            minutes=minute,
            seconds=second
        )

        user = random.choice(USERS)
        log = generate_log_entry(timestamp, user, is_anomaly=False, is_honeyfil=False)
        logs.append(log)

    # Generate out-of-hours anomalies
    for _ in range(int(num_events * 0.15)):  # 15% out-of-hours
        day_offset = random.randint(0, days)
        hour = random.choice([0, 1, 2, 3, 4, 5, 6, 7, 19, 20, 21, 22, 23])
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        timestamp = start_date + timedelta(
            days=day_offset,
            hours=hour,
            minutes=minute,
            seconds=second
        )

        user = random.choice(USERS)
        log = generate_log_entry(timestamp, user, is_anomaly=True, is_honeyfil=False)
        logs.append(log)

    # Generate honeyfile access (CRITICAL)
    for _ in range(int(num_events * 0.05)):  # 5% honeyfile access
        day_offset = random.randint(0, days)
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        timestamp = start_date + timedelta(
            days=day_offset,
            hours=hour,
            minutes=minute,
            seconds=second
        )

        # Suspicious users more likely to access honeyfiles
        user = random.choice(USERS[:3])  # Focus on first 3 users
        log = generate_log_entry(timestamp, user, is_anomaly=True, is_honeyfil=True)
        logs.append(log)

    # Generate unusual file access anomalies
    for _ in range(int(num_events * 0.10)):  # 10% unusual access
        day_offset = random.randint(0, days)
        hour = random.randint(OFFICE_HOURS_START, OFFICE_HOURS_END)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        timestamp = start_date + timedelta(
            days=day_offset,
            hours=hour,
            minutes=minute,
            seconds=second
        )

        user = random.choice(USERS)
        log = generate_log_entry(timestamp, user, is_anomaly=True, is_honeyfil=False)
        logs.append(log)

    # Sort by timestamp
    logs.sort(key=lambda x: x['timestamp'])

    return logs

def save_logs(logs, filename='sample_logs.json'):
    """Save logs to file in JSON lines format"""
    with open(filename, 'w') as f:
        for log in logs:
            f.write(json.dumps(log) + '\n')

    print(f"Generated {len(logs)} log entries")
    print(f"Saved to {filename}")

    # Print statistics
    honeyfil_count = sum(1 for log in logs if log['is_honeyfil'])
    out_of_hours = sum(1 for log in logs if
                      datetime.fromisoformat(log['timestamp']).hour < OFFICE_HOURS_START or
                      datetime.fromisoformat(log['timestamp']).hour > OFFICE_HOURS_END)

    print(f"\nStatistics:")
    print(f"- Total events: {len(logs)}")
    print(f"- Honeyfile alerts: {honeyfil_count}")
    print(f"- Out-of-hours access: {out_of_hours}")
    print(f"- Unique users: {len(set(log['user'] for log in logs))}")

if __name__ == '__main__':
    # Generate 300 events over 7 days
    logs = generate_logs(num_events=300, days=7)
    save_logs(logs, 'sample_logs.json')
