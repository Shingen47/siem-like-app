from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import csv
import io
import os
from collections import defaultdict

app = Flask(__name__)

# Global storage for logs and analysis
logs_data = []
honeyfil_alerts = []
user_profiles = defaultdict(lambda: {
    'normal_access_hours': set(),
    'common_files': set(),
    'access_history': []
})

def analyze_user_behavior(log_entry):
    """Analyze user behavior for anomalies"""
    anomalies = []
    user = log_entry.get('user')
    timestamp = datetime.fromisoformat(log_entry.get('timestamp'))
    file_path = log_entry.get('file_path')
    action = log_entry.get('action')

    # Get user profile
    profile = user_profiles[user]

    # Check time-based anomaly (office hours: 8 AM - 6 PM)
    hour = timestamp.hour
    if hour < 8 or hour > 18:
        anomalies.append({
            'type': 'OUT_OF_HOURS_ACCESS',
            'severity': 'HIGH',
            'description': f'Access outside office hours ({hour}:00)'
        })

    # Check unusual file access
    if profile['common_files'] and file_path not in profile['common_files']:
        if len(profile['access_history']) > 10:  # Only after building profile
            anomalies.append({
                'type': 'UNUSUAL_FILE_ACCESS',
                'severity': 'MEDIUM',
                'description': f'Accessing unusual file: {file_path}'
            })

    # Update user profile
    profile['normal_access_hours'].add(hour)
    profile['common_files'].add(file_path)
    profile['access_history'].append({
        'timestamp': log_entry.get('timestamp'),
        'file': file_path,
        'action': action
    })

    return anomalies

def detect_honeyfil(log_entry):
    """Detect if accessed file is a honeyfil"""
    file_path = log_entry.get('file_path', '')

    # Honeyfil indicators
    honeyfil_patterns = [
        'honeyfil', 'decoy', 'trap', 'confidential_2023',
        'passwords.txt', 'secret', 'backup_keys'
    ]

    for pattern in honeyfil_patterns:
        if pattern.lower() in file_path.lower():
            return True

    # Check if file is marked as honeyfil
    if log_entry.get('is_honeyfil', False):
        return True

    return False

@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('dashboard.html')

def parse_csv_logs(content):
    """Parse CSV format logs"""
    logs = []
    csv_file = io.StringIO(content)
    reader = csv.DictReader(csv_file)

    for row in reader:
        # Map CSV columns to expected format
        # Support common column names
        log_entry = {
            'timestamp': row.get('timestamp') or row.get('Timestamp') or row.get('time') or row.get('Time'),
            'user': row.get('user') or row.get('User') or row.get('username') or row.get('Username'),
            'action': row.get('action') or row.get('Action') or row.get('event') or row.get('Event'),
            'file_path': row.get('file_path') or row.get('file') or row.get('File') or row.get('path') or row.get('Path'),
            'ip_address': row.get('ip_address') or row.get('ip') or row.get('IP') or row.get('source_ip'),
        }

        # Handle is_honeyfil boolean field
        is_honeyfil_val = row.get('is_honeyfil') or row.get('is_honeyfile') or row.get('honeyfil') or row.get('honeyfile')
        if is_honeyfil_val:
            if isinstance(is_honeyfil_val, str):
                log_entry['is_honeyfil'] = is_honeyfil_val.lower() in ['true', '1', 'yes']
            else:
                log_entry['is_honeyfil'] = bool(is_honeyfil_val)
        else:
            log_entry['is_honeyfil'] = False

        # Only add if we have minimum required fields
        if log_entry['timestamp'] and log_entry['user']:
            logs.append(log_entry)

    return logs

def parse_json_logs(content):
    """Parse JSON or JSON lines format logs"""
    logs = []

    # Try JSON lines format first (one JSON object per line)
    for line in content.strip().split('\n'):
        if not line:
            continue
        try:
            log_entry = json.loads(line)
            logs.append(log_entry)
        except json.JSONDecodeError:
            continue

    # If no logs parsed, try as single JSON array
    if not logs:
        try:
            logs = json.loads(content)
            if not isinstance(logs, list):
                logs = [logs]
        except json.JSONDecodeError:
            pass

    return logs

@app.route('/api/logs', methods=['POST'])
def upload_logs():
    """Upload and process log file (supports JSON, JSON Lines, and CSV)"""
    global logs_data, honeyfil_alerts, user_profiles

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    filename = file.filename.lower()
    content = file.read().decode('utf-8')

    # Reset data
    logs_data = []
    honeyfil_alerts = []
    user_profiles.clear()

    # Detect and parse file format
    if filename.endswith('.csv'):
        parsed_logs = parse_csv_logs(content)
    else:
        # Try JSON format (also handles .json, .log, .txt)
        parsed_logs = parse_json_logs(content)

    # Process each log entry
    for log_entry in parsed_logs:
        if not log_entry:
            continue

        logs_data.append(log_entry)

        # Check for honeyfil access
        if detect_honeyfil(log_entry):
            alert = {
                'timestamp': log_entry.get('timestamp'),
                'user': log_entry.get('user'),
                'file_path': log_entry.get('file_path'),
                'action': log_entry.get('action'),
                'ip_address': log_entry.get('ip_address'),
                'severity': 'CRITICAL'
            }
            honeyfil_alerts.append(alert)

        # Analyze user behavior
        try:
            anomalies = analyze_user_behavior(log_entry)
            if anomalies:
                log_entry['anomalies'] = anomalies
        except Exception as e:
            # Skip entries with invalid data
            continue

    return jsonify({
        'status': 'success',
        'logs_processed': len(logs_data),
        'honeyfil_alerts': len(honeyfil_alerts)
    })

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get overall dashboard statistics"""
    total_events = len(logs_data)
    total_users = len(user_profiles)
    total_honeyfil_alerts = len(honeyfil_alerts)

    # Count behavior anomalies
    behavior_anomalies = 0
    for log in logs_data:
        if 'anomalies' in log:
            behavior_anomalies += len(log['anomalies'])

    return jsonify({
        'total_events': total_events,
        'total_users': total_users,
        'honeyfil_alerts': total_honeyfil_alerts,
        'behavior_anomalies': behavior_anomalies
    })

@app.route('/api/honeyfil-alerts')
def get_honeyfil_alerts():
    """Get all honeyfil alerts"""
    return jsonify(honeyfil_alerts[-50:])  # Last 50 alerts

@app.route('/api/behavior-anomalies')
def get_behavior_anomalies():
    """Get user behavior anomalies"""
    anomalies = []

    for log in logs_data:
        if 'anomalies' in log:
            for anomaly in log['anomalies']:
                anomalies.append({
                    'timestamp': log.get('timestamp'),
                    'user': log.get('user'),
                    'file_path': log.get('file_path'),
                    'type': anomaly['type'],
                    'severity': anomaly['severity'],
                    'description': anomaly['description']
                })

    return jsonify(anomalies[-50:])  # Last 50 anomalies

@app.route('/api/user-activity/<username>')
def get_user_activity(username):
    """Get activity timeline for specific user"""
    profile = user_profiles.get(username, {})

    return jsonify({
        'username': username,
        'access_history': profile.get('access_history', [])[-100:],
        'normal_hours': list(profile.get('normal_access_hours', [])),
        'common_files': list(profile.get('common_files', []))
    })

@app.route('/api/users')
def get_users():
    """Get list of all monitored users"""
    users = []
    for username, profile in user_profiles.items():
        # Count anomalies for this user
        user_anomalies = sum(1 for log in logs_data
                            if log.get('user') == username and 'anomalies' in log)

        users.append({
            'username': username,
            'total_access': len(profile['access_history']),
            'anomalies': user_anomalies
        })

    return jsonify(users)

@app.route('/api/timeline')
def get_timeline():
    """Get event timeline for visualization"""
    timeline = []

    for log in logs_data[-100:]:  # Last 100 events
        event = {
            'timestamp': log.get('timestamp'),
            'user': log.get('user'),
            'action': log.get('action'),
            'file': log.get('file_path'),
            'is_honeyfil': detect_honeyfil(log),
            'has_anomaly': 'anomalies' in log
        }
        timeline.append(event)

    return jsonify(timeline)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
