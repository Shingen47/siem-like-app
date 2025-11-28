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
process_tree = defaultdict(list)  # pid -> list of child pids
process_info = {}  # pid -> process details
provenance_data = {
    'nodes': [],  # processes and files
    'edges': []   # operations connecting them
}

# Baseline learning storage
baseline_learned = False
baseline_stats = {
    'normal_hours': set(),  # Set of normal access hours
    'normal_users': set(),  # Set of legitimate users
    'normal_ips': set(),  # Set of legitimate IP addresses
    'normal_processes': set(),  # Set of legitimate process names
    'file_patterns': set(),  # Set of normal file path patterns
    'avg_events_per_hour': 0,
    'common_actions': defaultdict(int),
    'user_file_associations': defaultdict(set)  # user -> set of files they normally access
}

def learn_baseline(baseline_logs):
    """Learn normal behavior patterns from baseline logs"""
    global baseline_learned, baseline_stats

    hours_count = defaultdict(int)

    for log_entry in baseline_logs:
        try:
            timestamp = datetime.fromisoformat(log_entry.get('timestamp'))
            user = log_entry.get('user')
            ip_address = log_entry.get('ip_address')
            file_path = log_entry.get('file_path')
            action = log_entry.get('action')
            process_name = log_entry.get('process_name') or log_entry.get('user')

            # Learn normal hours
            hour = timestamp.hour
            baseline_stats['normal_hours'].add(hour)
            hours_count[hour] += 1

            # Learn normal users
            if user:
                baseline_stats['normal_users'].add(user)
                if file_path:
                    baseline_stats['user_file_associations'][user].add(file_path)

            # Learn normal IPs
            if ip_address:
                baseline_stats['normal_ips'].add(ip_address)

            # Learn normal processes
            if process_name:
                baseline_stats['normal_processes'].add(process_name)

            # Learn file patterns (extract folder patterns)
            if file_path:
                baseline_stats['file_patterns'].add(file_path)
                # Also add parent directories as patterns
                if '\\' in file_path:
                    parts = file_path.split('\\')
                    for i in range(len(parts)):
                        baseline_stats['file_patterns'].add('\\'.join(parts[:i+1]))

            # Learn common actions
            if action:
                baseline_stats['common_actions'][action] += 1

        except Exception as e:
            continue

    # Calculate average events per hour
    if hours_count:
        baseline_stats['avg_events_per_hour'] = sum(hours_count.values()) / len(hours_count)

    baseline_learned = True
    print(f"✓ Baseline learned: {len(baseline_logs)} events")
    print(f"  - Normal users: {len(baseline_stats['normal_users'])}")
    print(f"  - Normal hours: {sorted(baseline_stats['normal_hours'])}")
    print(f"  - Normal IPs: {len(baseline_stats['normal_ips'])}")
    print(f"  - Normal processes: {len(baseline_stats['normal_processes'])}")

def analyze_user_behavior(log_entry):
    """Analyze user behavior for anomalies using learned baseline"""
    anomalies = []
    user = log_entry.get('user')
    timestamp = datetime.fromisoformat(log_entry.get('timestamp'))
    file_path = log_entry.get('file_path')
    action = log_entry.get('action')
    ip_address = log_entry.get('ip_address')
    process_name = log_entry.get('process_name') or log_entry.get('user')

    # Get user profile
    profile = user_profiles[user]

    if baseline_learned:
        # Use baseline for anomaly detection
        hour = timestamp.hour

        # Check time-based anomaly against learned baseline
        if hour not in baseline_stats['normal_hours']:
            anomalies.append({
                'type': 'OUT_OF_HOURS_ACCESS',
                'severity': 'CRITICAL',
                'description': f'Access outside learned normal hours ({hour}:00). Normal hours: {sorted(baseline_stats["normal_hours"])}'
            })

        # Check unknown user
        if user not in baseline_stats['normal_users']:
            anomalies.append({
                'type': 'UNKNOWN_USER',
                'severity': 'CRITICAL',
                'description': f'Unknown user "{user}" not in baseline. Known users: {len(baseline_stats["normal_users"])}'
            })

        # Check suspicious IP
        if ip_address and ip_address not in baseline_stats['normal_ips']:
            anomalies.append({
                'type': 'SUSPICIOUS_IP',
                'severity': 'HIGH',
                'description': f'IP {ip_address} not seen in baseline. Known IPs: {len(baseline_stats["normal_ips"])}'
            })

        # Check suspicious process
        if process_name and process_name not in baseline_stats['normal_processes']:
            anomalies.append({
                'type': 'SUSPICIOUS_PROCESS',
                'severity': 'HIGH',
                'description': f'Process "{process_name}" not in baseline. Baseline processes: {", ".join(list(baseline_stats["normal_processes"])[:3])}...'
            })

        # Check file access pattern deviation for known users
        if user in baseline_stats['user_file_associations']:
            user_normal_files = baseline_stats['user_file_associations'][user]
            if file_path and file_path not in user_normal_files:
                # Check if the file path pattern is similar to baseline
                file_in_normal_pattern = any(
                    pattern in file_path for pattern in baseline_stats['file_patterns']
                )
                if not file_in_normal_pattern:
                    anomalies.append({
                        'type': 'UNUSUAL_FILE_ACCESS',
                        'severity': 'MEDIUM',
                        'description': f'User accessing unusual file: {file_path}'
                    })

    else:
        # Fallback to hardcoded rules if no baseline
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
    profile['normal_access_hours'].add(timestamp.hour)
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

def build_provenance_graph():
    """Build provenance graph from logs data"""
    global provenance_data

    nodes = {}  # node_id -> node data
    edges = []

    for log in logs_data:
        pid = log.get('pid')
        process_name = log.get('process_name') or log.get('user')
        file_path = log.get('file_path')
        operation = log.get('operation') or log.get('action')
        timestamp = log.get('timestamp')

        if not process_name or not file_path:
            continue

        # Create process node
        proc_id = f"proc_{pid}_{process_name}" if pid else f"proc_{process_name}"
        if proc_id not in nodes:
            nodes[proc_id] = {
                'id': proc_id,
                'type': 'process',
                'label': f"{process_name}" + (f" (PID:{pid})" if pid else ""),
                'pid': pid,
                'name': process_name
            }

        # Create file node
        file_id = f"file_{hash(file_path) % 10000}"
        if file_id not in nodes:
            is_honeyfil = log.get('is_honeyfil', False)
            nodes[file_id] = {
                'id': file_id,
                'type': 'honeyfil' if is_honeyfil else 'file',
                'label': file_path.split('\\')[-1] if '\\' in file_path else file_path.split('/')[-1],
                'path': file_path,
                'is_honeyfil': is_honeyfil
            }

        # Create edge (operation)
        edge = {
            'source': proc_id,
            'target': file_id,
            'operation': operation,
            'timestamp': timestamp,
            'label': operation
        }
        edges.append(edge)

    provenance_data = {
        'nodes': list(nodes.values()),
        'edges': edges
    }

    return provenance_data

def build_process_tree():
    """Build process tree from logs data"""
    global process_tree, process_info

    process_tree.clear()
    process_info.clear()

    # Collect all unique processes
    processes = {}
    for log in logs_data:
        pid = log.get('pid')
        process_name = log.get('process_name') or log.get('user')

        if not pid or not process_name:
            continue

        if pid not in processes:
            processes[pid] = {
                'pid': pid,
                'name': process_name,
                'operations': 0,
                'files_accessed': set(),
                'honeyfils_accessed': 0,
                'first_seen': log.get('timestamp'),
                'last_seen': log.get('timestamp')
            }

        processes[pid]['operations'] += 1
        if log.get('file_path'):
            processes[pid]['files_accessed'].add(log.get('file_path'))
        if log.get('is_honeyfil'):
            processes[pid]['honeyfils_accessed'] += 1
        processes[pid]['last_seen'] = log.get('timestamp')

    # Convert sets to counts for JSON serialization
    for pid, info in processes.items():
        info['files_accessed'] = len(info['files_accessed'])
        process_info[pid] = info

    # For now, create a flat tree (can be enhanced with parent-child relationships)
    # In real ProcMon data, you'd extract parent PID from process creation events
    tree_data = {
        'name': 'System',
        'children': [
            {
                'name': f"{info['name']} (PID: {pid})",
                'pid': pid,
                'operations': info['operations'],
                'files_accessed': info['files_accessed'],
                'honeyfils_accessed': info['honeyfils_accessed'],
                'risk': 'high' if info['honeyfils_accessed'] > 0 else 'normal'
            }
            for pid, info in process_info.items()
        ]
    }

    return tree_data

@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('dashboard.html')

def parse_csv_logs(content):
    """Parse CSV format logs (supports basic and ProcMon formats)"""
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

        # Enhanced: Extract ProcMon-specific fields if available
        log_entry['process_name'] = row.get('process_name') or row.get('Process Name')
        log_entry['pid'] = row.get('pid') or row.get('PID')
        log_entry['operation'] = row.get('operation') or row.get('Operation')
        log_entry['result'] = row.get('result') or row.get('Result')
        log_entry['detail'] = row.get('detail') or row.get('Detail')

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

@app.route('/api/baseline/status')
def baseline_status():
    """Get current baseline learning status"""
    return jsonify({
        'baseline_learned': baseline_learned,
        'stats': {
            'normal_users': list(baseline_stats['normal_users']),
            'normal_hours': sorted(list(baseline_stats['normal_hours'])),
            'normal_ips': list(baseline_stats['normal_ips']),
            'normal_processes': list(baseline_stats['normal_processes']),
            'total_file_patterns': len(baseline_stats['file_patterns'])
        } if baseline_learned else {}
    })

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

    # Build provenance graph and process tree
    build_provenance_graph()
    build_process_tree()

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

@app.route('/api/provenance-graph')
def get_provenance_graph():
    """Get provenance graph data for visualization"""
    return jsonify(provenance_data)

@app.route('/api/process-tree')
def get_process_tree():
    """Get process tree data for visualization"""
    tree_data = build_process_tree()
    return jsonify(tree_data)

def load_baseline_from_file():
    """Load baseline from normal_user_baseline_50events.csv automatically"""
    baseline_file = 'normal_user_baseline_50events.csv'

    if not os.path.exists(baseline_file):
        print(f"⚠ Warning: Baseline file '{baseline_file}' not found. Baseline learning skipped.")
        return

    try:
        baseline_logs = []
        with open(baseline_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert is_honeyfil string to boolean
                if 'is_honeyfil' in row:
                    row['is_honeyfil'] = row['is_honeyfil'].lower() == 'true'
                baseline_logs.append(row)

        if baseline_logs:
            learn_baseline(baseline_logs)
            print(f"✓ Baseline automatically loaded from {baseline_file}")
        else:
            print(f"⚠ Warning: No baseline data found in {baseline_file}")

    except Exception as e:
        print(f"❌ Error loading baseline from {baseline_file}: {str(e)}")

if __name__ == '__main__':
    # Load baseline automatically on startup
    load_baseline_from_file()
    app.run(debug=True, host='0.0.0.0', port=5000)
