# SIEM-Like Dashboard

A Security Information and Event Management (SIEM) dashboard with honeyfile detection and user behavior analysis.

## Features

### 1. Honeyfile & Deception Mechanisms
- **Automatic honeyfile detection** - Identifies when decoy files are accessed
- **Critical alerts** - Immediately flags honeyfil access as CRITICAL security events
- **Detailed tracking** - Records user, timestamp, IP address, and action taken

### 2. User Behavior Analysis (Context Profiling)
- **Time-based anomaly detection** - Identifies access outside office hours (8 AM - 6 PM)
- **Unusual file access detection** - Flags when users access files they don't normally use
- **User-level monitoring** - Tracks individual user patterns and behaviors
- **Activity timeline** - Visual representation of user access patterns

### 3. Advanced Analytics
- **Risk scoring** - Automatically assigns risk levels to users based on anomalies
- **Pattern learning** - Builds user profiles over time to detect deviations
- **Office hours violation tracking** - Monitors after-hours system access
- **Real-time dashboard** - Live updates and visual analytics

## Differences from Nodoze

| Feature | This Solution | Nodoze |
|---------|--------------|--------|
| Detection Method | Honeyfiles + Behavior Analysis | Passive Recon |
| Monitoring Level | User-level | System-level |
| Time Analysis | Office hours & user patterns | File opening patterns |
| Deception | Active honeyfils | No decoys |
| Context Profiling | Full user behavior profiling | Alert ranking only |
| Analysis Depth | Two-layer analysis (deception + behavior) | Single-layer (event monitoring) |

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The dashboard will be available at `http://localhost:5000`

## Usage

### 1. Generate Sample Logs (for testing)

**JSON Format:**
```bash
python sample_log_generator.py
```

**CSV Format:**
```bash
python sample_log_generator_csv.py
```

This creates sample logs with realistic activity data including:
- Normal user activity during office hours
- Out-of-hours access anomalies
- Honeyfile access events
- Unusual file access patterns

### 2. Upload Logs to Dashboard
1. Open the dashboard at `http://localhost:5000`
2. Click "Choose File" and select your log file
3. Click "Upload Logs"
4. The dashboard will automatically process and display the analysis

**Supported formats:** `.json`, `.csv`, `.log`, `.txt`

### 3. Converting Process Monitor Logs

If you have **Process Monitor (ProcMon)** TSV logs from Windows:

```bash
python convert_full_procmon.py procmon_raw.tsv procmon_enhanced.csv
```

**What it does:**
- ✅ Parses full ProcMon TSV format with all operation details
- ✅ Extracts process information (name, PID, operations, results)
- ✅ Automatically identifies honeyfile access patterns
- ✅ Creates enhanced CSV with complete provenance data for graph visualization
- ✅ Generates analysis summary showing honeyfil detections

**Then upload** `procmon_enhanced.csv` to the dashboard to see:
- 🔗 **Provenance Graph** - Visual process-file relationships with honeyfile highlights
- 🌳 **Process Tree** - Hierarchical view of processes with risk scoring
- 🚨 **Honeyfil Alerts** - All honeyfile access events flagged as CRITICAL
- 📊 **Complete Analysis** - Timeline, behavior anomalies, and statistics

### 4. Using Your Own Logs

The dashboard supports **multiple log formats**:

#### Option A: JSON Lines Format (one JSON object per line)

```json
{"timestamp": "2025-11-25T14:30:00", "user": "john.doe", "action": "read", "file_path": "/home/user/document.pdf", "ip_address": "192.168.1.100", "is_honeyfil": false}
{"timestamp": "2025-11-25T22:15:00", "user": "jane.smith", "action": "read", "file_path": "/home/admin/honeyfil_decoy.pdf", "ip_address": "192.168.1.105", "is_honeyfil": true}
```

#### Option B: CSV Format

```csv
timestamp,user,action,file_path,ip_address,is_honeyfil
2025-11-25T14:30:00,john.doe,read,/home/user/document.pdf,192.168.1.100,false
2025-11-25T22:15:00,jane.smith,read,/home/admin/honeyfil_decoy.pdf,192.168.1.105,true
```

**Supported CSV column names** (case-insensitive):
- `timestamp` / `Timestamp` / `time` / `Time`
- `user` / `User` / `username` / `Username`
- `action` / `Action` / `event` / `Event`
- `file_path` / `file` / `File` / `path` / `Path`
- `ip_address` / `ip` / `IP` / `source_ip`
- `is_honeyfil` / `is_honeyfile` / `honeyfil` / `honeyfile`

#### Option C: JSON Array Format

```json
[
  {"timestamp": "2025-11-25T14:30:00", "user": "john.doe", "action": "read", "file_path": "/home/user/document.pdf"},
  {"timestamp": "2025-11-25T22:15:00", "user": "jane.smith", "action": "read", "file_path": "/home/admin/honeyfil_decoy.pdf"}
]
```

**Required fields:**
- `timestamp` - ISO format datetime (YYYY-MM-DDTHH:MM:SS)
- `user` - Username

**Optional fields:**
- `action` - Action performed (read, write, execute, delete, copy, etc.)
- `file_path` - Path to accessed file
- `ip_address` - User's IP address
- `is_honeyfil` - Boolean/string indicating if file is a honeyfil (auto-detected if not provided)

## Dashboard Panels

### 1. Statistics Overview
- Total honeyfil alerts (CRITICAL)
- Behavior anomalies count
- Number of monitored users
- Total events processed

### 2. Honeyfile Alerts
- Real-time alerts when honeyfiles are accessed
- Shows user, file path, action, IP address
- All marked as CRITICAL severity

### 3. User Behavior Anomalies
- Out-of-hours access violations
- Unusual file access patterns
- Severity levels: HIGH, MEDIUM

### 4. Event Timeline
- Visual chart showing activity distribution by hour
- Color-coded: Normal (green), Anomalies (orange), Honeyfils (red)
- Stacked bar chart for easy pattern recognition

### 5. Access Hours Pattern
- Heatmap showing when users access the system
- Office hours (8 AM - 6 PM) highlighted in green
- After-hours activity highlighted in red

### 6. Monitored Users
- List of all users with activity counts
- Risk scoring: HIGH, MEDIUM, LOW
- Sortd by risk level

### 7. Recent Activity Log
- Detailed table of all events
- Status indicators for honeyfile access and anomalies

## Honeyfile Detection

The system automatically detects honeyfiles based on:

1. **Filename patterns**: passwords.txt, secret, confidential, trap, decoy, honeyfil
2. **Explicit marking**: `is_honeyfil: true` in log entries
3. **Path patterns**: Suspicious directories like `/root/.ssh/`, `/admin/`, etc.

## User Behavior Analysis

The system learns normal patterns and detects:

1. **Time-based anomalies**
   - Access outside office hours (before 8 AM or after 6 PM)
   - Marked as HIGH severity

2. **File access anomalies**
   - User accessing files they don't normally use
   - Requires 10+ events to build baseline profile
   - Marked as MEDIUM severity

3. **Context profiling**
   - Tracks normal access hours per user
   - Builds list of commonly accessed files
   - Maintains access history for pattern analysis

## API Endpoints

- `GET /` - Dashboard home page
- `POST /api/logs` - Upload log file
- `GET /api/dashboard/stats` - Get dashboard statistics
- `GET /api/honeyfil-alerts` - Get honeyfile alerts
- `GET /api/behavior-anomalies` - Get behavior anomalies
- `GET /api/users` - Get list of monitored users
- `GET /api/user-activity/<username>` - Get specific user activity
- `GET /api/timeline` - Get event timeline data

## Architecture

```
siem-like-app/
├── app.py                    # Flask backend with analysis engine
├── templates/
│   └── dashboard.html        # Dashboard UI
├── static/
│   ├── css/
│   │   └── dashboard.css     # Styling
│   └── js/
│       └── dashboard.js      # Frontend logic & charts
├── sample_log_generator.py   # Generate test data
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## Security Features

1. **Two-layer detection**: Combines honeyfils (deception) with behavior analysis
2. **User-level monitoring**: Tracks individual patterns, not just system events
3. **Context-aware**: Understands office hours and normal work patterns
4. **Real-time alerting**: Immediate notification of critical events
5. **Risk scoring**: Automatically prioritizes high-risk users
6. **Minimal false positives**: Profile-based learning reduces noise

## Future Enhancements

- Email/SMS alerts for critical events
- Machine learning for advanced anomaly detection
- Integration with SIEM tools (Splunk, ELK)
- User entity behavior analytics (UEBA)
- Threat intelligence feeds
- Automated incident response

## License

MIT License
