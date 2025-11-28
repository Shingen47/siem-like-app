// Global variables for charts
let timelineChart = null;
let hoursChart = null;

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    checkBaselineStatus();
    // Auto-refresh every 30 seconds
    setInterval(refreshDashboard, 30000);
});

// Check baseline status on page load
async function checkBaselineStatus() {
    try {
        const response = await fetch('/api/baseline/status');
        const data = await response.json();

        if (data.baseline_learned) {
            updateBaselineStatus(data.stats);
        }
    } catch (error) {
        console.error('Error checking baseline status:', error);
    }
}

// Update baseline status UI
function updateBaselineStatus(data) {
    const indicator = document.getElementById('baselineIndicator');
    const statsDiv = document.getElementById('baselineStats');

    // Update status indicator
    indicator.innerHTML = `
        <span class="status-dot learned"></span>
        <span class="status-text">✅ Baseline learned successfully</span>
    `;

    // Show and populate statistics
    statsDiv.classList.remove('hidden');
    document.getElementById('baselineUsers').textContent = data.normal_users || 0;
    document.getElementById('baselineHours').textContent = (data.normal_hours || []).join(', ');
    document.getElementById('baselineIPs').textContent = data.normal_ips || 0;
    document.getElementById('baselineProcesses').textContent = data.normal_processes || 0;
}

// Upload log file
async function uploadLogs() {
    const fileInput = document.getElementById('logFile');
    const statusSpan = document.getElementById('uploadStatus');

    if (!fileInput.files || fileInput.files.length === 0) {
        statusSpan.textContent = '❌ Please select a file';
        statusSpan.style.color = '#ef4444';
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    statusSpan.textContent = '⏳ Uploading and processing...';
    statusSpan.style.color = '#f59e0b';

    try {
        const response = await fetch('/api/logs', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.status === 'success') {
            statusSpan.textContent = `✅ Processed ${data.logs_processed} events`;
            statusSpan.style.color = '#10b981';
            refreshDashboard();
        } else {
            statusSpan.textContent = '❌ Upload failed';
            statusSpan.style.color = '#ef4444';
        }
    } catch (error) {
        statusSpan.textContent = '❌ Error uploading file';
        statusSpan.style.color = '#ef4444';
        console.error('Upload error:', error);
    }
}

// Refresh entire dashboard
async function refreshDashboard() {
    await Promise.all([
        updateStats(),
        updateHoneyfilAlerts(),
        updateBehaviorAnomalies(),
        updateUsers(),
        updateTimeline()
    ]);
}

// Update dashboard statistics
async function updateStats() {
    try {
        const response = await fetch('/api/dashboard/stats');
        const stats = await response.json();

        document.getElementById('honeyfilCount').textContent = stats.honeyfil_alerts;
        document.getElementById('anomalyCount').textContent = stats.behavior_anomalies;
        document.getElementById('userCount').textContent = stats.total_users;
        document.getElementById('eventCount').textContent = stats.total_events;

        document.getElementById('honeyfilBadge').textContent = stats.honeyfil_alerts;
        document.getElementById('behaviorBadge').textContent = stats.behavior_anomalies;
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

// Update honeyfile alerts
async function updateHoneyfilAlerts() {
    try {
        const response = await fetch('/api/honeyfil-alerts');
        const alerts = await response.json();

        const container = document.getElementById('honeyfilAlerts');

        if (alerts.length === 0) {
            container.innerHTML = '<p class="no-data">No honeyfile alerts detected</p>';
            return;
        }

        container.innerHTML = alerts.map(alert => `
            <div class="alert-item critical">
                <div class="alert-header">
                    <span class="alert-severity CRITICAL">CRITICAL</span>
                    <span class="alert-time">${formatTimestamp(alert.timestamp)}</span>
                </div>
                <div class="alert-details">
                    <div><strong>User:</strong> ${alert.user}</div>
                    <div><strong>File:</strong> ${alert.file_path}</div>
                    <div><strong>Action:</strong> ${alert.action}</div>
                    <div><strong>IP:</strong> ${alert.ip_address || 'N/A'}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error updating honeyfile alerts:', error);
    }
}

// Update behavior anomalies
async function updateBehaviorAnomalies() {
    try {
        const response = await fetch('/api/behavior-anomalies');
        const anomalies = await response.json();

        const container = document.getElementById('behaviorAnomalies');

        if (anomalies.length === 0) {
            container.innerHTML = '<p class="no-data">No behavior anomalies detected</p>';
            return;
        }

        container.innerHTML = anomalies.map(anomaly => `
            <div class="alert-item ${anomaly.severity.toLowerCase()}">
                <div class="alert-header">
                    <span class="alert-severity ${anomaly.severity}">${anomaly.severity}</span>
                    <span class="alert-time">${formatTimestamp(anomaly.timestamp)}</span>
                </div>
                <div class="alert-details">
                    <div><strong>User:</strong> ${anomaly.user}</div>
                    <div><strong>Type:</strong> ${anomaly.type.replace(/_/g, ' ')}</div>
                    <div><strong>Description:</strong> ${anomaly.description}</div>
                    <div><strong>File:</strong> ${anomaly.file_path}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error updating behavior anomalies:', error);
    }
}

// Update users list
async function updateUsers() {
    try {
        const response = await fetch('/api/users');
        const users = await response.json();

        const container = document.getElementById('usersList');
        const userFilter = document.getElementById('userFilter');

        if (users.length === 0) {
            container.innerHTML = '<p class="no-data">No users data available</p>';
            return;
        }

        // Update user filter dropdown
        const currentFilter = userFilter.value;
        userFilter.innerHTML = '<option value="">All Users</option>' +
            users.map(user => `<option value="${user.username}">${user.username}</option>`).join('');
        userFilter.value = currentFilter;

        // Calculate risk level
        users.forEach(user => {
            if (user.anomalies > 5) {
                user.risk = 'high';
            } else if (user.anomalies > 0) {
                user.risk = 'medium';
            } else {
                user.risk = 'low';
            }
        });

        // Sort by risk level
        users.sort((a, b) => {
            const riskOrder = { high: 0, medium: 1, low: 2 };
            return riskOrder[a.risk] - riskOrder[b.risk];
        });

        container.innerHTML = users.map(user => `
            <div class="user-item">
                <div class="user-info">
                    <div class="user-name">👤 ${user.username}</div>
                    <div class="user-stats">${user.total_access} accesses | ${user.anomalies} anomalies</div>
                </div>
                <div class="user-risk ${user.risk}">${user.risk.toUpperCase()}</div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error updating users:', error);
    }
}

// Update timeline
async function updateTimeline() {
    try {
        const response = await fetch('/api/timeline');
        const timeline = await response.json();

        // Update activity log table
        updateActivityLog(timeline);

        // Update timeline chart
        updateTimelineChart(timeline);

        // Update hours heatmap
        updateHoursHeatmap(timeline);
    } catch (error) {
        console.error('Error updating timeline:', error);
    }
}

// Update activity log table
function updateActivityLog(timeline) {
    const tbody = document.getElementById('logTableBody');

    if (timeline.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="no-data">No activity data available</td></tr>';
        return;
    }

    tbody.innerHTML = timeline.map(event => {
        let statusBadge = 'normal';
        let statusText = 'Normal';

        if (event.is_honeyfil) {
            statusBadge = 'honeyfil';
            statusText = '🍯 HONEYFIL';
        } else if (event.has_anomaly) {
            statusBadge = 'anomaly';
            statusText = '⚡ Anomaly';
        }

        return `
            <tr>
                <td>${formatTimestamp(event.timestamp)}</td>
                <td>${event.user}</td>
                <td>${event.action}</td>
                <td>${event.file}</td>
                <td><span class="status-badge ${statusBadge}">${statusText}</span></td>
            </tr>
        `;
    }).join('');
}

// Update timeline chart
function updateTimelineChart(timeline) {
    const ctx = document.getElementById('timelineChart').getContext('2d');

    // Group events by hour
    const hourCounts = {};
    const honeyfilCounts = {};
    const anomalyCounts = {};

    timeline.forEach(event => {
        const date = new Date(event.timestamp);
        const hour = date.getHours();

        hourCounts[hour] = (hourCounts[hour] || 0) + 1;
        if (event.is_honeyfil) {
            honeyfilCounts[hour] = (honeyfilCounts[hour] || 0) + 1;
        }
        if (event.has_anomaly) {
            anomalyCounts[hour] = (anomalyCounts[hour] || 0) + 1;
        }
    });

    const hours = Array.from({ length: 24 }, (_, i) => i);
    const normalEvents = hours.map(h => (hourCounts[h] || 0) - (honeyfilCounts[h] || 0) - (anomalyCounts[h] || 0));
    const honeyfilEvents = hours.map(h => honeyfilCounts[h] || 0);
    const anomalyEvents = hours.map(h => anomalyCounts[h] || 0);

    if (timelineChart) {
        timelineChart.destroy();
    }

    timelineChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: hours.map(h => `${h}:00`),
            datasets: [
                {
                    label: 'Normal Events',
                    data: normalEvents,
                    backgroundColor: 'rgba(16, 185, 129, 0.6)',
                    borderColor: 'rgba(16, 185, 129, 1)',
                    borderWidth: 1
                },
                {
                    label: 'Anomalies',
                    data: anomalyEvents,
                    backgroundColor: 'rgba(245, 158, 11, 0.6)',
                    borderColor: 'rgba(245, 158, 11, 1)',
                    borderWidth: 1
                },
                {
                    label: 'Honeyfile Alerts',
                    data: honeyfilEvents,
                    backgroundColor: 'rgba(239, 68, 68, 0.6)',
                    borderColor: 'rgba(239, 68, 68, 1)',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    stacked: true,
                    grid: { color: '#2d3354' },
                    ticks: { color: '#9ca3af' }
                },
                y: {
                    stacked: true,
                    grid: { color: '#2d3354' },
                    ticks: { color: '#9ca3af' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#e4e7eb' }
                }
            }
        }
    });
}

// Update hours heatmap
function updateHoursHeatmap(timeline) {
    const ctx = document.getElementById('hoursHeatmap').getContext('2d');

    // Count events by hour
    const hourCounts = Array(24).fill(0);
    timeline.forEach(event => {
        const date = new Date(event.timestamp);
        const hour = date.getHours();
        hourCounts[hour]++;
    });

    // Define office hours (8 AM - 6 PM)
    const colors = hourCounts.map((count, hour) => {
        if (hour >= 8 && hour <= 18) {
            return 'rgba(16, 185, 129, 0.6)'; // Green for office hours
        } else {
            return count > 0 ? 'rgba(239, 68, 68, 0.6)' : 'rgba(59, 130, 246, 0.3)'; // Red if activity outside office hours
        }
    });

    if (hoursChart) {
        hoursChart.destroy();
    }

    hoursChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
            datasets: [{
                label: 'Activity by Hour',
                data: hourCounts,
                backgroundColor: colors,
                borderColor: colors.map(c => c.replace('0.6', '1').replace('0.3', '0.8')),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: '#2d3354' },
                    ticks: { color: '#9ca3af' }
                },
                y: {
                    grid: { color: '#2d3354' },
                    ticks: { color: '#9ca3af' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#e4e7eb' }
                },
                tooltip: {
                    callbacks: {
                        afterLabel: function(context) {
                            const hour = context.dataIndex;
                            if (hour >= 8 && hour <= 18) {
                                return 'Office Hours';
                            } else {
                                return 'Outside Office Hours';
                            }
                        }
                    }
                }
            }
        }
    });
}

// Initialize charts
function initializeCharts() {
    const ctx1 = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(ctx1, {
        type: 'bar',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { grid: { color: '#2d3354' }, ticks: { color: '#9ca3af' } },
                y: { grid: { color: '#2d3354' }, ticks: { color: '#9ca3af' } }
            },
            plugins: {
                legend: { labels: { color: '#e4e7eb' } }
            }
        }
    });

    const ctx2 = document.getElementById('hoursHeatmap').getContext('2d');
    hoursChart = new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { grid: { color: '#2d3354' }, ticks: { color: '#9ca3af' } },
                y: { grid: { color: '#2d3354' }, ticks: { color: '#9ca3af' } }
            },
            plugins: {
                legend: { labels: { color: '#e4e7eb' } }
            }
        }
    });
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}
