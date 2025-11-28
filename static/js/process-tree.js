/**
 * Process Tree Visualization using D3.js
 * Shows hierarchical process relationships with risk scoring
 */

async function updateProcessTree() {
    try {
        const response = await fetch('/api/process-tree');
        const data = await response.json();

        if (!data.children || data.children.length === 0) {
            document.getElementById('processTree').innerHTML =
                '<p class="no-data">No process data available</p>';
            return;
        }

        renderProcessTree(data);
    } catch (error) {
        console.error('Error loading process tree:', error);
    }
}

function renderProcessTree(data) {
    // Clear previous tree
    d3.select('#processTree').selectAll('*').remove();

    const container = document.getElementById('processTree');
    const width = container.clientWidth;
    const height = 800;

    // Create SVG with centered content
    const svg = d3.select('#processTree')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .style('display', 'block')
        .style('margin', '0 auto');

    const g = svg.append('g')
        .attr('transform', `translate(${width / 2}, 60)`);

    // Create tree layout with more vertical space
    const treeLayout = d3.tree()
        .size([width - 200, height - 180])
        .separation((a, b) => (a.parent === b.parent ? 1.5 : 2));

    // Convert data to hierarchy
    const root = d3.hierarchy(data);
    treeLayout(root);

    // Create links (lines connecting nodes)
    const links = g.selectAll('.link')
        .data(root.links())
        .enter().append('path')
        .attr('class', 'link')
        .attr('d', d3.linkVertical()
            .x(d => d.x)
            .y(d => d.y))
        .attr('fill', 'none')
        .attr('stroke', '#2d3354')
        .attr('stroke-width', 2)
        .attr('stroke-opacity', 0.6);

    // Create nodes
    const nodes = g.selectAll('.node')
        .data(root.descendants())
        .enter().append('g')
        .attr('class', 'node')
        .attr('transform', d => `translate(${d.x},${d.y})`);

    // Add circles for nodes (larger for better visibility)
    nodes.append('circle')
        .attr('r', d => d.depth === 0 ? 30 : 25)
        .attr('fill', d => {
            if (d.depth === 0) return '#667eea'; // Root node (System)
            if (d.data.risk === 'high') return '#ef4444'; // High risk (accessed honeyfils)
            return '#3b82f6'; // Normal
        })
        .attr('stroke', '#fff')
        .attr('stroke-width', 3);

    // Add icons for nodes
    nodes.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 7)
        .attr('font-size', d => d.depth === 0 ? 24 : 20)
        .text(d => {
            if (d.depth === 0) return '🖥️';
            if (d.data.risk === 'high') return '⚠️';
            return '⚙️';
        });

    // Add labels (larger font)
    nodes.append('text')
        .attr('dy', d => d.depth === 0 ? 50 : 42)
        .attr('text-anchor', 'middle')
        .attr('font-size', 13)
        .attr('fill', '#e4e7eb')
        .attr('font-weight', d => d.depth === 0 ? 'bold' : '600')
        .text(d => {
            const name = d.data.name;
            return name.length > 30 ? name.substring(0, 30) + '...' : name;
        });

    // Add statistics below process names (larger font)
    nodes.filter(d => d.depth > 0)
        .append('text')
        .attr('dy', 58)
        .attr('text-anchor', 'middle')
        .attr('font-size', 11)
        .attr('fill', '#9ca3af')
        .text(d => `Ops: ${d.data.operations} | Files: ${d.data.files_accessed}`);

    // Add risk badge for high-risk processes
    nodes.filter(d => d.data.risk === 'high')
        .append('text')
        .attr('dy', -25)
        .attr('text-anchor', 'middle')
        .attr('font-size', 10)
        .attr('fill', '#ef4444')
        .attr('font-weight', 'bold')
        .text(d => `🚨 ${d.data.honeyfils_accessed} honeyfil(s)`);

    // Add tooltips
    nodes.append('title')
        .text(d => {
            if (d.depth === 0) {
                return `${d.data.name}\nTotal Processes: ${d.children ? d.children.length : 0}`;
            }
            return `${d.data.name}\n` +
                   `Operations: ${d.data.operations}\n` +
                   `Files Accessed: ${d.data.files_accessed}\n` +
                   `Honeyfils Accessed: ${d.data.honeyfils_accessed}\n` +
                   `Risk Level: ${d.data.risk.toUpperCase()}`;
        });

    // Add legend
    const legend = svg.append('g')
        .attr('class', 'legend')
        .attr('transform', `translate(20, ${height - 120})`);

    const legendData = [
        { label: 'System Root', color: '#667eea', icon: '🖥️' },
        { label: 'Normal Process', color: '#3b82f6', icon: '⚙️' },
        { label: 'High Risk Process', color: '#ef4444', icon: '⚠️' }
    ];

    legendData.forEach((item, i) => {
        const g = legend.append('g')
            .attr('transform', `translate(0, ${i * 25})`);

        g.append('circle')
            .attr('r', 8)
            .attr('fill', item.color);

        g.append('text')
            .attr('x', 20)
            .attr('y', 5)
            .attr('font-size', 12)
            .attr('fill', '#e4e7eb')
            .text(`${item.icon} ${item.label}`);
    });

    // Add summary statistics
    const stats = svg.append('g')
        .attr('class', 'stats')
        .attr('transform', `translate(${width - 200}, ${height - 80})`);

    const totalProcesses = root.children ? root.children.length : 0;
    const highRiskProcesses = root.children ?
        root.children.filter(d => d.data.risk === 'high').length : 0;
    const totalOperations = root.children ?
        root.children.reduce((sum, d) => sum + d.data.operations, 0) : 0;

    stats.append('text')
        .attr('x', 0)
        .attr('y', 0)
        .attr('font-size', 11)
        .attr('fill', '#e4e7eb')
        .text(`Total Processes: ${totalProcesses}`);

    stats.append('text')
        .attr('x', 0)
        .attr('y', 20)
        .attr('font-size', 11)
        .attr('fill', '#ef4444')
        .text(`High Risk: ${highRiskProcesses}`);

    stats.append('text')
        .attr('x', 0)
        .attr('y', 40)
        .attr('font-size', 11)
        .attr('fill', '#9ca3af')
        .text(`Total Operations: ${totalOperations}`);
}

// Auto-refresh when dashboard is refreshed
if (typeof refreshDashboard !== 'undefined') {
    const originalRefreshDashboard = refreshDashboard;
    refreshDashboard = async function() {
        await originalRefreshDashboard();
        await updateProcessTree();
    };
}
