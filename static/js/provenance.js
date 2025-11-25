/**
 * Provenance Graph Visualization using D3.js
 * Shows relationships between processes and files
 */

async function updateProvenanceGraph() {
    try {
        const response = await fetch('/api/provenance-graph');
        const data = await response.json();

        if (!data.nodes || data.nodes.length === 0) {
            document.getElementById('provenanceGraph').innerHTML =
                '<p class="no-data">No provenance data available</p>';
            return;
        }

        renderProvenanceGraph(data);
    } catch (error) {
        console.error('Error loading provenance graph:', error);
    }
}

function renderProvenanceGraph(data) {
    // Clear previous graph
    d3.select('#provenanceGraph').selectAll('*').remove();

    const container = document.getElementById('provenanceGraph');
    const width = container.clientWidth;
    const height = 500;

    // Create SVG
    const svg = d3.select('#provenanceGraph')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    // Create simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges)
            .id(d => d.id)
            .distance(150))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(40));

    // Create arrow markers for directed edges
    svg.append('defs').selectAll('marker')
        .data(['normal', 'honeyfil'])
        .enter().append('marker')
        .attr('id', d => `arrow-${d}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 25)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', d => d === 'honeyfil' ? '#ef4444' : '#9ca3af');

    // Create links
    const link = svg.append('g')
        .selectAll('line')
        .data(data.edges)
        .enter().append('line')
        .attr('stroke', d => {
            const target = data.nodes.find(n => n.id === d.target);
            return target && target.is_honeyfil ? '#ef4444' : '#2d3354';
        })
        .attr('stroke-width', 2)
        .attr('stroke-opacity', 0.6)
        .attr('marker-end', d => {
            const target = data.nodes.find(n => n.id === d.target);
            return target && target.is_honeyfil ? 'url(#arrow-honeyfil)' : 'url(#arrow-normal)';
        });

    // Create nodes
    const node = svg.append('g')
        .selectAll('g')
        .data(data.nodes)
        .enter().append('g')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));

    // Add circles for nodes
    node.append('circle')
        .attr('r', 20)
        .attr('fill', d => {
            if (d.type === 'honeyfil') return '#ef4444';
            if (d.type === 'process') return '#667eea';
            return '#3b82f6';
        })
        .attr('stroke', '#fff')
        .attr('stroke-width', 2);

    // Add icons/text for node types
    node.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 5)
        .attr('font-size', 16)
        .text(d => d.type === 'process' ? '⚙️' : d.type === 'honeyfil' ? '🍯' : '📄');

    // Add labels
    node.append('text')
        .attr('dy', -25)
        .attr('text-anchor', 'middle')
        .attr('font-size', 11)
        .attr('fill', '#e4e7eb')
        .text(d => d.label.substring(0, 20) + (d.label.length > 20 ? '...' : ''));

    // Add tooltips
    node.append('title')
        .text(d => `${d.label}\nType: ${d.type}\n${d.path || ''}`);

    // Update positions on simulation tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    // Add legend
    const legend = svg.append('g')
        .attr('class', 'legend')
        .attr('transform', `translate(20, ${height - 100})`);

    const legendData = [
        { label: 'Process', color: '#667eea', icon: '⚙️' },
        { label: 'File', color: '#3b82f6', icon: '📄' },
        { label: 'Honeyfile', color: '#ef4444', icon: '🍯' }
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
}

// Auto-refresh when dashboard is refreshed
if (typeof refreshDashboard !== 'undefined') {
    const originalRefreshDashboard = refreshDashboard;
    refreshDashboard = async function() {
        await originalRefreshDashboard();
        await updateProvenanceGraph();
    };
}
