package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/raphael/kuberneet/pkg/finding"
	"github.com/raphael/kuberneet/pkg/graph"
)

// HTMLReport generates an interactive HTML report with D3 visualization
type HTMLReport struct {
	ScanTime    time.Time
	Findings    []finding.Finding
	AttackPaths []graph.AttackPath
	Graph       *graph.Graph
}

// NewHTMLReport creates a new HTML report
func NewHTMLReport(findings []finding.Finding, paths []graph.AttackPath, g *graph.Graph) *HTMLReport {
	return &HTMLReport{
		ScanTime:    time.Now(),
		Findings:    findings,
		AttackPaths: paths,
		Graph:       g,
	}
}

// Generate creates the HTML file
func (r *HTMLReport) Generate(filepath string) error {
	// Convert data to JSON for D3
	graphJSON, err := json.Marshal(r.Graph)
	if err != nil {
		return err
	}
	findingsJSON, err := json.Marshal(r.Findings)
	if err != nil {
		return err
	}
	pathsJSON, err := json.Marshal(r.AttackPaths)
	if err != nil {
		return err
	}

	// Write HTML in parts to avoid Sprintf formatting issues
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>KuberNeet Security Report</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }
        .header { text-align: center; padding: 20px; border-bottom: 1px solid #30363d; margin-bottom: 30px; }
        .header h1 { color: #58a6ff; margin: 0; font-size: 2.5em; }
        .header .subtitle { color: #8b949e; margin-top: 10px; }
        .stats { display: flex; justify-content: center; gap: 30px; margin: 30px 0; }
        .stat-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; min-width: 120px; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .stat-label { color: #8b949e; font-size: 0.9em; margin-top: 5px; }
        .critical { color: #f85149; }
        .high { color: #da3633; }
        .medium { color: #d29922; }
        .low { color: #58a6ff; }
        .container { max-width: 1400px; margin: 0 auto; }
        .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin: 20px 0; padding: 20px; }
        .section h2 { margin-top: 0; color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        #graph { width: 100%; height: 600px; border: 1px solid #30363d; border-radius: 4px; }
        .finding { background: #0d1117; border-left: 4px solid; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .finding.critical { border-color: #f85149; }
        .finding.high { border-color: #da3633; }
        .finding.medium { border-color: #d29922; }
        .finding.low { border-color: #58a6ff; }
        .finding-id { font-family: monospace; color: #8b949e; font-size: 0.85em; }
        .finding-title { font-weight: 600; margin: 5px 0; }
        .finding-desc { color: #8b949e; font-size: 0.95em; }
        .attack-path { background: #0d1117; border: 1px solid #30363d; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .path-chain { font-family: monospace; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .path-node { background: #238636; padding: 5px 10px; border-radius: 4px; color: white; }
        .path-arrow { color: #8b949e; }
        .path-risk { float: right; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #0d1117; font-weight: 600; color: #58a6ff; }
        tr:hover { background: #0d1117; }
        .node circle { stroke: #fff; stroke-width: 1.5px; }
        .node text { font-size: 10px; fill: #c9d1d9; }
        .link { stroke: #999; stroke-opacity: 0.6; stroke-width: 1.5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>` + "🔍 " + `KuberNeet</h1>
        <div class="subtitle">Security Scan Report - ` + r.ScanTime.Format("2006-01-02 15:04:05") + `</div>
    </div>

    <div class="container">
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number critical">` + fmt.Sprintf("%d", countBySeverity(r.Findings, "CRITICAL")) + `</div>
                <div class="stat-label">CRITICAL</div>
            </div>
            <div class="stat-box">
                <div class="stat-number high">` + fmt.Sprintf("%d", countBySeverity(r.Findings, "HIGH")) + `</div>
                <div class="stat-label">HIGH</div>
            </div>
            <div class="stat-box">
                <div class="stat-number medium">` + fmt.Sprintf("%d", countBySeverity(r.Findings, "MEDIUM")) + `</div>
                <div class="stat-label">MEDIUM</div>
            </div>
            <div class="stat-box">
                <div class="stat-number low">` + fmt.Sprintf("%d", countBySeverity(r.Findings, "LOW")) + `</div>
                <div class="stat-label">LOW</div>
            </div>
        </div>

        <div class="section">
            <h2>` + "🕸️ " + `Attack Path Graph</h2>
            <div id="graph"></div>
        </div>

        <div class="section">
            <h2>` + "⚡ " + `Attack Paths</h2>
            <div id="attack-paths"></div>
        </div>

        <div class="section">
            <h2>` + "📋 " + `Findings</h2>
            <div id="findings"></div>
        </div>
    </div>

    <script>
        const graphData = ` + string(graphJSON) + `;
        const findingsData = ` + string(findingsJSON) + `;
        const pathsData = ` + string(pathsJSON) + `;

        // Render graph
        function renderGraph() {
            const width = document.getElementById('graph').clientWidth;
            const height = 600;

            const svg = d3.select('#graph')
                .append('svg')
                .attr('width', width)
                .attr('height', height);

            const color = d3.scaleOrdinal()
                .domain(['pod', 'service', 'serviceaccount', 'role', 'clusterrole', 'node'])
                .range(['#58a6ff', '#238636', '#d29922', '#a371f7', '#f85149', '#8b949e']);

            const nodes = Object.values(graphData.nodes).map(n => ({...n}));
            const links = graphData.edges.map(e => ({...e}));

            const simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2));

            const link = svg.append('g')
                .selectAll('line')
                .data(links)
                .enter().append('line')
                .attr('class', 'link')
                .attr('stroke', '#30363d');

            const node = svg.append('g')
                .selectAll('g')
                .data(nodes)
                .enter().append('g')
                .attr('class', 'node')
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));

            node.append('circle')
                .attr('r', d => d.risk_score > 50 ? 15 : 8)
                .attr('fill', d => color(d.type))
                .attr('stroke', d => d.risk_score > 50 ? '#f85149' : '#fff')
                .attr('stroke-width', d => d.risk_score > 50 ? 3 : 1);

            node.append('text')
                .attr('dx', 12)
                .attr('dy', 4)
                .text(d => d.name);

            simulation.on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
            });

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
        }

        // Render attack paths
        function renderAttackPaths() {
            const container = document.getElementById('attack-paths');
            if (pathsData.length === 0) {
                container.innerHTML = '<p>No attack paths identified.</p>';
                return;
            }
            pathsData.forEach((path, i) => {
                const div = document.createElement('div');
                div.className = 'attack-path';
                const riskClass = path.risk_score >= 100 ? 'critical' : path.risk_score >= 50 ? 'high' : 'medium';
                const pathNodes = path.path.map((node, j) => {
                    const arrow = j < path.path.length - 1 ? '<span class="path-arrow">&rarr;</span>' : '';
                    return '<span class="path-node">' + node.type + '/' + node.name + '</span>' + arrow;
                }).join('');
                div.innerHTML = '<div class="finding-title">' + path.technique + '</div>' +
                    '<div class="path-chain">' + pathNodes + '</div>' +
                    '<div style="margin-top: 10px; color: #8b949e;">' + path.description + '</div>' +
                    '<div class="path-risk ' + riskClass + '">Risk: ' + Math.round(path.risk_score) + '</div>';
                container.appendChild(div);
            });
        }

        // Render findings table
        function renderFindings() {
            const container = document.getElementById('findings');
            if (findingsData.length === 0) {
                container.innerHTML = '<p>No findings.</p>';
                return;
            }
            const rows = findingsData.map(f => {
                return '<tr><td class="' + f.severity.toLowerCase() + '">' + f.severity + '</td>' +
                    '<td>' + f.id + '</td>' +
                    '<td>' + f.resource_kind + '/' + f.resource_name + '</td>' +
                    '<td>' + f.message + '</td></tr>';
            }).join('');
            container.innerHTML = '<table><thead><tr><th>Severity</th><th>ID</th><th>Resource</th><th>Issue</th></tr></thead>' +
                '<tbody>' + rows + '</tbody></table>';
        }

        renderGraph();
        renderAttackPaths();
        renderFindings();
    </script>
</body>
</html>`

	_, err = f.WriteString(html)
	return err
}

func countBySeverity(findings []finding.Finding, severity string) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}
