from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from aegismeta import __app_name__, __version__
from aegismeta.infra import db
from aegismeta.infra.logging_utils import LOGGER


def _graph_data(evidence_rows: List[Dict[str, Any]], metadata_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    nodes = []
    links = []
    for ev in evidence_rows:
        nodes.append({"id": f"e{ev['id']}", "name": ev["logical_name"], "type": "evidence"})
    for meta in metadata_rows:
        nodes.append({"id": f"m{meta['id']}", "name": meta["key"], "type": "metadata"})
        links.append({"source": f"e{meta['evidence_id']}", "target": f"m{meta['id']}", "value": 1})
    return {"nodes": nodes, "links": links}


def generate_html_report(case_db: db.CaseDatabase, output_path: Path) -> Path:
    conn = case_db.conn
    case_id = case_db.case_id or 1
    case_row = db.get_case(conn, case_id)
    evidence = db.iter_rows(db.fetch_evidence_items(conn, case_id))
    anomalies = db.iter_rows(db.fetch_anomalies(conn, case_id))
    timeline = db.iter_rows(db.fetch_timeline(conn, case_id))
    audit = db.iter_rows(db.fetch_audit_log(conn, case_id))
    metadata_rows = db.iter_rows(conn.execute("SELECT * FROM metadata_records WHERE evidence_id IN (SELECT id FROM evidence_items WHERE case_id=?)", (case_id,)))

    graph = _graph_data(evidence, metadata_rows)

    html = f"""
    <html>
    <head>
    <meta charset='utf-8'>
    <title>{__app_name__} Report</title>
    <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background: #f5f5f5; }}
    .section {{ margin-bottom: 24px; }}
    .graph {{ width: 100%; height: 400px; border: 1px solid #ddd; }}
    </style>
    </head>
    <body>
    <h1>{__app_name__} - Case Report</h1>
    <p>Version: {__version__} | Generated: {datetime.utcnow().isoformat()}Z</p>

    <div class='section'>
    <h2>Case Summary</h2>
    <pre>{json.dumps(dict(case_row) if case_row else {}, indent=2)}</pre>
    </div>

    <div class='section'>
    <h2>Evidence</h2>
    <table>
    <tr><th>ID</th><th>Name</th><th>Path</th><th>SHA256</th><th>BLAKE3</th></tr>
    {''.join([f"<tr><td>{e['id']}</td><td>{e['logical_name']}</td><td>{e['path']}</td><td>{e['sha256']}</td><td>{e['blake3']}</td></tr>" for e in evidence])}
    </table>
    </div>

    <div class='section'>
    <h2>Metadata Records</h2>
    <table>
    <tr><th>ID</th><th>Evidence</th><th>Extractor</th><th>Key</th><th>Value</th><th>Confidence</th></tr>
    {''.join([f"<tr><td>{m['id']}</td><td>{m['evidence_id']}</td><td>{m['extractor']}</td><td>{m['key']}</td><td>{m['value_json']}</td><td>{m['confidence']}</td></tr>" for m in metadata_rows])}
    </table>
    </div>

    <div class='section'>
    <h2>Anomalies</h2>
    <table>
    <tr><th>ID</th><th>Category</th><th>Severity</th><th>Description</th><th>Evidence</th></tr>
    {''.join([f"<tr><td>{a['id']}</td><td>{a['category']}</td><td>{a['severity']}</td><td>{a['description']}</td><td>{a.get('evidence_id','')}</td></tr>" for a in anomalies])}
    </table>
    </div>

    <div class='section'>
    <h2>Timeline</h2>
    <table>
    <tr><th>Time</th><th>Type</th><th>Source</th><th>Detail</th></tr>
    {''.join([f"<tr><td>{t['event_time_utc']}</td><td>{t['event_type']}</td><td>{t['source']}</td><td>{t['detail_json']}</td></tr>" for t in timeline])}
    </table>
    </div>

    <div class='section'>
    <h2>Audit Log</h2>
    <table>
    <tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th><th>Prev Hash</th><th>Hash</th></tr>
    {''.join([f"<tr><td>{a['ts']}</td><td>{a['actor']}</td><td>{a['action']}</td><td>{a['detail_json']}</td><td>{a['prev_hash']}</td><td>{a['entry_hash']}</td></tr>" for a in audit])}
    </table>
    </div>

    <div class='section'>
    <h2>Evidence Graph</h2>
    <div id='graph' class='graph'></div>
    <script>
    const data = {json.dumps(graph)};
    const container = document.getElementById('graph');
    const width = container.clientWidth;
    const height = 400;
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('width', width);
    svg.setAttribute('height', height);
    container.appendChild(svg);

    const radius = Math.min(width, height) / 3;
    data.nodes.forEach((node, idx) => {
        const angle = (idx / data.nodes.length) * Math.PI * 2;
        node.x = width / 2 + radius * Math.cos(angle);
        node.y = height / 2 + radius * Math.sin(angle);
    });

    data.links.forEach(link => {
        const src = data.nodes.find(n => n.id === link.source);
        const tgt = data.nodes.find(n => n.id === link.target);
        if (src && tgt) {
            const line = document.createElementNS(svgNS, 'line');
            line.setAttribute('x1', src.x);
            line.setAttribute('y1', src.y);
            line.setAttribute('x2', tgt.x);
            line.setAttribute('y2', tgt.y);
            line.setAttribute('stroke', '#999');
            svg.appendChild(line);
        }
    });

    data.nodes.forEach(node => {
        const circle = document.createElementNS(svgNS, 'circle');
        circle.setAttribute('cx', node.x);
        circle.setAttribute('cy', node.y);
        circle.setAttribute('r', 10);
        circle.setAttribute('fill', node.type === 'evidence' ? '#3366cc' : '#ff9933');
        svg.appendChild(circle);

        const label = document.createElementNS(svgNS, 'text');
        label.textContent = node.name;
        label.setAttribute('x', node.x + 12);
        label.setAttribute('y', node.y + 4);
        label.setAttribute('font-size', '10');
        svg.appendChild(label);
    });
    </script>
    </div>

    </body></html>
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    LOGGER.info("HTML report generated", extra={"extra_data": {"output": str(output_path)}})
    return output_path
