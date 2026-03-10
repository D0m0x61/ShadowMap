import json as _json
import os
from datetime import datetime
from typing import Any, Dict, List

from shadowmap.config import Config
from shadowmap.utils.logger import get_logger

logger = get_logger(__name__)

_PRIORITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#16a34a"}
_RISK_COLOR     = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#f59e0b", "CLEAN": "#16a34a"}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px 32px; line-height: 1.6; }
header { margin-bottom: 36px; }
header h1 { font-size: 26px; color: #38bdf8; font-weight: 700; }
header .meta { color: #64748b; font-size: 13px; margin-top: 6px; }
.grid { display: grid; grid-template-columns: 1fr; gap: 20px; }
.card { background: #1e293b; border-radius: 12px; padding: 24px 28px; border: 1px solid #334155; }
.card h2 { font-size: 16px; color: #7dd3fc; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #334155; font-weight: 600; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #0f172a; color: #64748b; text-align: left; padding: 8px 12px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
td { padding: 8px 12px; border-bottom: 1px solid #1e293b; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #162032; }
a { color: #38bdf8; text-decoration: none; }
a:hover { text-decoration: underline; }
.empty { color: #475569; font-style: italic; font-size: 13px; }
ul { padding-left: 20px; }
li { font-size: 13px; margin: 3px 0; color: #cbd5e1; }
#graph-container { width: 100%; height: 540px; position: relative; background: #0f172a; border-radius: 8px; overflow: hidden; }
#graph-svg { width: 100%; height: 100%; }
.graph-tooltip {
  position: absolute; background: #1e293b; border: 1px solid #334155;
  border-radius: 8px; padding: 10px 14px; font-size: 12px; color: #e2e8f0;
  pointer-events: none; opacity: 0; transition: opacity .15s;
  max-width: 260px; line-height: 1.7; z-index: 10;
}
.graph-legend { position: absolute; bottom: 14px; left: 18px; display: flex; gap: 14px; flex-wrap: wrap; }
.graph-legend span { font-size: 11px; color: #94a3b8; display: flex; align-items: center; gap: 5px; }
.graph-legend i { display: inline-block; width: 10px; height: 10px; border-radius: 50%; }
.graph-controls { position: absolute; top: 14px; right: 14px; display: flex; gap: 6px; }
.graph-controls button {
  background: #1e293b; border: 1px solid #334155; color: #94a3b8;
  border-radius: 6px; padding: 4px 10px; font-size: 12px; cursor: pointer;
}
.graph-controls button:hover { background: #334155; color: #e2e8f0; }
"""

# Node colors per type
_NODE_COLOR = {
    "domain":  "#38bdf8",
    "subdomain": "#818cf8",
    "ip":      "#34d399",
    "asn":     "#fb923c",
    "cert":    "#a78bfa",
    "cve":     "#f87171",
}

_GRAPH_JS = """
(function() {
  const W = document.getElementById('graph-container').offsetWidth;
  const H = 540;
  const data = GRAPH_DATA_PLACEHOLDER;

  const svg = d3.select('#graph-svg');
  const g   = svg.append('g');

  const zoom = d3.zoom()
    .scaleExtent([0.2, 4])
    .on('zoom', e => g.attr('transform', e.transform));
  svg.call(zoom);

  document.getElementById('graph-fit').onclick = () => {
    svg.transition().duration(400).call(zoom.transform, d3.zoomIdentity);
  };
  document.getElementById('graph-in').onclick  = () => svg.transition().duration(200).call(zoom.scaleBy, 1.4);
  document.getElementById('graph-out').onclick = () => svg.transition().duration(200).call(zoom.scaleBy, 0.7);

  const sim = d3.forceSimulation(data.nodes)
    .force('link',   d3.forceLink(data.links).id(d => d.id).distance(d => d.dist || 90).strength(0.7))
    .force('charge', d3.forceManyBody().strength(-320))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('x',      d3.forceX(W / 2).strength(0.04))
    .force('y',      d3.forceY(H / 2).strength(0.04))
    .force('collide', d3.forceCollide(d => d.r + 6));

  const link = g.append('g')
    .selectAll('line')
    .data(data.links)
    .join('line')
    .attr('stroke', '#334155')
    .attr('stroke-width', 1.2)
    .attr('stroke-opacity', 0.7);

  const tooltip = d3.select('.graph-tooltip');

  const node = g.append('g')
    .selectAll('g')
    .data(data.nodes)
    .join('g')
    .attr('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
    )
    .on('mouseover', (e, d) => {
      tooltip.style('opacity', 1).html(d.tooltip);
    })
    .on('mousemove', e => {
      const box = document.getElementById('graph-container').getBoundingClientRect();
      let x = e.clientX - box.left + 14;
      let y = e.clientY - box.top  - 10;
      if (x + 280 > W) x -= 300;
      tooltip.style('left', x + 'px').style('top', y + 'px');
    })
    .on('mouseout', () => tooltip.style('opacity', 0));

  node.append('circle')
    .attr('r',    d => d.r)
    .attr('fill', d => d.color)
    .attr('fill-opacity', 0.15)
    .attr('stroke', d => d.color)
    .attr('stroke-width', 2);

  node.append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', d => d.r + 13)
    .attr('fill', '#94a3b8')
    .attr('font-size', d => d.type === 'domain' ? '12px' : '10px')
    .attr('font-weight', d => d.type === 'domain' ? '700' : '400')
    .text(d => d.label);

  sim.on('tick', () => {
    link
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });
})();
"""


def _build_graph_data(target: str, data: Dict) -> Dict:
    nodes: List[Dict] = []
    links: List[Dict] = []
    seen_ids: set = set()

    def add_node(nid: str, label: str, ntype: str, tooltip_html: str) -> bool:
        if nid in seen_ids:
            return False
        seen_ids.add(nid)
        r = {"domain": 22, "subdomain": 14, "ip": 16, "asn": 18, "cert": 12, "cve": 11}.get(ntype, 12)
        nodes.append({
            "id":      nid,
            "label":   label[:28] + "…" if len(label) > 28 else label,
            "type":    ntype,
            "color":   _NODE_COLOR.get(ntype, "#94a3b8"),
            "r":       r,
            "tooltip": tooltip_html,
        })
        return True

    def add_link(src: str, tgt: str, dist: int = 90) -> None:
        if src in seen_ids and tgt in seen_ids:
            links.append({"source": src, "target": tgt, "dist": dist})

    # Root domain node
    add_node(target, target, "domain", f"<strong>{target}</strong><br>Root domain")

    # IP enrichment — build ip→asn map first so subdomains can link to IPs
    ip_asn: Dict[str, str] = {}
    for ip_info in data.get("ip_enrichment", []):
        ip = ip_info.get("ip", "")
        if not ip:
            continue
        asn     = ip_info.get("asn", "")
        country = ip_info.get("country", "")
        org     = ip_info.get("org", "")
        tip = (f"<strong>{ip}</strong><br>"
               f"ASN: {asn}<br>Org: {org}<br>Country: {country}")
        add_node(ip, ip, "ip", tip)

        if asn:
            ip_asn[ip] = asn
            asn_name = ip_info.get("asn_details", {}).get("name", "")
            asn_desc = ip_info.get("asn_details", {}).get("description", "")
            asn_tip  = f"<strong>{asn}</strong><br>{asn_name}<br>{asn_desc}"
            add_node(asn, asn, "asn", asn_tip)
            add_link(ip, asn, dist=70)

    # DNS A records → link domain to IPs directly
    dns_a = data.get("whois_dns", {}).get("dns_records", {}).get("A", [])
    for ip in dns_a:
        if ip in seen_ids:
            add_link(target, ip, dist=100)
        else:
            add_node(ip, ip, "ip", f"<strong>{ip}</strong><br>DNS A record")
            add_link(target, ip, dist=100)

    # Subdomains
    for sub in data.get("subdomains", []):
        sd  = sub.get("subdomain", "")
        ip  = sub.get("ip", "")
        src = ", ".join(sub.get("sources", []))
        if not sd:
            continue
        tip = f"<strong>{sd}</strong><br>IP: {ip or '—'}<br>Sources: {src}"
        add_node(sd, sd, "subdomain", tip)
        add_link(target, sd, dist=110)
        if ip and ip in seen_ids:
            add_link(sd, ip, dist=80)
        elif ip:
            add_node(ip, ip, "ip", f"<strong>{ip}</strong><br>Subdomain IP")
            add_link(sd, ip, dist=80)
            if ip in ip_asn:
                add_link(ip, ip_asn[ip], dist=70)

    # Correlated domains from certificates
    certs = data.get("certificates", {})
    for corr in certs.get("correlated_domains", [])[:15]:
        tip = f"<strong>{corr}</strong><br>Certificate correlation"
        add_node(corr, corr, "cert", tip)
        add_link(target, corr, dist=130)

    # Critical CVEs — attach to IPs that reported them via Shodan
    cve_ip_map: Dict[str, List[str]] = {}
    for host in data.get("shodan", []):
        ip = host.get("ip", "")
        for cve_id in host.get("vulns_from_shodan", []):
            cve_ip_map.setdefault(cve_id, []).append(ip)

    for cve in data.get("cves", []):
        cve_id   = cve.get("cve_id", "")
        priority = cve.get("priority", "LOW")
        if priority not in ("CRITICAL", "HIGH"):
            continue
        score = cve.get("composite_score", 0)
        kev   = "✅ CISA KEV" if cve.get("in_cisa_kev") else ""
        tip   = (f"<strong>{cve_id}</strong><br>"
                 f"Priority: {priority}<br>"
                 f"Score: {score}<br>"
                 f"CVSS: {cve.get('cvss_score','—')} · EPSS: {cve.get('epss_score','—')}<br>"
                 f"{kev}")
        add_node(cve_id, cve_id, "cve", tip)
        linked = False
        for ip in cve_ip_map.get(cve_id, []):
            if ip in seen_ids:
                add_link(ip, cve_id, dist=60)
                linked = True
        if not linked:
            add_link(target, cve_id, dist=140)

    return {"nodes": nodes, "links": links}


def _graph_card(target: str, data: Dict) -> str:
    graph_data = _build_graph_data(target, data)

    if len(graph_data["nodes"]) <= 1:
        return _card("🕸️", "Infrastructure Graph",
                     '<p class="empty">Not enough data to render the graph. '
                     'Run at least subdomains, ip, and certs modules.</p>')

    graph_data_json = _json.dumps(graph_data)

    # D3.js v7 served from cdnjs
    d3_url = "https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"

    legend_items = [
        ("domain",    "Domain"),
        ("subdomain", "Subdomain"),
        ("ip",        "IP"),
        ("asn",       "ASN"),
        ("cert",      "Cert correlation"),
        ("cve",       "CVE (HIGH+)"),
    ]
    legend_html = "".join(
        f'<span><i style="background:{_NODE_COLOR[t]}"></i>{label}</span>'
        for t, label in legend_items
    )

    js = _GRAPH_JS.replace("GRAPH_DATA_PLACEHOLDER", graph_data_json)

    content = f"""
<div id="graph-container">
  <svg id="graph-svg"></svg>
  <div class="graph-tooltip"></div>
  <div class="graph-controls">
    <button id="graph-in">+</button>
    <button id="graph-out">−</button>
    <button id="graph-fit">fit</button>
  </div>
  <div class="graph-legend">{legend_html}</div>
</div>
<script src="{d3_url}"></script>
<script>{js}</script>
"""
    return _card("🕸️", "Infrastructure Graph", content)


def _badge(text: str, cmap: Dict, default: str = "#6b7280") -> str:
    c = cmap.get(str(text), default)
    return f'<span style="background:{c};color:#fff;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700">{text}</span>'


def _link(url: str, label: str = "") -> str:
    return f'<a href="{url}" target="_blank" rel="noopener">{label or url}</a>'


def _table(headers: List[str], rows: List[List[Any]]) -> str:
    if not rows:
        return '<p class="empty">No data found.</p>'
    th   = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def _card(icon: str, title: str, content: str, count: int = None) -> str:
    cnt = (
        f' <span style="background:#334155;color:#94a3b8;padding:1px 8px;border-radius:10px;font-size:12px">{count}</span>'
        if count is not None else ""
    )
    return f'<div class="card"><h2>{icon} {title}{cnt}</h2>{content}</div>'


def _summary(meta: Dict, data: Dict) -> str:
    rows = [
        ("Target",      meta.get("target", "—")),
        ("Type",        meta.get("target_type", "—").upper()),
        ("Timestamp",   meta.get("timestamp", "—")),
        ("Modules run", ", ".join(meta.get("modules_run", []))),
        ("Subdomains",  str(len(data.get("subdomains", [])))),
        ("IPs",         str(len(data.get("ip_enrichment", [])))),
        ("CVEs",        str(len(data.get("cves", [])))),
        ("Leaks",       str(len(data.get("leaks", [])))),
    ]
    return "<table>" + "".join(
        f"<tr><td style='color:#94a3b8;width:140px'>{k}</td><td><strong>{v}</strong></td></tr>"
        for k, v in rows
    ) + "</table>"


def _whois(data: Dict) -> str:
    w = data.get("whois_dns", {}).get("whois", {})
    if not w or w.get("error"):
        return '<p class="empty">WHOIS data not available.</p>'
    rows = [
        ("Registrar",    w.get("registrar", "—")),
        ("Created",      w.get("creation_date", "—")),
        ("Expires",      w.get("expiration_date", "—")),
        ("Name Servers", ", ".join(w.get("name_servers", []))),
        ("Emails",       ", ".join(w.get("emails", []))),
        ("Country",      w.get("country", "—")),
        ("Org",          w.get("org", "—")),
    ]
    return "<table>" + "".join(
        f"<tr><td style='color:#94a3b8;width:140px'>{k}</td><td>{v or '—'}</td></tr>"
        for k, v in rows
    ) + "</table>"


def _dns(data: Dict) -> str:
    dns = data.get("whois_dns", {}).get("dns_records", {})
    if not dns:
        return '<p class="empty">DNS records not available.</p>'
    rows = [[rtype, "<br>".join(str(v) for v in vals)] for rtype, vals in dns.items() if vals]
    return _table(["Record", "Values"], rows)


def _subdomains(items: List[Dict]) -> str:
    rows = [[s["subdomain"], s.get("ip") or "—", ", ".join(s.get("sources", []))] for s in items]
    return _table(["Subdomain", "IP", "Sources"], rows)


def _ips(items: List[Dict]) -> str:
    rows = [
        [i.get("ip"), i.get("country"), i.get("org"), i.get("asn"), i.get("asn_details", {}).get("name", "—")]
        for i in items
    ]
    return _table(["IP", "Country", "Org", "ASN", "ASN Name"], rows)


def _certs(data: Dict) -> str:
    if not data:
        return '<p class="empty">Certificate data not available.</p>'
    corr = data.get("correlated_domains", [])
    html = (
        f"<p><strong>Certificates:</strong> {data.get('total_certs', 0)} &nbsp;·&nbsp; "
        f"<strong>Correlated domains:</strong> {len(corr)}</p>"
    )
    if corr:
        html += "<ul style='margin-top:8px'>" + "".join(f"<li>{d}</li>" for d in corr[:30]) + "</ul>"
    return html


def _shodan(items: List[Dict]) -> str:
    rows = [
        [
            h.get("ip"), h.get("os") or "—",
            ", ".join(str(p) for p in h.get("ports", [])) or "—",
            h.get("isp") or "—",
            str(len(h.get("vulns_from_shodan", []))),
        ]
        for h in items
    ]
    return _table(["IP", "OS", "Ports", "ISP", "CVEs"], rows)


def _cves(items: List[Dict]) -> str:
    rows = [
        [
            _link(f"https://nvd.nist.gov/vuln/detail/{c['cve_id']}", c["cve_id"]),
            str(c.get("cvss_score", "—")),
            str(c.get("epss_score", "—")),
            "✅" if c.get("in_cisa_kev") else "—",
            str(c.get("composite_score", "—")),
            _badge(c.get("priority", "LOW"), _PRIORITY_COLOR),
        ]
        for c in items
    ]
    return _table(["CVE", "CVSS", "EPSS", "KEV", "Score", "Priority"], rows)


def _reputation(items: List[Dict]) -> str:
    rows = []
    for r in items:
        if r.get("skipped"):
            rows.append([r.get("ip"), "—", "—", "—", "key not set"])
            continue
        rows.append([
            r.get("ip"),
            str(r.get("abuse_confidence", "—")),
            str(r.get("total_reports", "—")),
            "Yes" if r.get("is_tor") else "No",
            _badge(r.get("risk_level", "CLEAN"), _RISK_COLOR),
        ])
    return _table(["IP", "Abuse Score", "Reports", "TOR", "Risk"], rows)


def _leaks(items: List[Dict]) -> str:
    rows = [
        [
            _link(lk.get("repo_url", "#"), lk.get("repo", "—")),
            lk.get("file", "—"),
            lk.get("query", "—"),
            _badge(lk.get("severity", "MEDIUM"), _PRIORITY_COLOR),
            _link(lk.get("url", "#"), "view"),
        ]
        for lk in items
    ]
    return _table(["Repository", "File", "Query", "Severity", "Link"], rows)


def save(data: Dict[str, Any], target: str) -> str:
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = target.replace(".", "_").replace("/", "_").replace(":", "_")
    path = os.path.join(Config.OUTPUT_DIR, f"report_{name}_{ts}.html")

    meta       = data.get("meta", {})
    subdomains = data.get("subdomains", [])
    ips        = data.get("ip_enrichment", [])
    certs      = data.get("certificates", {})
    shodan     = data.get("shodan", [])
    cves       = data.get("cves", [])
    rep        = data.get("reputation", [])
    leaks      = data.get("leaks", [])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShadowMap — {target}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>🔍 ShadowMap</h1>
  <div class="meta">
    Target: <strong style="color:#e2e8f0">{target}</strong> &nbsp;·&nbsp;
    {meta.get('timestamp', datetime.now().isoformat())} &nbsp;·&nbsp;
    {', '.join(meta.get('modules_run', []))}
  </div>
</header>
<div class="grid">
{_card("📋", "Summary", _summary(meta, data))}
{_graph_card(target, data)}
{_card("📝", "WHOIS", _whois(data))}
{_card("🌐", "DNS Records", _dns(data))}
{_card("📡", "Subdomains", _subdomains(subdomains), len(subdomains))}
{_card("🗺️", "IP & ASN", _ips(ips), len(ips))}
{_card("🔒", "Certificates", _certs(certs))}
{_card("🛰️", "Shodan", _shodan(shodan), len(shodan))}
{_card("⚠️", "CVEs", _cves(cves), len(cves))}
{_card("🚨", "Reputation", _reputation(rep), len(rep))}
{_card("🔑", "GitHub Leaks", _leaks(leaks), len(leaks))}
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"[output] HTML: {path}")
    return os.path.abspath(path)
