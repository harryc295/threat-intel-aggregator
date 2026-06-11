"""Read a JSON enrichment report and write a self-contained HTML dashboard."""

import json
import sys
from pathlib import Path
from datetime import datetime


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

def _risk_class(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _badge(score: int) -> str:
    cls = _risk_class(score)
    return f'<span class="badge {cls}">{score}</span>'


def _cell(v) -> str:
    if v is None:
        return "<td>—</td>"
    if isinstance(v, list):
        return f"<td>{', '.join(str(x) for x in v) or '—'}</td>"
    return f"<td>{v}</td>"


def _row(record: dict) -> str:
    ioc = record.get("ioc", "")
    ioc_type = record.get("ioc_type", "")
    risk = record.get("risk_score", 0)
    cls = _risk_class(risk)

    e = record.get("enrichments", {})
    vt = e.get("virustotal", {})
    abuse = e.get("abuseipdb", {})
    geo = e.get("geolocation", {})
    shodan = e.get("shodan", {})
    whois_data = e.get("whois", {})

    positives = vt.get("positives", "—")
    total = vt.get("total", "—")
    vt_str = f"{positives}/{total}" if positives != "—" else "—"

    abuse_score = abuse.get("abuse_confidence_score", "—")
    country = geo.get("country") or abuse.get("country_code") or whois_data.get("country") or "—"
    isp = geo.get("isp") or shodan.get("isp") or "—"
    ports = ", ".join(str(p) for p in shodan.get("open_ports", [])) or "—"
    vulns = len(shodan.get("vulnerabilities", []))
    vulns_str = str(vulns) if vulns else "—"
    registrar = whois_data.get("registrar") or "—"
    resolved = record.get("resolved_ip") or "—"

    return (
        f'<tr class="row-{cls}">'
        f"<td>{ioc}</td>"
        f"<td>{ioc_type}</td>"
        f"<td>{_badge(risk)}</td>"
        f"<td>{vt_str}</td>"
        f"<td>{abuse_score}</td>"
        f"<td>{country}</td>"
        f"<td>{isp}</td>"
        f"<td>{ports}</td>"
        f"<td>{vulns_str}</td>"
        f"<td>{registrar}</td>"
        f"<td>{resolved}</td>"
        "</tr>"
    )


# --------------------------------------------------------------------------- #
#  HTML template
# --------------------------------------------------------------------------- #

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Intelligence Dashboard</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0f1117;
    color: #e2e8f0;
    margin: 0;
    padding: 1.5rem;
  }}
  h1 {{ color: #f8fafc; margin-bottom: 0.25rem; }}
  .meta {{ color: #64748b; font-size: 0.85rem; margin-bottom: 1.5rem; }}

  /* Stats cards */
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .card {{
    background: #1e2433;
    border: 1px solid #2d3748;
    border-radius: 8px;
    padding: 1rem 1.4rem;
    min-width: 140px;
  }}
  .card .label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card .value {{ font-size: 2rem; font-weight: 700; margin-top: 0.2rem; }}
  .card.red .value   {{ color: #f87171; }}
  .card.yellow .value {{ color: #fbbf24; }}
  .card.green .value  {{ color: #34d399; }}
  .card.blue .value   {{ color: #60a5fa; }}

  /* Controls */
  .controls {{ display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; }}
  input[type=text] {{
    background: #1e2433;
    border: 1px solid #2d3748;
    border-radius: 6px;
    color: #e2e8f0;
    padding: 0.45rem 0.75rem;
    font-size: 0.9rem;
    width: 280px;
    outline: none;
  }}
  input[type=text]:focus {{ border-color: #60a5fa; }}
  select {{
    background: #1e2433;
    border: 1px solid #2d3748;
    border-radius: 6px;
    color: #e2e8f0;
    padding: 0.45rem 0.75rem;
    font-size: 0.9rem;
    outline: none;
  }}

  /* Table */
  .tbl-wrap {{ overflow-x: auto; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }}
  thead th {{
    background: #1a2035;
    color: #94a3b8;
    text-align: left;
    padding: 0.6rem 0.8rem;
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
    border-bottom: 2px solid #2d3748;
  }}
  thead th:hover {{ color: #e2e8f0; }}
  thead th::after {{ content: " ⇅"; opacity: 0.4; font-size: 0.7rem; }}
  thead th.asc::after  {{ content: " ↑"; opacity: 1; }}
  thead th.desc::after {{ content: " ↓"; opacity: 1; }}
  tbody tr {{ border-bottom: 1px solid #1e2433; }}
  tbody tr:hover {{ background: #1e2433; }}
  tbody td {{ padding: 0.55rem 0.8rem; white-space: nowrap; }}

  /* Row risk coloring */
  .row-high  {{ background: rgba(248, 113, 113, 0.08); }}
  .row-medium {{ background: rgba(251, 191, 36, 0.06); }}
  .row-low   {{ background: transparent; }}

  /* Badges */
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 600;
  }}
  .badge.high   {{ background: rgba(248, 113, 113, 0.2); color: #f87171; }}
  .badge.medium {{ background: rgba(251, 191, 36, 0.2); color: #fbbf24; }}
  .badge.low    {{ background: rgba(52, 211, 153, 0.2); color: #34d399; }}

  .hidden {{ display: none !important; }}
  .no-results {{ text-align: center; color: #64748b; padding: 2rem; }}
</style>
</head>
<body>
<h1>Threat Intelligence Dashboard</h1>
<p class="meta">Generated: {generated} &nbsp;|&nbsp; Report: {report_file}</p>

<div class="stats">
  <div class="card blue">
    <div class="label">Total IOCs</div>
    <div class="value">{total_iocs}</div>
  </div>
  <div class="card red">
    <div class="label">High Risk</div>
    <div class="value">{high_risk}</div>
  </div>
  <div class="card yellow">
    <div class="label">Medium Risk</div>
    <div class="value">{medium_risk}</div>
  </div>
  <div class="card green">
    <div class="label">Low / Clean</div>
    <div class="value">{low_risk}</div>
  </div>
  <div class="card blue">
    <div class="label">Avg Risk Score</div>
    <div class="value">{avg_risk}</div>
  </div>
</div>

<div class="controls">
  <input type="text" id="search" placeholder="Search IOC, country, ISP…" oninput="applyFilters()">
  <select id="typeFilter" onchange="applyFilters()">
    <option value="">All types</option>
    <option value="ip">IP</option>
    <option value="domain">Domain</option>
    <option value="hash">Hash</option>
  </select>
  <select id="riskFilter" onchange="applyFilters()">
    <option value="">All risk levels</option>
    <option value="high">High (≥70)</option>
    <option value="medium">Medium (30-69)</option>
    <option value="low">Low (&lt;30)</option>
  </select>
</div>

<div class="tbl-wrap">
<table id="iocTable">
  <thead>
    <tr>
      <th onclick="sortTable(0)">IOC</th>
      <th onclick="sortTable(1)">Type</th>
      <th onclick="sortTable(2)">Risk</th>
      <th onclick="sortTable(3)">VT (pos/total)</th>
      <th onclick="sortTable(4)">Abuse Score</th>
      <th onclick="sortTable(5)">Country</th>
      <th onclick="sortTable(6)">ISP</th>
      <th onclick="sortTable(7)">Open Ports</th>
      <th onclick="sortTable(8)">CVEs</th>
      <th onclick="sortTable(9)">Registrar</th>
      <th onclick="sortTable(10)">Resolved IP</th>
    </tr>
  </thead>
  <tbody id="tbody">
{rows}
  </tbody>
</table>
<p class="no-results hidden" id="noResults">No matching IOCs found.</p>
</div>

<script>
  let sortCol = 2;
  let sortDir = -1; // -1 = desc

  function applyFilters() {{
    const q = document.getElementById("search").value.toLowerCase();
    const typeF = document.getElementById("typeFilter").value;
    const riskF = document.getElementById("riskFilter").value;
    let visible = 0;
    document.querySelectorAll("#tbody tr").forEach(row => {{
      const text = row.textContent.toLowerCase();
      const type = row.cells[1].textContent.trim();
      const cls = Array.from(row.classList).find(c => c.startsWith("row-"))?.replace("row-", "") || "";
      const matchText = !q || text.includes(q);
      const matchType = !typeF || type === typeF;
      const matchRisk = !riskF || cls === riskF;
      const show = matchText && matchType && matchRisk;
      row.classList.toggle("hidden", !show);
      if (show) visible++;
    }});
    document.getElementById("noResults").classList.toggle("hidden", visible > 0);
  }}

  function sortTable(col) {{
    const headers = document.querySelectorAll("thead th");
    if (sortCol === col) sortDir *= -1;
    else {{ sortCol = col; sortDir = -1; }}
    headers.forEach((h, i) => {{
      h.classList.remove("asc", "desc");
      if (i === col) h.classList.add(sortDir === 1 ? "asc" : "desc");
    }});

    const tbody = document.getElementById("tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    rows.sort((a, b) => {{
      let av = a.cells[col]?.textContent.trim() || "";
      let bv = b.cells[col]?.textContent.trim() || "";
      const an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) return (an - bn) * sortDir;
      return av.localeCompare(bv) * sortDir;
    }});
    rows.forEach(r => tbody.appendChild(r));
  }}

  // Default sort by risk descending on load
  sortTable(2);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #

def generate(report_path: str, output_path: str) -> None:
    report_path = Path(report_path)
    records = json.loads(report_path.read_text(encoding="utf-8"))

    total = len(records)
    scores = [r.get("risk_score", 0) for r in records]
    high = sum(1 for s in scores if s >= 70)
    medium = sum(1 for s in scores if 30 <= s < 70)
    low = total - high - medium
    avg = round(sum(scores) / total) if total else 0

    rows_html = "\n".join(_row(r) for r in records)

    html = _HTML.format(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report_file=report_path.name,
        total_iocs=total,
        high_risk=high,
        medium_risk=medium,
        low_risk=low,
        avg_risk=avg,
        rows=rows_html,
    )

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[dashboard] HTML written to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python dashboard.py <report.json> <output.html>")
        sys.exit(1)
    generate(sys.argv[1], sys.argv[2])
