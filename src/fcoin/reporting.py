"""JSON and self-contained HTML report generation."""

from __future__ import annotations

from html import escape
import json
from pathlib import Path

from fcoin.analysis import AnalysisReport


def write_json_report(report: AnalysisReport, path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    target.chmod(0o600)
    return target


def write_html_report(report: AnalysisReport, path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for finding in report.findings:
        evidence = escape(json.dumps(finding.evidence, sort_keys=True))
        rows.append(
            "<tr>"
            f"<td>{finding.block}</td><td>{finding.sector}</td>"
            f"<td><span class='kind'>{escape(finding.kind)}</span></td>"
            f"<td>{escape(finding.summary)}</td>"
            f"<td>{finding.confidence:.0%}</td><td><code>{evidence}</code></td>"
            "</tr>"
        )
    warning_html = "".join(f"<li>{escape(item)}</li>" for item in report.warnings)
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FCOIN report · {escape(report.uid)}</title>
<style>
:root {{ color-scheme: dark; --bg:#090b10; --panel:#111620; --line:#263044;
--text:#eef4ff; --muted:#96a3b7; --cyan:#4de1ff; --green:#7dffb2; --amber:#ffcf70; }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.55 ui-monospace,
SFMono-Regular,Consolas,monospace }}
main {{ width:min(1500px,94vw); margin:48px auto }}
.eyebrow {{ color:var(--cyan); letter-spacing:.18em; text-transform:uppercase }}
h1 {{ margin:.25rem 0 2rem; font-size:clamp(2rem,6vw,5.5rem); letter-spacing:-.06em }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:1px;
background:var(--line); border:1px solid var(--line) }}
.metric {{ padding:20px; background:var(--panel) }}
.metric b {{ display:block; color:var(--muted); font-size:.75rem; text-transform:uppercase }}
.metric span {{ display:block; margin-top:8px; color:var(--green); word-break:break-all }}
.table-wrap {{ overflow:auto; margin-top:32px; border:1px solid var(--line) }}
table {{ width:100%; border-collapse:collapse; min-width:1000px }}
th,td {{ padding:12px 14px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top }}
th {{ position:sticky; top:0; background:#151c28; color:var(--muted); text-transform:uppercase }}
tr:hover td {{ background:#101722 }}
code {{ color:var(--muted); white-space:pre-wrap; word-break:break-word }}
.kind {{ color:var(--cyan) }} .warnings {{ color:var(--amber) }}
</style>
</head>
<body><main>
<div class="eyebrow">FCOIN / deterministic forensic report</div>
<h1>{escape(report.card_type)}</h1>
<section class="grid">
<div class="metric"><b>UID prefix</b><span>{escape(report.uid)}</span></div>
<div class="metric"><b>Image size</b><span>{report.byte_size} bytes</span></div>
<div class="metric"><b>BCC</b><span>{"valid" if report.bcc_valid else "invalid"}</span></div>
<div class="metric"><b>Findings</b><span>{len(report.findings)}</span></div>
<div class="metric"><b>SHA-256</b><span>{report.sha256}</span></div>
</section>
<section class="warnings"><ul>{warning_html}</ul></section>
<div class="table-wrap"><table>
<thead><tr><th>Block</th><th>Sector</th><th>Kind</th><th>Summary</th>
<th>Confidence</th><th>Evidence</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table></div>
</main></body></html>
"""
    target.write_text(document, encoding="utf-8")
    target.chmod(0o600)
    return target
