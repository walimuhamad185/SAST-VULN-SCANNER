"""Output generators: interactive HTML dashboard, JSON, SARIF (2.1.0), Markdown."""
import html
import json
import datetime
from .config import SEVERITY_ORDER
from . import __version__ as _VERSION


def to_sarif(findings, target) -> str:
    rules = []
    results = []
    seen_rules = {}
    for f in findings:
        rid = f.rule
        if rid not in seen_rules:
            seen_rules[rid] = len(seen_rules) + 1
            rules.append({
                "id": rid.replace(" ", ""),
                "name": rid,
                "shortDescription": {"text": rid},
                "fullDescription": {"text": f.message},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html",
                "defaultConfiguration": {"level": _severity_to_sarif(f.severity)},
                "properties": {"tags": ["security", "sast", f.cwe, f.owasp],
                               "precision": "high" if f.confidence == "HIGH" else "medium"},
            })
        results.append({
            "ruleId": rid.replace(" ", ""),
            "ruleIndex": seen_rules[rid] - 1,
            "level": _severity_to_sarif(f.severity),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _rel_path(f.file)},
                "region": {"startLine": f.line, "startColumn": max(f.column, 1)},
            }}],
            "properties": {"cwe": f.cwe, "confidence": f.confidence,
                           "owasp": f.owasp, "attackTechnique": f.attack_technique},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SAST-VULN-SCANNER", "version": _VERSION,
                                 "rules": rules,
                                 "informationUri": "https://github.com/walimuhamad185/SAST-VULN-SCANNER"}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _rel_path(p: str) -> str:
    import os
    return os.path.basename(p)


def _severity_to_sarif(sev):
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
            "LOW": "note", "INFO": "note"}.get(sev, "warning")


def to_html(findings, target, raw_total, verified_total) -> str:
    sev_color = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
        "LOW": "#2563eb", "INFO": "#6b7280",
    }
    rows = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
        code = html.escape(f.code)
        owasp = html.escape(f.owasp) if f.owasp else "-"
        df = "".join(f"<span class='chip'>🡒 {html.escape(p)}</span>" for p in f.dataflow[:3])
        rows.append(f"""
        <tr>
          <td><span class='sev' style='background:{sev_color.get(f.severity, '#6b7280')}'>{f.severity}</span></td>
          <td class='rule'>{html.escape(f.rule)}</td>
          <td><code>{html.escape(f.file)}:{f.line}</code></td>
          <td class='cwe'>{f.cwe}</td>
          <td class='owasp'>{owasp}</td>
          <td class='msg'>{html.escape(f.message)}</td>
          <td class='df'>{df or '-'}</td>
        </tr>""")
    return f"""<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>SAST Security Report</title>
<style>
:root {{ color-scheme: dark; }}
body {{ margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
       background:#0b0f17; color:#e2e8f0; }}
header {{ padding:24px 28px; border-bottom:1px solid #1e293b; background:linear-gradient(180deg,#111827,#0b0f17); }}
h1 {{ margin:0 0 4px; font-size:22px; }}
.sub {{ color:#64748b; font-size:13px; }}
.badge {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px;
          background:#1e293b; color:#cbd5e1; margin-right:6px; }}
.badge.crit {{ background:#7f1d1d; color:#fecaca; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; padding:10px 14px; background:#111827; color:#94a3b8;
      font-size:11px; text-transform:uppercase; letter-spacing:.05em;
      border-bottom:1px solid #1e293b; }}
td {{ padding:10px 14px; border-bottom:1px solid #1e293b; vertical-align:top; }}
.sev {{ padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; color:#fff; }}
.code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:#93c5fd; }}
.cwe {{ color:#fbbf24; }} .owasp {{ color:#a78bfa; }} .msg {{ color:#cbd5e1; }}
.df {{ color:#34d399; font-size:11px; }} .chip {{ display:block; }}
</style></head><body>
<header>
  <h1>🛡️ SAST-VULN-SCANNER — Security Report</h1>
  <div class='sub'>Target: <code>{html.escape(target)}</code> · {verified_total} verified threat(s) · {raw_total} raw concern(s)</div>
  <div style='margin-top:8px'>
    <span class='badge crit'>{verified_total} findings</span>
    <span class='badge'>SARIF 2.1.0</span>
    <span class='badge'>CWE · OWASP 2021 · ATT&amp;CK</span>
  </div>
</header>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>CWE</th><th>OWASP</th><th>Message</th><th>Data-flow</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>"""


def _severity_summary(findings) -> dict:
    s = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s[f.severity] = s.get(f.severity, 0) + 1
    return s


def to_json(findings, target) -> str:
    out = {
        "tool": "SAST-VULN-SCANNER",
        "version": _VERSION,
        "target": target,
        "scan_date": datetime.datetime.now().isoformat(),
        "finding_count": len(findings),
        "severity_summary": _severity_summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(out, indent=2)


def to_markdown(findings, target) -> str:
    lines = ["# 🛡️ SAST Security Report", "",
             f"**Target:** `{target}`  ", f"**Findings:** {len(findings)}", ""]
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
        lines.append(f"### [{f.severity}] {f.rule}")
        lines.append(f"- **File:** `{f.file}:{f.line}`")
        lines.append(f"- **CWE:** {f.cwe}  ")
        if f.owasp:
            lines.append(f"- **OWASP:** {f.owasp}  ")
        lines.append(f"- **Message:** {f.message}")
        if f.dataflow:
            lines.append("- **Data-flow:** " + " → ".join(f.dataflow))
        lines.append("")
    return "\n".join(lines)
