"""Output generators: interactive HTML dashboard, JSON, and SARIF (2.1.0)."""
import html
import json
import datetime
from .config import SEVERITY_ORDER


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
                "defaultConfiguration": {"level": _severity_to_sarif(f.severity)},
            })
        results.append({
            "ruleId": rid.replace(" ", ""),
            "level": _severity_to_sarif(f.severity),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line, "startColumn": max(f.column, 1)},
                }
            }],
            "properties": {"cwe": f.cwe, "confidence": f.confidence},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SAST-VULN-SCANNER", "rules": rules,
                                 "informationUri": "https://github.com/walimuhamad185/SAST-VULN-SCANNER"}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


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
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{sev_color.get(f.severity,'#6b7280')}">{html.escape(f.severity)}</span>
              <br><strong>{html.escape(f.rule)}</strong>
              <br><span class="cwe">{html.escape(f.cwe)}</span></td>
          <td><code>{html.escape(f.file)}</code><br>
              <span class="muted">Line {f.line}, col {f.column}</span>
              <pre><code>{code}</code></pre></td>
          <td><div class="analysis">{html.escape(f.message)}</div>
              <div class="conf">Confidence: {html.escape(f.confidence)} · Lang: {html.escape(f.language)}</div></td>
        </tr>""")

    body_rows = "\n".join(rows) if rows else (
        '<tr><td colspan="3" style="text-align:center;padding:40px;color:#16a34a">'
        '✅ No verified security threats found! Code meets strict compliance standards.</td></tr>'
    )
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI-Powered SAST Security Report</title>
<style>
  body {{ font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:#0b1220; color:#e2e8f0; margin:0; }}
  .container {{ max-width:1280px; margin:auto; padding:30px; }}
  h1 {{ color:#f1f5f9; border-bottom:2px solid #1e293b; padding-bottom:15px; margin-top:0; }}
  .stats {{ display:flex; gap:20px; margin:20px 0; flex-wrap:wrap; }}
  .card {{ flex:1; padding:20px; border-radius:10px; color:#fff; font-weight:bold; text-align:center; min-width:160px; }}
  .total {{ background:#334155; }} .threats {{ background:#dc2626; }} .raw {{ background:#2563eb; font-weight:normal; font-size:14px; text-align:left; }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; background:#0f172a; border-radius:10px; overflow:hidden; }}
  th, td {{ padding:14px; text-align:left; border-bottom:1px solid #1e293b; vertical-align:top; }}
  th {{ background:#1e293b; color:#94a3b8; }}
  tr:hover {{ background:#1e293b; }}
  .badge {{ padding:4px 10px; border-radius:4px; font-size:11px; font-weight:bold; text-transform:uppercase; color:#fff; display:inline-block; }}
  .cwe {{ color:#64748b; font-size:12px; }} .muted {{ color:#64748b; font-size:12px; }}
  .analysis {{ font-size:13px; line-height:1.5; color:#cbd5e1; }}
  .conf {{ font-size:11px; color:#64748b; margin-top:8px; }}
  pre {{ background:#0b1120; color:#7dd3fc; padding:10px; border-radius:6px; overflow-x:auto; font-family:'Courier New',monospace; font-size:12px; margin-top:8px; }}
  code {{ word-break:break-all; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ Next-Gen AI-Powered SAST Security Report</h1>
  <div class="stats">
    <div class="card total">Potential Concerns Found<br><span style="font-size:28px">{raw_total}</span></div>
    <div class="card threats">Verified Actionable Threats<br><span style="font-size:28px">{verified_total}</span></div>
    <div class="card raw"><strong>Target:</strong> {html.escape(target)}<br>
      <strong>Scan Date:</strong> {now}</div>
  </div>
  <table>
    <thead><tr>
      <th style="width:22%">Vulnerability</th>
      <th style="width:40%">File &amp; Location</th>
      <th style="width:38%">AI Security Analysis &amp; Remediation</th>
    </tr></thead>
    <tbody>{body_rows}</tbody>
  </table>
</div>
</body>
</html>"""


def to_json(findings, target) -> str:
    out = {
        "tool": "SAST-VULN-SCANNER",
        "version": "2.0.0",
        "target": target,
        "scan_date": datetime.datetime.now().isoformat(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(out, indent=2)
