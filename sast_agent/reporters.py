"""Output generators: interactive HTML dashboard, JSON, SARIF (2.1.0), Markdown."""
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
            "tool": {"driver": {"name": "SAST-VULN-SCANNER", "version": "3.0.0",
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
        owasp = html.escape(f.owasp) if f.owasp else "—"
        attack = html.escape(f.attack_technique) if f.attack_technique else "—"
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{sev_color.get(f.severity,'#6b7280')}">{html.escape(f.severity)}</span>
              <br><strong>{html.escape(f.rule)}</strong>
              <div class="tax"><span class="chip cwe">{html.escape(f.cwe)}</span>
              <span class="chip owasp">{owasp}</span></div></td>
          <td><code>{html.escape(f.file)}</code><br>
              <span class="muted">Line {f.line}, col {f.column} · {html.escape(f.language)}</span>
              <pre><code>{code}</code></pre></td>
          <td><div class="analysis">{html.escape(f.message)}</div>
              <div class="conf">Confidence: {html.escape(f.confidence)}</div>
              <div class="attack">MITRE ATT&amp;CK: {attack}</div></td>
        </tr>""")
    body_rows = "\n".join(rows) if rows else (
        '<tr><td colspan="3" style="text-align:center;padding:40px;color:#16a34a">'
        '✅ No verified security threats found! Code meets strict compliance standards.</td></tr>'
    )
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI-Powered SAST Security Report</title>
<style>
  body {{ font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:#0b1220; color:#e2e8f0; margin:0; }}
  .container {{ max-width:1320px; margin:auto; padding:30px; }}
  h1 {{ color:#f1f5f9; border-bottom:2px solid #1e293b; padding-bottom:15px; margin-top:0; }}
  .stats {{ display:flex; gap:20px; margin:20px 0; flex-wrap:wrap; }}
  .card {{ flex:1; padding:20px; border-radius:10px; color:#fff; font-weight:bold; text-align:center; min-width:150px; }}
  .total {{ background:#334155; }} .threats {{ background:#dc2626; }}
  .crit {{ background:#7f1d1d; }} .high {{ background:#9a3412; }} .med {{ background:#92400e; }}
  .raw {{ background:#1e3a8a; font-weight:normal; font-size:13px; text-align:left; }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; background:#0f172a; border-radius:10px; overflow:hidden; }}
  th, td {{ padding:14px; text-align:left; border-bottom:1px solid #1e293b; vertical-align:top; }}
  th {{ background:#1e293b; color:#94a3b8; }}
  tr:hover {{ background:#1e293b; }}
  .badge {{ padding:4px 10px; border-radius:4px; font-size:11px; font-weight:bold; text-transform:uppercase; color:#fff; display:inline-block; }}
  .tax {{ margin-top:8px; }}
  .chip {{ display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px; margin:2px 2px 0 0; }}
  .cwe {{ background:#1e293b; color:#7dd3fc; }} .owasp {{ background:#312e81; color:#c7d2fe; }}
  .muted {{ color:#64748b; font-size:12px; }}
  .analysis {{ font-size:13px; line-height:1.5; color:#cbd5e1; }}
  .conf {{ font-size:11px; color:#64748b; margin-top:10px; }}
  .attack {{ font-size:11px; color:#93c5fd; margin-top:4px; }}
  pre {{ background:#0b1120; color:#7dd3fc; padding:10px; border-radius:6px; overflow-x:auto; font-family:'Courier New',monospace; font-size:12px; margin-top:8px; }}
  code {{ word-break:break-all; }}
  .legend {{ color:#64748b; font-size:12px; margin-top:12px; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ Next-Gen AI-Powered SAST Security Report</h1>
  <div class="stats">
    <div class="card total">Potential Concerns Found<br><span style="font-size:28px">{raw_total}</span></div>
    <div class="card threats">Verified Actionable Threats<br><span style="font-size:28px">{verified_total}</span></div>
    <div class="card crit">Critical<br><span style="font-size:28px">{sev_counts.get('CRITICAL', 0)}</span></div>
    <div class="card high">High<br><span style="font-size:28px">{sev_counts.get('HIGH', 0)}</span></div>
    <div class="card med">Medium<br><span style="font-size:28px">{sev_counts.get('MEDIUM', 0)}</span></div>
    <div class="card raw"><strong>Target:</strong> {html.escape(target)}<br><strong>Scan Date:</strong> {now}</div>
  </div>
  <table>
    <thead><tr>
      <th style="width:22%">Vulnerability</th>
      <th style="width:40%">File &amp; Location</th>
      <th style="width:38%">AI Security Analysis &amp; Remediation</th>
    </tr></thead>
    <tbody>{body_rows}</tbody>
  </table>
  <p class="legend">CWE + OWASP Top 10 (2021) + MITRE ATT&amp;CK mapping provided for every finding.</p>
</div>
</body>
</html>"""


def to_json(findings, target) -> str:
    out = {
        "tool": "SAST-VULN-SCANNER",
        "version": "3.0.0",
        "target": target,
        "scan_date": datetime.datetime.now().isoformat(),
        "finding_count": len(findings),
        "severity_summary": _severity_summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(out, indent=2)


def _severity_summary(findings) -> dict:
    s = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s[f.severity] = s.get(f.severity, 0) + 1
    return s


def to_markdown(findings, target) -> str:
    """Render a clean Markdown report (GitHub/CI friendly)."""
    import datetime
    lines = ["# 🛡️ SAST Security Report", "",
             f"- **Target:** `{target}`",
             f"- **Scan date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             f"- **Findings:** {len(findings)}", ""]
    if not findings:
        lines.append("✅ No verified security threats found.")
        return "\n".join(lines)
    summary = _severity_summary(findings)
    lines.append("## Severity Summary")
    lines.append("| Severity | Count |")
    lines.append("|:--|--:|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {summary.get(sev, 0)} |")
    lines.append("")
    lines.append("## Findings")
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
        lines.append(f"### {f.severity} — {f.rule} ({f.cwe})")
        owasp = f.owasp or "—"
        attack = f.attack_technique or "—"
        lines.append(f"- **Location:** `{f.file}:{f.line}` (col {f.column}) · language `{f.language}`")
        lines.append(f"- **OWASP:** {owasp} · **MITRE ATT&CK:** {attack} · **Confidence:** {f.confidence}")
        if f.dataflow:
            lines.append("- **Dataflow:**")
            for d in f.dataflow:
                lines.append(f"  - `{d}`")
        lines.append("")
        lines.append("```" + f.language)
        lines.append(f.code)
        lines.append("```")
        lines.append(f"- **Remediation:** {f.message}")
        lines.append("")
    return "\n".join(lines)
