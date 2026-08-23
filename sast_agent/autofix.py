"""Auto-fix / remediation patch generation.

For each verified finding, produce a concrete, copy-pasteable remediation with
context. Optionally uses the local LLM (Ollama) to tailor a patch; otherwise it
falls back to a curated snippet from rules.REMEDIATION_SNIPPETS.
"""
from .rules import REMEDIATION_SNIPPETS


def build_remediation(finding, ai_verifier=None) -> dict:
    """Return a {rule, cwe, severity, location, remediation, patch} dict."""
    snippet = REMEDIATION_SNIPPETS.get(
        finding.rule,
        "Review this finding and apply a manual fix.",
    )
    patch = ""
    if ai_verifier is not None and getattr(ai_verifier, "enabled", False):
        patch = _ai_patch(ai_verifier, finding)
    return {
        "rule": finding.rule,
        "cwe": finding.cwe,
        "severity": finding.severity,
        "file": finding.file,
        "line": finding.line,
        "remediation": snippet,
        "ai_patch": patch or None,
    }


def _ai_patch(verifier, finding) -> str:
    language = finding.language
    prompt = (
        "You are a security fix bot. Produce ONLY a short diff-style code fix, "
        "no explanation, for the following finding.\n"
        f"Language: {language}\n"
        f"Vulnerability: {finding.rule}\n"
        "Vulnerable line(s):\n"
        f"<code>\n{finding.code}\n</code>\n\n"
        "Return the corrected code as a single fenced code block."
    )
    try:
        resp = verifier.ask(prompt)
    except Exception:
        resp = ""
    if not resp:
        return ""
    import re
    m = re.search(r"```(?:\w+)?\s*\n(.*?)```", resp, re.DOTALL)
    if m:
        return m.group(1).strip()
    return resp.strip()


def generate_patch_report(findings, ai_verifier=None) -> str:
    """Return a Markdown remediation document for all findings."""
    lines = ["# 🔧 Auto-Fix Recommendations", "",
             f"Generated for {len(findings)} verified finding(s).", ""]
    for f in findings:
        r = build_remediation(f, ai_verifier)
        lines.append(f"## {r['severity']} — {r['rule']} ({r['cwe']})")
        lines.append(f"- **Location:** `{r['file']}:{r['line']}`")
        lines.append(f"- **Remediation:** {r['remediation']}")
        if r.get("ai_patch"):
            lines.append("")
            lines.append("**Suggested patch:**")
            lines.append("```" + f.language)
            lines.append(r["ai_patch"])
            lines.append("```")
        lines.append("")
    return "\n".join(lines)
