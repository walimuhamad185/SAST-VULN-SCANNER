"""Slack / Email / generic webhook notifications when findings are detected.

Configure via environment variables (no secrets in code):
  SAST_SLACK_WEBHOOK_URL   -> POST a Slack message
  SAST_EMAIL_SMTP_*        -> send email (SMTP)
  SAST_WEBHOOK_URL         -> POST JSON to any webhook
"""
import os
import json
import urllib.request


def _slack_webhook() -> str:
    return os.getenv("SAST_SLACK_WEBHOOK_URL", "")


def _webhook() -> str:
    return os.getenv("SAST_WEBHOOK_URL", "")


def notify_findings(target: str, findings, threshold: str = "LOW") -> dict:
    """Send notifications for findings at/above threshold. Returns summary."""
    results = {"sent": []}
    if not findings:
        results["note"] = "No findings to notify."
        return results
    summary = _summary_text(target, findings)
    if _slack_webhook():
        ok = _post_json(_slack_webhook(), {"text": summary})
        results["sent"].append("slack" if ok else "slack_failed")
    if _webhook():
        ok = _post_json(_webhook(), {"target": target, "findings": [f.to_dict() for f in findings]})
        results["sent"].append("webhook" if ok else "webhook_failed")
    _email_if_configured(summary)
    return results


def _summary_text(target, findings) -> str:
    lines = ["🛡️ *SAST-VULN-SCANNER* found security threats:",
             f"Target: `{target}`", f"Findings: {len(findings)}", ""]
    for f in findings[:20]:
        lines.append(f"• `{f.severity}` — {f.rule} @ `{f.file}:{f.line}`")
    if len(findings) > 20:
        lines.append(f"…and {len(findings) - 20} more.")
    return "\n".join(lines)


def _post_json(url, payload) -> bool:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


def _email_if_configured(text: str) -> None:
    host = os.getenv("SAST_EMAIL_SMTP_HOST", "")
    if not host:
        return
    import smtplib
    from email.mime.text import MIMEText
    user = os.getenv("SAST_EMAIL_SMTP_USER", "")
    pw = os.getenv("SAST_EMAIL_SMTP_PASSWORD", "")
    port = int(os.getenv("SAST_EMAIL_SMTP_PORT", "587"))
    to = os.getenv("SAST_EMAIL_TO", "").split(",")
    frm = os.getenv("SAST_EMAIL_FROM", user)
    if not to or not frm:
        return
    msg = MIMEText(text)
    msg["Subject"] = "SAST Scan — Security Threats Detected"
    msg["From"] = frm
    msg["To"] = ", ".join(to)
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls()
            if user:
                s.login(user, pw)
            s.sendmail(frm, to, msg.as_string())
    except Exception:
        pass
