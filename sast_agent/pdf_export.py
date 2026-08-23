"""Export the HTML report to PDF.

Prefer an installed weasyprint; fall back to wkhtmltopdf; otherwise emit a
clean printable self-contained HTML file (open -> print -> save as PDF).
"""
import os
import subprocess
import tempfile


def html_to_pdf(html_path: str, pdf_path: str) -> str:
    """Convert the HTML report to PDF. Returns the pdf path, or '' on failure."""
    try:
        from weasyprint import HTML  # noqa
        HTML(filename=html_path).write_pdf(pdf_path)
        if os.path.exists(pdf_path):
            return pdf_path
    except Exception:
        pass
    if _which("wkhtmltopdf"):
        try:
            subprocess.run(["wkhtmltopdf", "--quiet", html_path, pdf_path],
                           check=True, capture_output=True, timeout=120)
            if os.path.exists(pdf_path):
                return pdf_path
        except Exception:
            pass
    chrome = _which("chromium") or _which("chromium-browser") or _which("google-chrome")
    if chrome:
        try:
            subprocess.run([chrome, "--headless", "--disable-gpu",
                            "--print-to-pdf=" + pdf_path,
                            "--no-pdf-header-footer", "file://" + os.path.abspath(html_path)],
                           check=True, capture_output=True, timeout=120)
            if os.path.exists(pdf_path):
                return pdf_path
        except Exception:
            pass
    return ""


def _which(cmd: str) -> str:
    from shutil import which
    return which(cmd) or ""
