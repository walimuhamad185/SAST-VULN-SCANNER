"""Command-line interface with CI/CD exit codes and all feature flags."""
import os
import sys
import argparse

from .scanner import SASTScanner
from .ai_filter import OllamaVerify, verify_finding
from .config import SEVERITY_ORDER
from . import reporters, autofix, baseline, notify, pdf_export, config_loader
import sast_agent

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser():
    p = argparse.ArgumentParser(
        prog="sast-agent",
        description="Next-Gen AI-Powered Universal SAST Agent — Automated Code Security Audits (v3)",
    )
    p.add_argument("target", nargs="?", help="File or folder path to scan")
    p.add_argument("--format", "-f", choices=["html", "json", "sarif", "markdown", "md", "all"],
                   default="html", help="Output format (default: html; 'all' = html+json+sarif+md)")
    p.add_argument("--output", "-o", default=None, help="Output file path")
    p.add_argument("--no-ai", action="store_true", help="Disable AI re-verification")
    p.add_argument("--extensions", "-e", nargs="+", default=None, help="Restrict to extensions (.py .js)")
    p.add_argument("--threshold", "-t", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                   default="LOW", help="Severity gate for exit code (default LOW)")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress per-finding output")
    p.add_argument("--version", action="version", version=f"%(prog)s {sast_agent.__version__}")

    p.add_argument("--config", "-c", default=None, help="Path to sast.yaml / sast.json config")
    p.add_argument("--autofix", action="store_true", help="Generate auto-fix remediation report")
    p.add_argument("--baseline", default=None, help="Baseline JSON path (report only new findings)")
    p.add_argument("--save-baseline", action="store_true", help="After scan, save current findings as baseline")
    p.add_argument("--notify", action="store_true", help="Send notifications (Slack/webhook/email)")
    p.add_argument("--pdf", action="store_true", help="Also export the HTML report to PDF")
    p.add_argument("--exclude", nargs="+", default=None, help="Glob patterns to exclude")
    return p


def _meets_threshold(sev: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(sev, 9) <= SEVERITY_ORDER.get(threshold, 9)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = {}
    cfg_path = args.config or ""
    if cfg_path:
        cfg = config_loader.load_config(cfg_path)
    elif not args.target:
        cfg_path = config_loader.discover_config(os.getcwd())
        if cfg_path:
            cfg = config_loader.load_config(cfg_path)

    target = args.target or cfg.get("target")
    if not target:
        print("[!] Error: a target path is required (or set 'target' in sast.yaml).")
        return EXIT_ERROR

    fmt = args.format or cfg.get("format", "html")
    threshold = (args.threshold if args.threshold != "LOW" else cfg.get("threshold", "LOW"))
    extensions = args.extensions or cfg.get("extensions")
    exclude = args.exclude or cfg.get("exclude") or cfg.get("ignore_paths")
    no_ai = args.no_ai or cfg.get("no_ai", False)
    quiet = args.quiet

    if not quiet:
        print("=" * 62)
        print("   🛡️  NEXT-GEN AI-POWERED UNIVERSAL SAST AGENT  🛡️")
        print("   " + ("(v" + sast_agent.__version__ + ")").center(58))
        print("=" * 62)

    target = os.path.abspath(target)
    if not os.path.exists(target):
        print(f"[!] Error: Target does not exist: {target}")
        return EXIT_ERROR

    verifier = None if no_ai else OllamaVerify()
    if not quiet:
        print("[+] Local AI re-verification layer active (Ollama)." if (verifier and verifier.enabled)
              else "[+] Running in deterministic mode (AI layer disabled/offline).")

    scanner = SASTScanner()
    raw_findings = scanner.scan(target, extensions=extensions, exclude=exclude)
    raw_total = len(raw_findings)
    if not quiet:
        print(f"\n[+] Universal engine flagged {raw_total} raw concern(s).")

    verified = []
    if raw_total > 0:
        for idx, f in enumerate(raw_findings, 1):
            verdict, analysis = verify_finding(verifier, f.rule, f.code)
            if verdict == "REAL VULNERABILITY":
                f.analysis = analysis
                verified.append(f)
                if not quiet:
                    print(f"  \033[91m[{idx}/{raw_total}] VERIFIED THREAT\033[0m — {f.rule} @ {f.file}:{f.line}")
            elif verdict == "INCONCLUSIVE":
                f.analysis = "INCONCLUSIVE: manual review required."
                verified.append(f)
                if not quiet:
                    print(f"  \033[93m[{idx}/{raw_total}] INCONCLUSIVE\033[0m — {f.rule} @ {f.file}:{f.line}")
            else:
                if not quiet:
                    print(f"  \033[92m[{idx}/{raw_total}] FILTERED (false alarm)\033[0m — {f.rule}")

    if args.baseline or args.save_baseline:
        bpath = args.baseline or cfg.get("baseline") or "sast_baseline.json"
        if args.baseline:
            verified = baseline.filter_new(verified, args.baseline)
            if not quiet:
                print(f"[+] Baseline filter applied — {len(verified)} new finding(s).")
        if args.save_baseline:
            baseline.save_baseline(bpath, verified)
            if not quiet:
                print(f"[+] Baseline saved to {bpath}")

    out_path = args.output or cfg.get("output")
    written = []

    def _html_out():
        return out_path.replace(".html", "") + ".html" if out_path else "sast_security_report.html"

    if fmt in ("html", "all"):
        html_out = _html_out()
        with open(html_out, "w", encoding="utf-8") as fh:
            fh.write(reporters.to_html(verified, target, raw_total, len(verified)))
        written.append(html_out)
    if fmt in ("json", "all"):
        json_out = _tail(out_path, ".json", "sast_security_report.json")
        with open(json_out, "w", encoding="utf-8") as fh:
            fh.write(reporters.to_json(verified, target))
        written.append(json_out)
    if fmt in ("sarif", "all"):
        sarif_out = _tail(out_path, ".sarif", "sast_security_report.sarif")
        with open(sarif_out, "w", encoding="utf-8") as fh:
            fh.write(reporters.to_sarif(verified, target))
        written.append(sarif_out)
    if fmt in ("markdown", "md", "all"):
        md_out = _tail(out_path, ".md", "sast_security_report.md")
        with open(md_out, "w", encoding="utf-8") as fh:
            fh.write(reporters.to_markdown(verified, target))
        written.append(md_out)

    if args.autofix:
        fix_out = out_path.replace(".html", "").replace(".json", "").replace(".sarif", "").replace(".md", "") + "_fixes.md" if out_path else "sast_autofix_report.md"
        with open(fix_out, "w", encoding="utf-8") as fh:
            fh.write(autofix.generate_patch_report(verified, verifier))
        written.append(fix_out)

    if args.pdf and fmt in ("html", "all"):
        pdf_path = _tail(out_path, ".pdf", "sast_security_report.pdf")
        res = pdf_export.html_to_pdf(html_out, pdf_path)
        if res:
            written.append(res)
        else:
            print("[!] PDF export needs weasyprint / wkhtmltopdf / chromium installed.")

    if not quiet:
        print("\n[ Scan Complete ]")
        print(f"[+] Triage: {raw_total} raw issues -> {len(verified)} verified actionable threats.")
        for w in written:
            print(f"[+] Report written: {w}")

    if args.notify:
        res = notify.notify_findings(target, verified, threshold)
        if not quiet:
            sent = res.get("sent", [])
            print(f"[+] Notifications: {', '.join(sent) if sent else 'none configured'}")

    actionable = [f for f in verified if _meets_threshold(f.severity, threshold)]
    return EXIT_FINDINGS if actionable else EXIT_OK


def _tail(out_path, ext, default):
    if not out_path:
        return default
    if out_path.endswith(ext):
        return out_path
    base, _ = os.path.splitext(out_path)
    return base + ext


if __name__ == "__main__":
    sys.exit(main())
