"""Command-line interface with clean argument parsing and CI/CD-ready exit codes."""
import os
import sys
import argparse

from .scanner import SASTScanner
from .ai_filter import OllamaVerify, verify_finding
from .config import SEVERITY_ORDER
from . import reporters
import sast_agent

# Exit codes (CI/CD friendly):
EXIT_OK = 0       # scan completed, no findings at/above threshold
EXIT_FINDINGS = 1 # scan completed, findings found at/above threshold
EXIT_ERROR = 2    # usage / IO / fatal error


def build_parser():
    p = argparse.ArgumentParser(
        prog="sast-agent",
        description="Next-Gen AI-Powered Universal SAST Agent — Automated Code Security Audits",
    )
    p.add_argument("target", help="File or folder path to scan")
    p.add_argument("--format", "-f", choices=["html", "json", "sarif", "all"],
                   default="html", help="Output report format (default: html)")
    p.add_argument("--output", "-o", default=None, help="Output file path (default: sast_security_report.<ext>)")
    p.add_argument("--no-ai", action="store_true", help="Disable AI re-verification")
    p.add_argument("--extensions", "-e", nargs="+", default=None,
                   help="Restrict scan to file extensions (e.g. .py .js)")
    p.add_argument("--threshold", "-t", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                   default="LOW", help="Only exit non-zero for findings at/above this severity (default: LOW)")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress per-finding output (CI/CD mode)")
    p.add_argument("--version", action="version", version=f"%(prog)s {sast_agent.__version__}")
    return p


def _meets_threshold(sev: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(sev, 9) <= SEVERITY_ORDER.get(threshold, 9)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    quiet = args.quiet

    if not quiet:
        print("=" * 62)
        print("   🛡️  NEXT-GEN AI-POWERED UNIVERSAL SAST AGENT  🛡️")
        print("=" * 62)

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print(f"[!] Error: Target does not exist: {target}")
        return EXIT_ERROR
    if not (os.path.isfile(target) or os.path.isdir(target)):
        print(f"[!] Error: Target is neither file nor directory: {target}")
        return EXIT_ERROR

    verifier = None if args.no_ai else OllamaVerify()
    if not quiet:
        if verifier and verifier.enabled:
            print("[+] Local AI re-verification layer active (Ollama).")
        else:
            print("[+] Running in deterministic mode (AI layer disabled/offline).")

    scanner = SASTScanner()
    raw_findings = scanner.scan(target, extensions=args.extensions)
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

    # Reports
    out_path = args.output
    fmt = args.format
    written = []
    if fmt in ("html", "all"):
        html_out = out_path or "sast_security_report.html"
        with open(html_out, "w", encoding="utf-8") as f:
            f.write(reporters.to_html(verified, target, raw_total, len(verified)))
        written.append(html_out)
    if fmt in ("json", "all"):
        json_out = out_path or "sast_security_report.json"
        with open(json_out, "w", encoding="utf-8") as f:
            f.write(reporters.to_json(verified, target))
        written.append(json_out)
    if fmt in ("sarif", "all"):
        sarif_out = out_path or "sast_security_report.sarif"
        with open(sarif_out, "w", encoding="utf-8") as f:
            f.write(reporters.to_sarif(verified, target))
        written.append(sarif_out)

    if not quiet:
        print("\n[ Scan Complete ]")
        print(f"[+] Triage: {raw_total} raw issues -> {len(verified)} verified actionable threats.")
        for w in written:
            print(f"[+] Report written: {w}")

    # Exit code: non-zero only if a finding meets the severity threshold
    actionable = [f for f in verified if _meets_threshold(f.severity, args.threshold)]
    return EXIT_FINDINGS if actionable else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
