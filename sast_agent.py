#!/usr/bin/env python3
"""
SAST-VULN-SCANNER — main entry point.

Usage:
    python sast_agent.py scan <file_or_folder> [--format html|json|sarif|all]

Examples:
    python sast_agent.py scan ./src --format all
    python sast_agent.py scan app.py --no-ai --format json
"""
import sys

from sast_agent.cli import main


def dispatch():
    args = sys.argv[1:]
    if args and args[0] == "scan":
        args = args[1:]
    return main(args)


if __name__ == "__main__":
    sys.exit(dispatch())
