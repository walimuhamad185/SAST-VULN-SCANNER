"""Baseline / incremental scan support.

Store a SHA-less fingerprint of previously-seen findings and diff against it so
only NEW findings are reported on subsequent scans.
"""
import os
import json
import hashlib


def _fingerprint(f) -> str:
    key = f"{f.file}:{f.line}:{f.rule}"
    return hashlib.sha256(key.encode()).hexdigest()


def load_baseline(path: str):
    """Return a set of fingerprints from a baseline JSON file."""
    if not path or not os.path.exists(path):
        return set()
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return set()
    return set(data.get("fingerprints", []))


def save_baseline(path: str, findings) -> None:
    """Write current findings as a baseline JSON file."""
    fps = [_fingerprint(f) for f in findings]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"fingerprints": fps, "count": len(fps)}, fh, indent=2)


def filter_new(findings, baseline_path: str):
    """Return only findings whose fingerprint is NOT in the baseline."""
    existing = load_baseline(baseline_path)
    new = [f for f in findings if _fingerprint(f) not in existing]
    return new
