"""Load a `sast.yaml` configuration file to customize scan behavior."""
import os
import re

DEFAULT_CONFIG = {
    "threshold": "LOW",
    "extensions": None,
    "exclude": [],
    "ignore_paths": [],
    "no_ai": False,
    "format": "all",
    "output": None,
}


def _try_import_yaml():
    try:
        import yaml  # noqa
        return yaml
    except Exception:
        return None


def load_config(path: str) -> dict:
    """Parse sast.yaml (or JSON) into a dict; return {} if absent/invalid."""
    cfg = dict(DEFAULT_CONFIG)
    if not path or not os.path.exists(path):
        return {}
    try:
        text = open(path, "r", encoding="utf-8").read()
    except OSError:
        return {}
    data = None
    if path.endswith((".yaml", ".yml")):
        yaml = _try_import_yaml()
        if yaml is None:
            return {}
        try:
            data = yaml.safe_load(text)
        except Exception:
            return {}
    elif path.endswith(".json"):
        import json
        try:
            data = json.loads(text)
        except Exception:
            return {}
    if not isinstance(data, dict):
        return {}
    def norm(k):
        k = re.sub(r"^sast\.", "", k)
        return k.replace("-", "_")
    allowed = set(cfg) | {"target", "ignore_dirs", "ignored_dirs", "ignore_paths",
                        "rules", "severity", "min_severity"}
    for k, v in data.items():
        nk = norm(k)
        if nk in allowed:
            cfg[nk] = v
    return cfg


def discover_config(target: str) -> str:
    """Look for sast.yaml/.json in the target dir or cwd."""
    candidates = []
    if os.path.isdir(target):
        candidates.append(os.path.join(target, "sast.yaml"))
        candidates.append(os.path.join(target, ".sast.yaml"))
    candidates.append("sast.yaml")
    candidates.append(".sast.yaml")
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""
