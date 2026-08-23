"""
sast_agent/models.py
====================
Dataclasses representing scan findings and rule definitions.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List

MITRE_MAP = {
    "OS Command Injection": "CWE-78",
    "Code Injection (eval/exec)": "CWE-94",
    "SQL Injection": "CWE-89",
    "Insecure Cryptography": "CWE-327",
    "Cross-Site Scripting (XSS)": "CWE-79",
    "Path Traversal": "CWE-22",
    "Hardcoded Credential": "CWE-798",
    "Insecure Deserialization": "CWE-502",
    "Use of eval with user input": "CWE-95",
    "Server-Side Request Forgery": "CWE-918",
    "Insecure Randomness": "CWE-330",
}


@dataclass
class Finding:
    """A single vulnerability finding with full context metadata."""
    rule: str
    cwe: str
    severity: str
    file: str
    line: int
    column: int = 0
    code: str = ""
    language: str = "unknown"
    message: str = ""
    confidence: str = "HIGH"
    dataflow: List[str] = field(default_factory=list)
    cwe_url: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cwe_url"] = f"https://cwe.mitre.org/data/definitions/{self.cwe.split('-')[-1]}.html"
        return d


@dataclass
class Rule:
    """Description of a detection rule."""
    name: str
    cwe: str
    severity: str
    description: str
    remediation: str
    languages: List[str]
