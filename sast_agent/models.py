"""Dataclasses representing scan findings and rule definitions."""
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
    "XML External Entity (XXE)": "CWE-611",
    "Server-Side Template Injection": "CWE-1336",
    "LDAP Injection": "CWE-90",
    "Open Redirect": "CWE-601",
    "Insecure JWT": "CWE-347",
    "Log Injection": "CWE-117",
    "Insecure YAML Deserialization": "CWE-502",
}

OWASP_2021_MAP = {
    "OS Command Injection": "A03:2021 Injection",
    "Code Injection (eval/exec)": "A03:2021 Injection",
    "SQL Injection": "A03:2021 Injection",
    "Insecure Deserialization": "A08:2021 Software and Data Integrity Failures",
    "Insecure Cryptography": "A02:2021 Cryptographic Failures",
    "Cross-Site Scripting (XSS)": "A03:2021 Injection",
    "Path Traversal": "A01:2021 Broken Access Control",
    "Hardcoded Credential": "A07:2021 Identification and Authentication Failures",
    "Server-Side Request Forgery": "A10:2021 SSRF",
    "Insecure Randomness": "A02:2021 Cryptographic Failures",
    "XML External Entity (XXE)": "A05:2021 Security Misconfiguration",
    "Server-Side Template Injection": "A03:2021 Injection",
    "LDAP Injection": "A03:2021 Injection",
    "Open Redirect": "A01:2021 Broken Access Control",
    "Insecure JWT": "A07:2021 Identification and Authentication Failures",
    "Log Injection": "A09:2021 Security Logging and Monitoring Failures",
    "Insecure YAML Deserialization": "A08:2021 Software and Data Integrity Failures",
}

ATTACK_MAP = {
    "OS Command Injection": "T1059 — Command and Scripting Interpreter",
    "Code Injection (eval/exec)": "T1059 — Command and Scripting Interpreter",
    "SQL Injection": "T1190 — Exploit Public-Facing Application",
    "Insecure Deserialization": "T1190 — Exploit Public-Facing Application",
    "Cross-Site Scripting (XSS)": "T1189 — Drive-by Compromise",
    "Hardcoded Credential": "T1078 — Valid Accounts",
    "Server-Side Request Forgery": "T1190 — Exploit Public-Facing Application",
    "Path Traversal": "T1005 — Data from Local System",
    "Insecure Cryptography": "T1600 — Weaken Encryption",
    "Insecure Randomness": "T1600 — Weaken Encryption",
    "XML External Entity (XXE)": "T1190 — Exploit Public-Facing Application",
    "Server-Side Template Injection": "T1190 — Exploit Public-Facing Application",
    "LDAP Injection": "T1190 — Exploit Public-Facing Application",
    "Open Redirect": "T1189 — Drive-by Compromise",
    "Insecure JWT": "T1078 — Valid Accounts",
    "Log Injection": "T1562 — Impair Defenses",
    "Insecure YAML Deserialization": "T1190 — Exploit Public-Facing Application",
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

    @property
    def owasp(self) -> str:
        return OWASP_2021_MAP.get(self.rule, "")

    @property
    def attack_technique(self) -> str:
        return ATTACK_MAP.get(self.rule, "")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cwe_url"] = f"https://cwe.mitre.org/data/definitions/{self.cwe.split('-')[-1]}.html"
        d["owasp"] = self.owasp
        d["attack_technique"] = self.attack_technique
        d["remediation"] = self.message
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
