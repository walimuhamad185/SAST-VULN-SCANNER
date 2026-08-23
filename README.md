# Next-Gen AI-Powered Universal SAST Agent 🛡️

[![Static Application Security Testing](https://img.shields.io/badge/SAST-AI%20Powered-red)](https://github.com/walimuhamad185/SAST-VULN-SCANNER)
[![Languages](https://img.shields.io/badge/languages-11+-blue)](https://github.com/walimuhamad185/SAST-VULN-SCANNER)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/walimuhamad185/SAST-VULN-SCANNER)

An advanced, open-source static application security testing (SAST) engine that
bridges the gap between naive regex-based scanners and heavyweight commercial
tools. It performs **AST-aware, context-sensitive data-flow analysis** across
multiple programming languages to detect real, high-severity vulnerabilities with
minimal false positives — entirely on localhost for strict data privacy.

> **Black Hat Europe 2026 Arsenal** submission.

---

## 🎯 Why this tool is different

Traditional regex SAST flags isolated strings and drowns developers in false
positives. This engine:

1. **Parses source into an AST** (Python) for column-accurate detection.
2. **Performs taint analysis** — a sink (e.g. `os.system`) is only a *real*
   finding when the data reaching it can be traced to an untrusted source
   (`request.args`, `$_GET`, `req.query`, `input()`, …).
3. **Applies sanitizer awareness** — parameterized queries, `sha256`, `secrets`,
   `htmlspecialchars`, etc. are recognized and suppressed.
4. **Optionally re-verifies** findings through a fully-local LLM (Ollama),
   treating scanned code as *untrusted data* (CWE-94 safe by design).

---

## 🧩 Architecture

```
Raw Source Code Assets
        │
        ▼
Tokenize & Detect Language  (11+ languages)
        │
        ▼
AST Structural Analysis  ──►  Python
        │
        ▼
Signature + Taint Evaluation Engine (sources → sinks → sanitizers)
        │
        ▼
Risk Grading (CRITICAL / HIGH / MEDIUM / LOW)
        │
        ▼
Optional Local AI Re-verification (Ollama)
        │
        ▼
Reports → HTML (interactive) · JSON · SARIF 2.1.0
```

---

## 🛡️ Vulnerability coverage matrix

| Severity | Category | CWE |
|:--|:--|:--|
| **Critical** | OS Command Injection | CWE-78 |
| **Critical** | Code Injection | CWE-94 |
| **Critical** | SQL Injection | CWE-89 |
| **Critical** | Insecure Deserialization | CWE-502 |
| **High** | Insecure Cryptography | CWE-327 |
| **High** | XSS | CWE-79 |
| **High** | Path Traversal | CWE-22 |
| **High** | Hardcoded Credential | CWE-798 |
| **High** | SSRF | CWE-918 |
| **Medium** | Insecure Randomness | CWE-330 |

---

## 📦 Installation

```bash
git clone https://github.com/walimuhamad185/SAST-VULN-SCANNER.git
cd SAST-VULN-SCANNER
pip install -r requirements.txt           # core: no external deps
pip install openai                         # OPTIONAL: only for AI re-verification
```

The core engine has **zero mandatory dependencies** (Python 3.8+ standard
library only). The `openai` package is needed *only* for the optional local LLM
re-verification via Ollama.

---

## 🚀 Usage

```bash
python sast_agent.py scan ./my-project                 # scan a folder
python sast_agent.py scan ./my-project --format all    # HTML + JSON + SARIF
python sast_agent.py scan app.py --no-ai --format json # deterministic mode
```

Reports generated:
- **`sast_security_report.html`** — dark-themed interactive triage dashboard
- **`sast_security_report.json`** — machine-readable findings
- **`sast_security_report.sarif`** — SARIF 2.1.0 (GitHub code scanning, GitLab, Azure DevOps)

---

## 🧪 Validation

```bash
python sast_agent.py scan ./tests --format all --no-ai
```

The engine detects all planted vulnerabilities **and** leaves safe code
(`sha256`, `secrets.token_hex`, parameterized queries) un-flagged —
demonstrating low false-positive behavior.

---

## 🔒 Privacy-first design

- **100% local execution** — no cloud telemetry, no data exfiltration.
- **Optional local LLM** — Ollama runs on your machine; source never leaves.
- **Prompt-injection safe** — scanned code is sanitized, length-capped, and
  wrapped in an inert `<user_code>` block; model output is mapped to a strict
  enum so free-form text can never influence the verdict.

---

## 🗺️ Roadmap

- [x] AST parsing (Python)
- [x] Taint-aware source→sink analysis
- [x] SARIF 2.1.0 output
- [x] 11+ language detection
- [ ] Tree-sitter grammars for full JS/TS/Go AST precision
- [ ] GitHub Actions CI/CD integration
- [ ] Auto-fix suggestions

---

**Author:** Wali Muhammad  
**Classification:** Infrastructure Security Automation / SAST  
**License:** MIT (open source)
