<p align="center">
  <img src="https://img.shields.io/badge/SAST-AI%20Powered-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Languages-11%2B-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
</p>

<h1 align="center">🛡️ Next-Gen AI-Powered Universal SAST Agent</h1>
<p align="center"><b>Automated Code Security Audits</b> — privacy-first, AST-aware, taint-driven, fully open source.</p>

> **Black Hat Europe 2026 Arsenal** submission.

---

## 🔍 What it is

A **static application security testing (SAST)** engine that detects real,
high-severity vulnerabilities in source code with minimal false positives —
**entirely on localhost** (no cloud telemetry, no data exfiltration).

It bridges the gap between naive regex scanners (too many false positives) and
heavyweight commercial tools (cloud-dependent, expensive): it **parses code into
an AST**, traces **data flow from untrusted sources to dangerous sinks**, and
reports findings with exact file paths and line numbers.

---

## ✨ Key differentiators

| Capability | Naive regex SAST | This engine |
|:--|:--:|:--:|
| AST structural analysis | ❌ | ✅ |
| Taint-aware data-flow (source → sink) | ❌ | ✅ |
| Sanitizer awareness (suppress `sha256`, parameterized queries) | ❌ | ✅ |
| CWE + OWASP Top 10 + MITRE ATT&CK mapping | partial | ✅ |
| SARIF output (GitHub code scanning) | ❌ | ✅ |
| CI/CD exit codes + quiet mode | ❌ | ✅ |
| Optional local LLM re-verification (prompt-injection safe) | ❌ | ✅ |

---

## 🧩 Architecture

```
Raw Source Code
      │
      ▼
 Language Detection (11+ languages)
      │
      ▼
 AST Structural Analysis ──► Python (ast module)
      │
      ▼
 Taint Evaluation Engine (sources → sinks → sanitizers)
      │
      ▼
 Risk Grading (CRITICAL / HIGH / MEDIUM / LOW / INFO)
      │
      ▼
 Optional Local AI Re-verification (Ollama, prompt-injection safe)
      │
      ▼
 Reports → HTML (interactive) · JSON · SARIF 2.1.0
```

---

## 🛡️ Vulnerability coverage

| Severity | Category | CWE | OWASP 2021 | ATT&CK |
|:--|:--|:--|:--|:--|
| 🔴 Critical | OS Command Injection | CWE-78 | A03 Injection | T1059 |
| 🔴 Critical | Code Injection (eval/exec) | CWE-94 | A03 Injection | T1059 |
| 🔴 Critical | SQL Injection | CWE-89 | A03 Injection | T1190 |
| 🔴 Critical | Insecure Deserialization | CWE-502 | A08 | T1190 |
| 🟠 High | Insecure Cryptography | CWE-327 | A02 Crypto | T1600 |
| 🟠 High | Cross-Site Scripting | CWE-79 | A03 Injection | T1189 |
| 🟠 High | Path Traversal | CWE-22 | A01 Access Control | T1005 |
| 🟠 High | Hardcoded Credential | CWE-798 | A07 Auth | T1078 |
| 🟠 High | SSRF | CWE-918 | A10 SSRF | T1190 |
| 🟡 Medium | Insecure Randomness | CWE-330 | A02 Crypto | T1600 |

**Languages supported:** Python, JavaScript, TypeScript, PHP, Ruby, Java, Go,
C, C++, C#, Shell.

---

## 📦 Installation

```bash
git clone https://github.com/walimuhamad185/SAST-VULN-SCANNER.git
cd SAST-VULN-SCANNER
pip install -r requirements.txt    # core: zero mandatory deps (Python 3.8+)
```

- **Core engine** uses only the Python standard library.
- **Optional AI layer**: `pip install openai` + a running [Ollama](https://ollama.com)
  instance (fully local). Without it, the engine runs in deterministic mode.

---

## 🚀 Usage

```bash
# Scan a folder
python sast_agent.py scan ./src

# Generate all report formats (HTML + JSON + SARIF)
python sast_agent.py scan ./src --format all

# Deterministic mode (no AI)
python sast_agent.py scan app.py --no-ai

# Restrict to extensions
python sast_agent.py scan ./src --extensions .py .js

# CI/CD: quiet mode + severity gate (exit 1 only on HIGH or worse)
python sast_agent.py scan ./src --quiet --threshold HIGH
```

### CLI options

| Flag | Description |
|:--|:--|
| `--format html\|json\|sarif\|all` | Output format (default `html`) |
| `--output -o <path>` | Custom output path |
| `--no-ai` | Disable AI re-verification (deterministic) |
| `--extensions -e .py .js` | Restrict scan to extensions |
| `--threshold -t CRITICAL\|HIGH\|MEDIUM\|LOW` | Severity gate for exit code |
| `--quiet -q` | Suppress per-finding output (CI/CD) |

### Exit codes (CI/CD ready)

| Code | Meaning |
|:--|:--|
| `0` | Scan completed, no findings at/above threshold |
| `1` | Findings found at/above threshold |
| `2` | Usage / IO / fatal error |

---

## 🧪 Validation

The repo ships with intentionally-vulnerable targets under `tests/`:

```bash
python sast_agent.py scan ./tests --format all --no-ai
```

The engine detects **all** planted vulnerabilities (command injection, SQL
injection, MD5, XSS, pickle deserialization, hardcoded secrets, weak RNG, path
traversal — across Python and JavaScript) **and** correctly leaves safe code
(`sha256`, `secrets.token_hex`, parameterized queries) un-flagged.

---

## 🔧 CI/CD integration (GitHub Actions)

Add this to `.github/workflows/sast.yml`:

```yaml
name: SAST
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: python sast_agent.py scan . --quiet --threshold HIGH
```

The build fails (exit 1) when HIGH/CRITICAL findings are present.

---

## 🔒 Privacy-first design

- **100% local execution** — no cloud telemetry, no data exfiltration.
- **Optional local LLM** — Ollama runs on your machine; source never leaves.
- **Prompt-injection safe** — scanned code is sanitized, length-capped, and
  wrapped in an inert `<user_code>` block; model output is mapped to a strict
  enum so free-form text can never influence the verdict (CWE-94 safe by design).

---

## 🗺️ Roadmap

- [x] AST parsing (Python)
- [x] Taint-aware source → sink analysis
- [x] CWE + OWASP + ATT&CK mapping
- [x] SARIF 2.1.0 output
- [x] CI/CD exit codes + quiet mode
- [x] 11+ language detection
- [ ] Tree-sitter grammars for full JS/TS/Go AST precision
- [ ] Auto-fix suggestions (AI-generated patches)
- [ ] C/C++ data-flow via LLVM

---

## 👤 Author

**Wali Muhammad** — Infrastructure Security Automation / SAST

## 📄 License

MIT — open source
