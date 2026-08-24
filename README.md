<p align="center">
  <img src="https://img.shields.io/badge/SAST-AI%20Powered-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Languages-11%2B-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Release-v3.1.0-purple?style=for-the-badge" />
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

## ✨ Feature set (v3)

| # | Feature | What it does |
|:--|:--|:--|
| 1 | 🛠️ **Auto-Fix** | Generates a copy-pasteable remediation report per finding (`--autofix`) |
| 2 | 🧬 **17+ rule classes** | XXE, SSTI, LDAP, Open Redirect, JWT, Log Injection, YAML, SSRF & more |
| 3 | 🌲 **11+ languages** | Full tree-sitter AST for all 11 languages (Python ast + 10 tree-sitter grammars) |
| 4 | 🕸️ **Data-flow evidence** | Source → sink path recorded in JSON/Markdown/SARIF reports |
| 5 | 📦 **PyPI packaging** | `pip install sast-vuln-scanner` (`setup.py` + `pyproject.toml`) |
| 6 | 📝 **Markdown report** | Clean GitHub/CI-friendly `.md` output |
| 7 | 🧾 **Baseline scans** | Incremental: report only NEW findings (`--baseline` / `--save-baseline`) |
| 8 | ⚙️ **Config file** | `sast.yaml` / `sast.json` driven scans (`--config`) |
| 9 | 🐳 **Docker** | Containerized scanning with OCI labels |
| 10 | 🔗 **Pre-commit hook** | Run on every commit via `.pre-commit-hooks.yaml` |
| 11 | 📄 **PDF export** | Render the HTML report to PDF (`--pdf`) |
| 12 | 📢 **Notifications** | Slack / webhook / email alerts on findings (`--notify`) |

---

## 🧩 Architecture

```
Raw Source Code
      │
      ▼
 Language Detection (11+ languages)
      │
      ▼
 AST Structural Analysis ──► Python (ast) + 10 languages (tree-sitter)
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
 Reports → HTML · JSON · SARIF 2.1.0 · Markdown · PDF · Auto-Fix
```

---

## 🛡️ Vulnerability coverage (17+ classes)

| Severity | Category | CWE | OWASP 2021 | ATT&CK |
|:--|:--|:--|:--|:--|
| 🔴 Critical | OS Command Injection | CWE-78 | A03 | T1059 |
| 🔴 Critical | Code Injection (eval/exec) | CWE-94 | A03 | T1059 |
| 🔴 Critical | SQL Injection | CWE-89 | A03 | T1190 |
| 🔴 Critical | Insecure Deserialization | CWE-502 | A08 | T1190 |
| 🔴 Critical | Insecure YAML Deserialization | CWE-502 | A08 | T1190 |
| 🔴 Critical | Server-Side Template Injection | CWE-1336 | A03 | T1190 |
| 🟠 High | Insecure Cryptography | CWE-327 | A02 | T1600 |
| 🟠 High | Cross-Site Scripting | CWE-79 | A03 | T1189 |
| 🟠 High | Path Traversal | CWE-22 | A01 | T1005 |
| 🟠 High | Hardcoded Credential | CWE-798 | A07 | T1078 |
| 🟠 High | SSRF | CWE-918 | A10 | T1190 |
| 🟠 High | XML External Entity (XXE) | CWE-611 | A05 | T1190 |
| 🟠 High | LDAP Injection | CWE-90 | A03 | T1190 |
| 🟠 High | Insecure JWT | CWE-347 | A07 | T1078 |
| 🟡 Medium | Insecure Randomness | CWE-330 | A02 | T1600 |
| 🟡 Medium | Open Redirect | CWE-601 | A01 | T1189 |
| 🟡 Medium | Log Injection | CWE-117 | A09 | T1562 |

**Languages:** Python (full AST) + JavaScript, TypeScript, Go, PHP, Ruby, Java, C, C++, C#, Shell (all tree-sitter AST).

---

## 📦 Installation

```bash
git clone https://github.com/walimuhamad185/SAST-VULN-SCANNER.git
cd SAST-VULN-SCANNER

pip install .            # core (zero mandatory deps)
pip install .[ai]        # + Ollama AI layer
pip install .[pdf]       # + PDF export (weasyprint)
pip install .[all]       # everything
```

---

## 🚀 Usage

```bash
python sast_agent.py scan ./src                    # HTML report
python sast_agent.py scan ./src --format all       # HTML+JSON+SARIF+MD
python sast_agent.py scan ./src --autofix          # remediation report
python sast_agent.py scan ./src --save-baseline    # save baseline
python sast_agent.py scan ./src --baseline sast_baseline.json   # only NEW
python sast_agent.py --config sast.yaml            # config-driven
python sast_agent.py scan ./src --quiet --threshold HIGH --pdf --notify
```

### CLI flags

| Flag | Description |
|:--|:--|
| `--format html\|json\|sarif\|markdown\|all` | Output format |
| `--output -o <path>` | Custom output path |
| `--no-ai` | Disable AI re-verification |
| `--extensions -e .py .js` | Restrict extensions |
| `--threshold -t CRITICAL\|HIGH\|MEDIUM\|LOW` | Severity gate |
| `--quiet -q` | CI/CD quiet mode |
| `--config -c <path>` | Load sast.yaml/json |
| `--autofix` | Generate auto-fix report |
| `--baseline <path>` | Incremental scan |
| `--save-baseline` | Save findings as baseline |
| `--notify` | Slack/webhook/email alerts |
| `--pdf` | Export HTML to PDF |
| `--exclude <glob>` | Exclude paths |

### Exit codes

| Code | Meaning |
|:--|:--|
| `0` | No findings at/above threshold |
| `1` | Findings found at/above threshold |
| `2` | Usage / IO / fatal error |

---

## 🧪 Validation

```bash
python sast_agent.py scan ./tests --format all --no-ai
```

Detects **all** planted vulnerabilities and passes safe code (`sha256`,
`secrets.token_hex`, parameterized queries) with **zero false positives**.

---

## 🔧 CI/CD & Integrations

### GitHub Actions
```yaml
- uses: actions/checkout@v4
- run: pip install .
- run: sast-agent scan . --quiet --threshold HIGH --format sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: sast_security_report.sarif }
```

### Pre-commit
```yaml
repos:
  - repo: https://github.com/walimuhamad185/SAST-VULN-SCANNER
    rev: v3.1.0
    hooks:
      - id: sast-agent
```

### Docker
```bash
docker build -t sast-agent .
docker run --rm -v "$PWD:/app" sast-agent scan /app
```

### Notifications (env vars)
```bash
export SAST_SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export SAST_WEBHOOK_URL="https://your-api.example/hook"
export SAST_EMAIL_SMTP_HOST="smtp.gmail.com"
```

---

## 🔒 Privacy-first design

- **100% local execution** — no cloud telemetry, no data exfiltration.
- **Optional local LLM** — Ollama runs on your machine; source never leaves.
- **Prompt-injection safe** — scanned code is sanitized, length-capped, wrapped
  in an inert `<user_code>` block; model output mapped to a strict enum.

---

## 🗺️ Roadmap

- [x] AST parsing (Python), taint data-flow, 17+ rule classes
- [x] CWE + OWASP + ATT&CK mapping, SARIF 2.1.0
- [x] Auto-fix, baseline, config file, PDF, notifications, Docker
- [x] Native tree-sitter grammars for all 10 non-Python languages (full AST)
- [ ] Structured multi-file interprocedural data-flow

---

## 👤 Author

**Wali Muhammad** — Infrastructure Security Automation / SAST

## 📄 License

MIT — open source
