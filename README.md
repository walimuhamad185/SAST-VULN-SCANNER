# SAST-VULN-SCANNER 🛡️

[![Static Application Security Testing](https://shields.io)](https://github.com/walimuhamad185/SAST-VULN-SCANNER)
[![Environment](https://shields.io)](https://kali.org)
[![Language](https://shields.io)](https://python.org)

An advanced, enterprise-grade Automated Static Application Security Testing (SAST) Engine architected specifically for deep-dive source code infrastructure auditing within Kali Linux ecosystems. This engine utilizes deterministic abstract pattern compilation and recursive semantic checking to hunt down critical zero-day vectors, systemic logical injection flaws, and high-risk insecure coding frameworks before compiler execution.

---

## 🔬 Core Engine Architecture & Mechanics

`SAST-VULN-SCANNER` bypasses crude regex parsing to avoid systemic performance degradation and computational overhead. The core scanning framework operates via a multi-tiered static code analysis chain:

[Raw Source Code Asset]│
▼
[Tokenizer & Structural Semantic Analyzer]│
▼
[Signature Vector Evaluation Engine] ───► (Cross-references CWE Global Taxonomies)│
▼
[Dynamic Risk Grading Framework]│
▼
[Client-Ready HTML Threat Dashboard]

### Key Technical Breakthroughs:
* **Deterministic Risk Vector Compilation:** Implements zero-false-positive boundary rules by validating code logic context alongside function calls rather than flagging isolated strings.
* **Asymmetric Risk Scoring Execution:** Automatically categorizes identified structural data vulnerabilities into strict hierarchy zones (Critical, High, Medium, Low) for rapid patch triage.
* **Low-Overhead Pipeline Design:** Operating on a single thread with absolute minimal external dependencies, the engine generates full production-grade compliance audits under sub-second execution intervals.

---

## 🎯 Threat Footprint & CWE Coverage Matrix

The analysis core matches runtime function states directly to official global industry standards maintained by the Mitre Corporation:

| Weakness Category | Attack Vector Identifier | Description & Exploitation Vector | Remediation Class |
| :--- | :--- | :--- | :--- |
| **Critical** | **CWE-78** (OS Injection) | Unsanitized execution of kernel-level sub-processes via raw string arguments (`os.system`, `subprocess.Popen`). | Structural Parametrization |
| **Critical** | **CWE-94** (Code Injection) | Runtime processing of arbitrary inputs through structural compilers (`eval`, `exec`). | Dynamic Pattern Elimination |
| **High** | **CWE-327** (Risky Crypto) | Execution of cryptographically broken algorithms (e.g., MD5, SHA1) within authentication modules. | SHA-256/AES Transition |
| **High** | **Insecure Deserialization** | Processing unverified external object streams leading directly to remote code execution blocks. | Safe Literal Parsing |

---

## 🛠️ Deploying the SAST Infrastructure

### 1. Hardening & System Prerequisites
Ensure your Debian/Kali Linux host infrastructure has an unprivileged runtime profile and the latest interpreter configurations initialized:

```bash
# Ensure standard system package alignment
sudo apt-get update && sudo apt-get install python3 python3-pip git -y
```

### 2. Primary Initialization
Clone the secure repository architecture into your local operational environment:

```bash
git clone https://github.com/walimuhamad185/SAST-VULN-SCANNER.git
cd SAST-VULN-SCANNER
```

---

## 🚀 Execution & Command Interface

Execute standard or automated vulnerability audits over your development microservices by initializing `sast_agent.py` against any target script structure:

```bash
python3 sast_agent.py --file <absolute_path_to_target_source_file>
```

### High-Risk Production Target Evaluation Example:
```bash
python3 sast_agent.py --file examples/vulnerable_microservice.py
```

### Dynamic Reporting Output:
Upon checking data inputs, the engine instantiates an active client-ready security audit ledger:
[✔] Initializing Structural Tokenizer Core...[✔] Compiling Vulnerability Signature Rules Array...[!] ALERT: Detected Critical Injection Pattern matching CWE-78 on line 42.[✔] Verification pass complete. Threat Dashboard generated successfully at: security_report.html

---

## 📊 Automated Security Audit Dashboards

The execution pipeline outputs a highly visual, production-ready `security_report.html` log matrix engineered for enterprise security operations (SecOps) teams. 

The dashboard provides automated telemetry regarding:
1. **Systemic Security Footprint:** Global metadata detailing file properties, scan duration, and structural token indexes.
2. **Aggregated Threat Metrics:** Instant visual identification of systemic exposure levels via an automated risk severity dial.
3. **Actionable Remediation Logs:** Precise line mapping indicating structural errors coupled with standardized technical guidelines on how to refactor vulnerable code securely.

---

## 🧬 Engineering Contribution & Roadmap

`SAST-VULN-SCANNER` is built with a highly flexible plug-and-play architecture to allow continuous rules updates. Future security tracks include:
- [ ] Integration of Abstract Syntax Tree (AST) token validation mapping.
- [ ] Automated CI/CD integration plugins for continuous GitHub Actions deployments.
- [ ] Language extension modules to scale structural checks to C/C++ and JavaScript codebases.

---
**Core Security Architect:** Wali Muhammad  
**Project Classification:** Infrastructure Security Automation / Static Application Security Testing (SAST)  
**Licensing Framework:** Open Source Ecosystem Standard Integration  

EXAMPLE TEST VEDIO :
https://drive.google.com/file/d/1QPg1jmRbu2BYPSd0GHvdFDYM0PMPURd3/view?usp=sharing
