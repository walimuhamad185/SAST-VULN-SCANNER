"""
sast_agent/scanner.py
=====================
Core scanning engine: walks a target, detects language, parses with AST where
possible, applies sink/sanitizer rules, and performs taint-aware verification
to reduce false positives.
"""
import os
import re
import ast
import fnmatch

from .config import (
    IGNORED_DIRS, MAX_FILE_SIZE, detect_language, is_text_file, SEVERITY_ORDER,
)
from .models import Finding
from .rules import RULES, SINKS, SANITIZERS
from . import taint as taintmod

_CONF_HIGH = "HIGH"
_CONF_MED = "MEDIUM"
_CONF_LOW = "LOW"


class SASTScanner:
    def __init__(self, ai_verifier=None):
        self.ai_verifier = ai_verifier
        self.findings: list = []

    def scan(self, target: str, extensions=None, exclude=None):
        target = os.path.abspath(target)
        if os.path.isfile(target):
            self._scan_file(target)
        elif os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                for fname in files:
                    fp = os.path.join(root, fname)
                    lang = detect_language(fp)
                    if lang == "unknown" or not is_text_file(fp):
                        continue
                    if extensions and not any(fname.endswith(e) for e in extensions):
                        continue
                    if exclude and any(fnmatch.fnmatch(fp, pat) for pat in exclude):
                        continue
                    self._scan_file(fp)
        return self.findings

    def _scan_file(self, path: str):
        lang = detect_language(path)
        if lang == "unknown":
            return
        try:
            if os.path.getsize(path) > MAX_FILE_SIZE:
                return
        except OSError:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read()
        except OSError:
            return

        lines = src.splitlines()
        tainted_vars = set()
        source_lines = set()

        for i, line in enumerate(lines, 1):
            s = line.strip()
            if not s:
                continue
            if taintmod.identify_sources(s, lang):
                source_lines.add(i)
                v = taintmod.assign_tainted_var(s)
                if v:
                    tainted_vars.add(v)

        if lang == "python":
            self._scan_python_ast(path, src, lines, tainted_vars, source_lines)
        elif lang in ("javascript", "typescript"):
            self._scan_js(path, lines, tainted_vars, source_lines, lang)
        else:
            self._scan_pattern(path, lines, tainted_vars, source_lines, lang)

    def _scan_python_ast(self, path, src, lines, tainted_vars, source_lines):
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            self._scan_pattern(path, lines, tainted_vars, source_lines, "python")
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in ("eval", "exec"):
                    self._add(path, node.lineno, node.col_offset,
                              "Code Injection (eval/exec)", "CWE-94", "CRITICAL",
                              lines[node.lineno - 1], "python",
                              f"Dynamic execution of untrusted code via {name}().", _CONF_HIGH)
                elif name in ("os.system", "os.popen", "subprocess.call", "subprocess.Popen",
                              "subprocess.run", "subprocess.check_output", "subprocess.check_call",
                              "subprocess.getoutput", "subprocess.getstatusoutput"):
                    self._add(path, node.lineno, node.col_offset,
                              "OS Command Injection", "CWE-78", "CRITICAL",
                              lines[node.lineno - 1], "python",
                              f"Shell command execution via {name}() — ensure no user input.", _CONF_HIGH)
                elif name in ("pickle.load", "pickle.loads", "yaml.load"):
                    self._add(path, node.lineno, node.col_offset,
                              "Insecure Deserialization", "CWE-502", "CRITICAL",
                              lines[node.lineno - 1], "python",
                              f"Deserializing untrusted data via {name}() is unsafe (use yaml.safe_load / JSON).", _CONF_HIGH)
                elif name in ("hashlib.md5", "hashlib.sha1"):
                    self._add(path, node.lineno, node.col_offset,
                              "Insecure Cryptography", "CWE-327", "HIGH",
                              lines[node.lineno - 1], "python",
                              f"Use of broken hash {name}() — use SHA-256 or bcrypt.", _CONF_HIGH)
                elif name in ("random.random", "random.randint", "random.randrange",
                              "random.choice", "random.uniform"):
                    self._add(path, node.lineno, node.col_offset,
                              "Insecure Randomness", "CWE-330", "MEDIUM",
                              lines[node.lineno - 1], "python",
                              "Non-cryptographic RNG — use the 'secrets' module for security.", _CONF_MED)
                elif name in ("requests.get", "requests.post", "httpx.get", "httpx.post"):
                    if _call_has_taint(node, tainted_vars):
                        self._add(path, node.lineno, node.col_offset,
                                  "Server-Side Request Forgery", "CWE-918", "HIGH",
                                  lines[node.lineno - 1], "python",
                                  "User-controlled URL passed to server-side HTTP client.", _CONF_MED)
                elif name == "open" and self._file_open_tainted(node, tainted_vars):
                    self._add(path, node.lineno, node.col_offset,
                              "Path Traversal", "CWE-22", "HIGH",
                              lines[node.lineno - 1], "python",
                              "File opened with a tainted (user-controlled) path.", _CONF_MED)

            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    for t in targets:
                        tname = _target_name(t)
                        if tname and _looks_secret(tname) and len(val) >= 4:
                            self._add(path, node.lineno, node.col_offset,
                                      "Hardcoded Credential", "CWE-798", "HIGH",
                                      lines[node.lineno - 1], "python",
                                      f"Hardcoded value for secret-like variable '{tname}'.", _CONF_HIGH)

            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in ("MD5.new", "SHA1.new", "SHA.new") or (
                        name.startswith(("Crypto.Hash.MD5", "Crypto.Hash.SHA1"))):
                    self._add(path, node.lineno, node.col_offset,
                              "Insecure Cryptography", "CWE-327", "HIGH",
                              lines[node.lineno - 1], "python",
                              "Broken cryptographic algorithm in use.", _CONF_HIGH)

    def _scan_js(self, path, lines, tainted_vars, source_lines, lang):
        self._scan_pattern(path, lines, tainted_vars, source_lines, lang)

    def _scan_pattern(self, path, lines, tainted_vars, source_lines, lang):
        sinks = SINKS.get(lang, [])
        sanitizers = SANITIZERS.get(lang, [])
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith(("#", "//", "/*", "*", "<!--")):
                continue
            for pat in sinks:
                m = _search(pat, s)
                if not m:
                    continue
                if any(_search(san, s) for san in sanitizers):
                    continue
                rule = self._attribute_rule(pat, lang)
                cwe = _cwe_for_rule(rule)
                sev = _severity_for_rule(rule)
                conf = _CONF_HIGH if (tainted_vars or source_lines) else _CONF_MED
                self._add(path, i, m.start(), rule, cwe, sev, line, lang,
                          _message_for(rule), conf)
                break

    def _add(self, path, line, col, rule, cwe, severity, code, lang, msg, conf):
        self.findings.append(Finding(
            rule=rule, cwe=cwe, severity=severity, file=path, line=line,
            column=col + 1, code=code.strip()[:300], language=lang,
            message=msg, confidence=conf,
        ))

    def _file_open_tainted(self, node, tainted_vars):
        if not tainted_vars:
            return False
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                return True
            if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                return True
        return False

    def _attribute_rule(self, pat, lang):
        p = pat.lower()
        if any(k in p for k in ("os.system", "os.popen", "subprocess", "exec(",
                                "system(", "popen(", "shell_exec", "passthru",
                                "runtime.getruntime", "processbuilder", "spawn(",
                                "execsync", "execlp", "execvp", "execv", "command")):
            return "OS Command Injection"
        if "eval" in p or "exec(" in p or "function(" in p:
            return "Code Injection (eval/exec)"
        if any(k in p for k in ("query", "execute(", "mysql", "mysqli", "select",
                                "where(", "statement", "sqlcommand")):
            return "SQL Injection"
        if any(k in p for k in ("md5", "sha1", "messagedigest", "des", "rc4",
                                "crypto.", "createmd5", "descryptoserviceprovider", "digest::")):
            return "Insecure Cryptography"
        if any(k in p for k in ("innerhtml", "document.write", "dangerouslyset",
                                "echo ", "print ", "response.write", "insertadjacenthtml", "xss")):
            return "Cross-Site Scripting (XSS)"
        if any(k in p for k in ("pickle", "unserialize", "marshal.load", "objectinputstream",
                                "readobject", "binaryformatter")):
            return "Insecure Deserialization"
        if any(k in p for k in ("password", "api_key", "api-key", "apikey", "secret",
                                "token", "private_key", "aws_secret")):
            return "Hardcoded Credential"
        if any(k in p for k in ("math.random", "random.", "randint", "mt_rand", "rand(",
                                "randombytes")):
            return "Insecure Randomness"
        if any(k in p for k in ("open(", "send_file", "readfile", "file(", "fopen",
                                "include", "require", "traversal", "../", "getparameter")):
            return "Path Traversal"
        if any(k in p for k in ("requests.", "http.get", "fetch(", "axios", "net/http",
                                "httpurlconnection", "curl")):
            return "Server-Side Request Forgery"
        return "OS Command Injection"


def _call_name(node):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    elif isinstance(func, ast.Call):
        return ""
    return ".".join(reversed(parts))


def _call_has_taint(node, tainted_vars):
    for arg in node.args:
        if isinstance(arg, ast.Name) and arg.id in tainted_vars:
            return True
        if isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            return True
    return False


def _target_name(t):
    if isinstance(t, ast.Name):
        return t.id
    if isinstance(t, ast.Attribute):
        return t.attr
    return None


def _looks_secret(name):
    n = name.lower()
    return any(k in n for k in ("password", "passwd", "secret", "api_key",
                                 "apikey", "api-key", "token", "private_key",
                                 "aws_secret", "access_key", "auth"))


def _search(pat, text):
    try:
        return re.search(pat, text, re.IGNORECASE)
    except re.error:
        return None


def _cwe_for_rule(rule):
    from .models import MITRE_MAP
    return MITRE_MAP.get(rule, "CWE-79")


def _severity_for_rule(rule):
    for r in RULES:
        if r.name == rule:
            return r.severity
    return "MEDIUM"


def _message_for(rule):
    for r in RULES:
        if r.name == rule:
            return r.remediation
    return "Review this finding for a potential vulnerability."
