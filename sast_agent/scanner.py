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
from .taint import SOURCES as _SOURCES

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
                    if exclude and any(
                            fnmatch.fnmatch(fp, pat) or fnmatch.fnmatch(os.path.basename(fp), pat)
                            for pat in exclude):
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
            tainted_vars = _compute_python_taint(src, tainted_vars)
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
                if name in ("cursor.execute", "cursor.executemany", "execute", "executemany",
                            "connection.execute", "db.execute", "session.execute", "raw"):
                    for arg in node.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod) and \
                                _expr_is_tainted(arg.right, tainted_vars):
                            self._add(path, node.lineno, node.col_offset,
                                      "SQL Injection", "CWE-89", "CRITICAL",
                                      lines[node.lineno - 1], "python",
                                      "SQL built by %-interpolation of user input.",
                                      _CONF_HIGH, tainted=True, source_lines=source_lines)
                        if isinstance(arg, (ast.JoinedStr, ast.FormattedValue)) and \
                                _expr_is_tainted(arg, tainted_vars):
                            self._add(path, node.lineno, node.col_offset,
                                      "SQL Injection", "CWE-89", "CRITICAL",
                                      lines[node.lineno - 1], "python",
                                      "SQL built by f-string interpolation of user input.",
                                      _CONF_HIGH, tainted=True, source_lines=source_lines)

            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and \
                    hasattr(node.left, "value") and isinstance(node.left.value, str) and \
                    _expr_is_tainted(node.right, tainted_vars) and \
                    any(k in node.left.value.lower() for k in
                        ("select", "insert", "update", "delete", "from ")):
                self._add(path, node.lineno, node.col_offset,
                          "SQL Injection", "CWE-89", "CRITICAL",
                          lines[node.lineno - 1], "python",
                          "SQL string built via %-interpolation of user input.",
                          _CONF_HIGH, tainted=True, source_lines=source_lines)

            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in ("eval", "exec"):
                    is_t = _call_has_taint(node, tainted_vars)
                    self._add(path, node.lineno, node.col_offset,
                              "Code Injection (eval/exec)", "CWE-94",
                              "CRITICAL" if is_t else "HIGH",
                              lines[node.lineno - 1], "python",
                              f"Dynamic execution via {name}() — {'tainted input' if is_t else 'review input source'}.",
                              _CONF_HIGH if is_t else _CONF_MED,
                              tainted=is_t, source_lines=source_lines)
                elif name in ("os.system", "os.popen", "subprocess.call", "subprocess.Popen",
                              "subprocess.run", "subprocess.check_output", "subprocess.check_call",
                              "subprocess.getoutput", "subprocess.getstatusoutput"):
                    # list-form (shell=False) is a sanitizer for command injection:
                    # subprocess.call(["echo", user]) passes args without a shell, so it
                    # is only dangerous if a tainted STRING is concatenated into the list,
                    # or the whole command is a tainted string (shell=True usage).
                    if len(node.args) and isinstance(node.args[0], (ast.List, ast.Tuple)):
                        # list-form: only flag if a list ELEMENT itself is a tainted
                        # string/expression (not just a tainted var name reference).
                        dangerous = _list_has_tainted_string(node.args[0], tainted_vars)
                        if dangerous:
                            self._add(path, node.lineno, node.col_offset,
                                      "OS Command Injection", "CWE-78", "CRITICAL",
                                      lines[node.lineno - 1], "python",
                                      f"List-form shell command via {name}() mixes a tainted string argument with shell metacharacters.",
                                      _CONF_HIGH, tainted=True, source_lines=source_lines)
                        # else: safe (argument vector, no shell) -> no finding
                    else:
                        is_t = _call_has_taint(node, tainted_vars)
                        if is_t:
                            self._add(path, node.lineno, node.col_offset,
                                      "OS Command Injection", "CWE-78", "CRITICAL",
                                      lines[node.lineno - 1], "python",
                                      f"Shell command execution via {name}() with tainted input.",
                                      _CONF_HIGH, tainted=True, source_lines=source_lines)
                elif name in ("pickle.load", "pickle.loads"):
                    is_t = _call_has_taint(node, tainted_vars)
                    self._add(path, node.lineno, node.col_offset,
                              "Insecure Deserialization", "CWE-502",
                              "CRITICAL" if is_t else "HIGH",
                              lines[node.lineno - 1], "python",
                              f"Deserialization via {name}() — safe only on trusted/validated data.",
                              _CONF_HIGH if is_t else _CONF_MED,
                              tainted=is_t, source_lines=source_lines)
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
                elif name in ("requests.get", "requests.post", "requests.request",
                              "httpx.get", "httpx.post", "urllib.request.urlopen"):
                    is_t = _call_has_taint(node, tainted_vars)
                    self._add(path, node.lineno, node.col_offset,
                              "Server-Side Request Forgery", "CWE-918", "HIGH",
                              lines[node.lineno - 1], "python",
                              "Server-side HTTP request to a potentially user-controlled URL (SSRF).",
                              _CONF_HIGH if is_t else _CONF_MED,
                              tainted=is_t, source_lines=source_lines)
                elif name == "open" and self._file_open_tainted(node, tainted_vars):
                    self._add(path, node.lineno, node.col_offset,
                              "Path Traversal", "CWE-22", "HIGH",
                              lines[node.lineno - 1], "python",
                              "File opened with a tainted (user-controlled) path.", _CONF_MED)

            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in ("yaml.load",):
                    self._add(path, node.lineno, node.col_offset,
                              "Insecure YAML Deserialization", "CWE-502", "CRITICAL",
                              lines[node.lineno - 1], "python",
                              "Unsafe yaml.load() with untrusted input — use yaml.safe_load().", _CONF_HIGH)
                if any(k in name for k in ("etree.parse", "etree.fromstring", "minidom.parse",
                                           "lxml.etree.parse", "lxml.etree.fromstring", "sax.parse")):
                    self._add(path, node.lineno, node.col_offset,
                              "XML External Entity (XXE)", "CWE-611", "HIGH",
                              lines[node.lineno - 1], "python",
                              "XML parsed without disabling external entities (XXE).", _CONF_MED)
                if name in ("render_template_string", "render_template") or "jinja2" in name or name.endswith(("from_string", "from_string_")):
                    is_t = _call_has_taint(node, tainted_vars)
                    self._add(path, node.lineno, node.col_offset,
                              "Server-Side Template Injection", "CWE-1336", "CRITICAL",
                              lines[node.lineno - 1], "python",
                              "Server-side template rendered from input (SSTI) — use sandboxed engine / pass data, not template.",
                              _CONF_HIGH if is_t else _CONF_MED,
                              tainted=is_t, source_lines=source_lines)
                if "ldap" in name or name.endswith(("search_s", "search_ext")):
                    self._add(path, node.lineno, node.col_offset,
                              "LDAP Injection", "CWE-90", "HIGH",
                              lines[node.lineno - 1], "python",
                              "Unsanitized input flows into an LDAP query.", _CONF_MED)
                if name in ("jwt.encode", "jwt.decode"):
                    self._add(path, node.lineno, node.col_offset,
                              "Insecure JWT", "CWE-347", "HIGH",
                              lines[node.lineno - 1], "python",
                              "JWT handling may use weak algorithm / disabled verification.", _CONF_MED)
                if name.startswith(("logging.", "logger.")) and _call_has_taint(node, tainted_vars):
                    self._add(path, node.lineno, node.col_offset,
                              "Log Injection", "CWE-117", "MEDIUM",
                              lines[node.lineno - 1], "python",
                              "Unsanitized user input written to logs.", _CONF_LOW)

            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in ("redirect", "url_for", "HttpResponseRedirect", "HttpResponsePermanentRedirect"):
                    is_t = _call_has_taint(node, tainted_vars)
                    if name != "url_for" or is_t:
                        self._add(path, node.lineno, node.col_offset,
                                  "Open Redirect", "CWE-601", "MEDIUM",
                                  lines[node.lineno - 1], "python",
                                  "Redirect target derived from user input without validation.",
                                  _CONF_MED if is_t else _CONF_LOW,
                                  tainted=is_t, source_lines=source_lines)

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
                if name in ("MD5.new", "SHA1.new") or name.startswith(("Crypto.Hash.MD5", "Crypto.Hash.SHA1")):
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
                is_tainted = bool(tainted_vars or source_lines)
                conf = _CONF_HIGH if is_tainted else _CONF_MED
                self._add(path, i, m.start(), rule, cwe, sev, line, lang,
                          _message_for(rule), conf,
                          tainted=is_tainted, source_lines=source_lines)
                break

    def _add(self, path, line, col, rule, cwe, severity, code, lang, msg, conf,
             tainted=False, source_lines=None):
        dataflow = []
        if tainted and source_lines:
            for sl in sorted(source_lines):
                dataflow.append(f"{path}:{sl} -> {path}:{line} (sink)")
        self.findings.append(Finding(
            rule=rule, cwe=cwe, severity=severity, file=path, line=line,
            column=col + 1, code=code.strip()[:300], language=lang,
            message=msg, confidence=conf, dataflow=dataflow,
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
                                "execsync", "execlp", "execvp", "execv", "command",
                                "child_process")):
            return "OS Command Injection"
        if "eval" in p or "exec(" in p or "function(" in p:
            return "Code Injection (eval/exec)"
        # XSS BEFORE SQL: res.send(...), document.write, innerHTML etc. and the
        # tainted vars they reference (req.query/query. inside an XSS sink must
        # not be mis-attributed as SQL).
        if any(k in p for k in ("innerhtml", "document.write", "dangerouslyset",
                                "insertadjacenthtml", "xss", "res.send", "res.write",
                                "res.end", "response.write", "echo ", "print ",
                                "\\.(send|write|end)", "res\\.")):
            return "Cross-Site Scripting (XSS)"
        if any(k in p for k in ("query", "execute(", "mysql", "mysqli", "select",
                                "where(", "statement", "sqlcommand")):
            return "SQL Injection"
        if any(k in p for k in ("md5", "sha1", "messagedigest", "des", "rc4",
                                "crypto.", "createmd5", "descryptoserviceprovider", "digest::")):
            return "Insecure Cryptography"
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
        if any(k in p for k in ("etree.parse", "fromstring", "minidom", "sax", "xml.",
                                "xmldocument", "xmlreader", "domdocument", "loadxml",
                                "simplexml", "documentbuilder", "saxparser", "xmldecoder",
                                "xml.unmarshal", "inputsource", "xdocument.parse")):
            return "XML External Entity (XXE)"
        if any(k in p for k in ("jinja2", "render_template_string", "from_string",
                                "ejs.render", "template(", "erb.new", ".result(",
                                ".render(", "template.inject")):
            return "Server-Side Template Injection"
        if any(k in p for k in ("ldap.", "ldap3", "ldapsearch", "search_s",
                                "dircontext", "initialdircontext", "directorysearcher",
                                "searchrequest", "ldap.dial", "ldap_search")):
            return "LDAP Injection"
        if any(k in p for k in ("redirect", "sendredirect", "http.redirect",
                                "location.href", "window.location", "redirectto",
                                "redirectpermanent")):
            return "Open Redirect"
        if any(k in p for k in ("jwt.", "signingmethod", "jsonwebtoken", "jwtsecuritytoken",
                                "alg", "signwith", "jwt.encode", "jwt.sign")):
            return "Insecure JWT"
        if any(k in p for k in ("logging.", "logger.", "log.info", "log.error", "log.warn",
                                "syslog", "error_log", "rails.logger", "console.log",
                                "console.error", "log.println")):
            return "Log Injection"
        return "OS Command Injection"


# Functions whose return value is tainted because they return a tainted-returning
# function's result, or their params (which are tainted) flow to the return.
def _funcs_that_return_taint(tree, tainted):
    """Return a set of local function names that RETURN a tainted expression.

    Interprocedural: a function is 'taint-returning' if any Return statement
    returns a tainted name, a source expression, or a call to another
    taint-returning function (computed as a fixed point).
    """
    funcs = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node

    returns_taint = set()
    changed = True
    while changed:
        changed = False
        for fname, fnode in funcs.items():
            if fname in returns_taint:
                continue
            for r in ast.walk(fnode):
                if isinstance(r, ast.Return) and r.value is not None:
                    if _expr_is_tainted(r.value, tainted | returns_taint):
                        returns_taint.add(fname)
                        changed = True
    return returns_taint


def _compute_python_taint(src: str, seed: set) -> set:
    """Propagate taint transitively across the AST via fixed-point analysis.

    Unlike the naive approach, this does NOT blanket-mark every function
    parameter as tainted. Instead, taint flows only from real sources and
    is broken by sanitizer calls (strip/escape/etc.)."""
    tainted = set(seed or [])
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return tainted

    taint_returns = _funcs_that_return_taint(tree, tainted)

    # Conservative entry-point handling: a function parameter is treated as a
    # potential taint source ONLY for functions that contain a dangerous sink in
    # their body. This is the standard SAST heuristic for web handlers /
    # entry-points where the parameter is externally controlled.
    _SINK_NAMES = ("os.system", "os.popen", "subprocess.", "eval", "exec",
                   "pickle.", "yaml.load", "cursor.execute", ".execute(",
                   "render_template_string", "redirect", "open(", "requests.",
                   "httpx.", "jinja2.", "child_process", "require(")
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for fname, fnode in funcs.items():
        body_src = ast.unparse(fnode)
        if any(k in body_src for k in _SINK_NAMES):
            for a in fnode.args.args:
                if a.arg not in ("self", "cls"):
                    tainted.add(a.arg)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value_tainted = _expr_is_tainted(node.value, tainted | taint_returns)
                if value_tainted:
                    for t in node.targets:
                        for name in _target_names(t):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
                # independent of value_tainted: re-scan return set since taint changed
                new_returns = _funcs_that_return_taint(tree, tainted)
                if new_returns - taint_returns:
                    taint_returns |= new_returns
                    changed = True
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if _expr_is_tainted(node.value, tainted | taint_returns):
                    for name in _target_names(node.target):
                        if name not in tainted:
                            tainted.add(name)
                            changed = True
            elif isinstance(node, ast.AugAssign):
                names = _target_names(node.target)
                if _expr_is_tainted(node.value, tainted | taint_returns) or any(n in tainted for n in names):
                    for name in names:
                        if name not in tainted:
                            tainted.add(name)
                            changed = True
    return tainted | taint_returns


def _target_names(t):
    out = []
    if isinstance(t, ast.Name):
        out.append(t.id)
    elif isinstance(t, (ast.Tuple, ast.List)):
        for el in t.elts:
            out.extend(_target_names(el))
    return out


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
    tainted = set(tainted_vars or [])
    for arg in node.args:
        if _expr_is_tainted(arg, tainted):
            return True
    for kw in node.keywords:
        if _expr_is_tainted(kw.value, tainted):
            return True
    return False


_SANITIZER_SUFFIXES = ("strip", "lstrip", "rstrip", "escape", "escaped", "trim",
                       "safe", "clean", "sanitize", "quote", "urlencode",
                       "html_escape", "escape_html", "encodeURIComponent")


def _is_source_call(node):
    """True if the call is a known taint SOURCE (input(), os.environ, request.*,
    sys.argv, getenv, readFile, etc.). These introduce taint regardless of args."""
    name = _call_name(node)
    if not name:
        return False
    leaf = name.split(".")[-1]
    # direct source functions
    if leaf in ("input", "raw_input", "getenv", "environ", "argv", "recv",
                "readline", "get_data", "FieldStorage", "getParameter", "getHeader"):
        return True
    if name in ("os.environ", "sys.argv", "os.getenv", "os.popen"):
        return True
    if "request." in name or ".query" in name or ".form" in name or ".args" in name:
        return True
    if "readFile" in name or "readFileSync" in name:
        return True
    return False


def _is_sanitizer_call(node):
    """True if the call is a known sanitizer that removes taint (e.g. .strip(),
    html.escape()). Hashing/encoding that is security-sensitive is excluded
    (md5/sha1/hexdigest are NOT sanitizers for sinks)."""
    name = _call_name(node)
    if not name:
        return False
    leaf = name.split(".")[-1]
    if leaf in _SANITIZER_SUFFIXES:
        return True
    if name in ("markupsafe.escape", "html.escape", "htmlspecialchars", "htmlentities",
                "cgi.escape", "bleach.clean", "urlquote", "urllib.parse.quote"):
        return True
    return False


def _expr_is_tainted(expr, tainted):
    if isinstance(expr, ast.Name):
        return expr.id in tainted
    if isinstance(expr, ast.Constant):
        # a literal string is never tainted on its own
        return False
    if isinstance(expr, ast.Call):
        # sanitizer calls break taint
        if _is_sanitizer_call(expr):
            return False
        # source calls introduce taint (input(), os.environ, request.*, etc.)
        if _is_source_call(expr):
            return True
        # any other call propagates taint from its args (interprocedural)
        return any(_expr_is_tainted(a, tainted) for a in expr.args) or \
               any(_expr_is_tainted(kw.value, tainted) for kw in expr.keywords)
    if isinstance(expr, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
        return True
    if isinstance(expr, ast.Attribute):
        # .strip().foo etc: attribute access on a sanitized call is safe
        return _expr_is_tainted(expr.value, tainted)
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return any(_expr_is_tainted(e, tainted) for e in expr.elts)
    if isinstance(expr, ast.Dict):
        for k, v in zip(expr.keys, expr.values):
            if _expr_is_tainted(k, tainted) or _expr_is_tainted(v, tainted):
                return True
    if isinstance(expr, ast.IfExp):
        return _expr_is_tainted(expr.body, tainted) or _expr_is_tainted(expr.orelse, tainted)
    return False


def _list_has_tainted_string(lst, tainted):
    """For list-form shell args: only dangerous if a list ELEMENT is a tainted
    string-build (BinOp/JoinedStr) or a tainted Name that flows into the command
    string with shell metacharacters. A sanitized element (.strip etc.) is safe."""
    for el in lst.elts:
        if isinstance(el, ast.Name) and el.id in tainted:
            return True
        if isinstance(el, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            return True
        if isinstance(el, ast.Call) and not _is_sanitizer_call(el):
            return any(_expr_is_tainted(a, tainted) for a in el.args)
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
