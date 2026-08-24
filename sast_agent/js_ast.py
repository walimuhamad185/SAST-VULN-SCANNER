"""
sast_agent/js_ast.py
====================
Precise tree-sitter AST analysis for JavaScript and TypeScript.

JS/TS are the most security-relevant web languages, so they get a dedicated
engine with real syntax-tree walking: sources are matched on member/call nodes,
taint flows through variable assignments, sanitizers break the flow, and sinks
are matched on actual call expressions — eliminating false positives while
catching multi-line / template-literal patterns the regex engine misses.

tree-sitter is an OPTIONAL dependency; without it this engine reports itself
unavailable and the scanner falls back to the regex engine (no crash).
"""

import re

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript
    import tree_sitter_typescript
    TREE_SITTER_OK = True
except Exception:
    TREE_SITTER_OK = False


def _node_text(node, src_bytes):
    return src_bytes[node.start_byte:node.end_byte].decode("utf-8", "ignore")


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def _is_source_member(member, src_bytes):
    text = _node_text(member, src_bytes).lower()
    if text.startswith(("req.", "request.", "req[", "request[")):
        return True
    if any(k in text for k in ("window.location", "location.hash", "location.search",
                                "document.url", "document.referrer", "document.cookie",
                                "process.argv", "process.env")):
        return True
    return False


def _is_source_call(call, src_bytes):
    text = _node_text(call, src_bytes).lower()
    return any(k in text for k in ("readfilesync", "readfile", "getelementbyid", "queryselector", "formdata"))


# ---------------------------------------------------------------------------
# Sink matching (callee name based)
# ---------------------------------------------------------------------------

def _function_name(call, src_bytes):
    fn = call.child_by_field_name("function")
    if fn is None:
        text = _node_text(call, src_bytes)
        m = re.match(r"\s*([^\n(]+)", text)
        return m.group(1).strip() if m else ""
    return _node_text(fn, src_bytes).strip()


def _first_string_arg(call, src_bytes):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for a in args.children:
        if a.type == "string":
            return _node_text(a, src_bytes).strip("\"'`")
        if a.type not in ("(", ")"):
            return None
    return None


def _is_list_form(call, src_bytes):
    args = call.child_by_field_name("arguments")
    if args is None:
        return False
    for a in args.children:
        if a.type in ("(", ")", ",", "comment"):
            continue
        return a.type == "array"
    return False


def _is_parameterized(call, src_bytes):
    args = call.child_by_field_name("arguments")
    if args is None:
        return False
    count = 0
    for a in args.children:
        if a.type in ("(", ")", ",", "comment"):
            continue
        count += 1
        if count >= 2 and a.type == "array":
            return True
    return False


def _sink_for_call(call, src_bytes):
    name = _function_name(call, src_bytes)
    if not name:
        return None
    lower = name.lower()
    leaf = name.split(".")[-1].lower()

    # Command injection
    if leaf in ("exec", "execsync", "spawn", "spawnsync", "fork"):
        if _is_list_form(call, src_bytes):
            return None
        return ("OS Command Injection", "CWE-78", "CRITICAL",
                "Shell command execution; concatenating user input is command injection.")

    # Code injection
    if name.lower() == "eval" or "function" in name.lower():
        return ("Code Injection (eval/exec)", "CWE-94", "CRITICAL",
                "Dynamic code execution (eval/Function) from input.")

    # XSS
    if leaf in ("send", "write", "end", "sendfile") and name.lower().startswith(("res.", "response.", "ctx.")):
        return ("Cross-Site Scripting (XSS)", "CWE-79", "HIGH",
                "Response body built from user input (reflected XSS).")
    if leaf == "write" and name.lower().startswith("document."):
        return ("Cross-Site Scripting (XSS)", "CWE-79", "HIGH",
                "document.write of user input (DOM XSS).")
    if name.lower().endswith(".innerhtml") or leaf == "dangerouslysetinnerhtml":
        return ("Cross-Site Scripting (XSS)", "CWE-79", "HIGH",
                "HTML injection via innerHTML / dangerouslySetInnerHTML.")

    # SQL injection
    if leaf in ("query", "execute", "raw", "executemany"):
        if any(k in lower for k in ("db.", "pool.", "connection.", "conn.", "client.",
                                    "knex", "sequelize", "sql", "database", "cursor.")):
            if _is_parameterized(call, src_bytes):
                return None
            return ("SQL Injection", "CWE-89", "CRITICAL",
                    "SQL string built by concatenation/interpolation of user input.")

    # Insecure cryptography (leaf createHash with weak alg)
    if lower.endswith("createhash"):
        alg = _first_string_arg(call, src_bytes)
        if alg and alg.lower() in ("md5", "sha1"):
            return ("Insecure Cryptography", "CWE-327", "HIGH",
                    f"Use of broken cryptographic hash {alg.upper()}.")

    # Insecure randomness
    if name.lower() == "math.random":
        return ("Insecure Randomness", "CWE-330", "MEDIUM",
                "Non-cryptographic RNG (Math.random) for security-sensitive values.")

    # SSRF
    if "axios" in lower and leaf in ("get", "post", "request", "put", "delete"):
        return ("Server-Side Request Forgery", "CWE-918", "HIGH",
                "SSRF via Axios to a user-controlled URL.")

    # Open redirect
    if leaf == "redirect" and name.lower().startswith(("res.", "response.", "ctx.")):
        return ("Open Redirect", "CWE-601", "MEDIUM",
                "Redirect target derived from user input without validation.")

    # JWT
    if "jwt" in lower and leaf in ("sign", "verify", "decode"):
        return ("Insecure JWT", "CWE-347", "HIGH",
                "JWT handling may use a weak algorithm / disabled verification.")

    # Log injection
    if leaf in ("log", "error", "warn", "warning", "info", "debug") and name.lower().startswith(("console.", "logger.")):
        return ("Log Injection", "CWE-117", "MEDIUM",
                "Unsanitized user input written to logs.")

    return None


_SANITIZER_LEAVES = {"escape", "escapehtml", "encodeuri", "encodeuricomponent",
                     "sanitize", "clean", "trim", "stringify"}


def _is_sanitizing_call(call, src_bytes):
    name = _function_name(call, src_bytes)
    leaf = name.split(".")[-1].lower()
    if leaf in _SANITIZER_LEAVES:
        return True
    lower = name.lower()
    return "dompurify" in lower or "sanitizehtml" in lower or "escapehtml" in lower


# ---------------------------------------------------------------------------
# Taint
# ---------------------------------------------------------------------------

def _destructure_names(node, src_bytes):
    if node.type == "identifier":
        return [_node_text(node, src_bytes)]
    names = []
    for c in node.children:
        if c.type in ("identifier", "shorthand_property_identifier"):
            names.append(_node_text(c, src_bytes))
        elif c.type in ("object_pattern", "array_pattern", "rest_pattern", "assignment_pattern"):
            names.extend(_destructure_names(c, src_bytes))
    return names


def _expr_is_tainted(node, src_bytes, tainted, depth=0):
    if node is None or depth > 40:
        return False
    t = node.type
    if t == "identifier":
        return _node_text(node, src_bytes) in tainted
    if t == "member_expression":
        if _is_source_member(node, src_bytes):
            return True
        return _expr_is_tainted(node.child_by_field_name("object"), src_bytes, tainted, depth + 1)
    if t == "subscript_expression":
        return _expr_is_tainted(node.child_by_field_name("object"), src_bytes, tainted, depth + 1)
    if t == "call_expression":
        if _is_sanitizing_call(node, src_bytes):
            return False
        if _is_source_call(node, src_bytes):
            return True
        args = node.child_by_field_name("arguments")
        if args is not None:
            for a in args.children:
                if a.type in ("(", ")", ",", "comment"):
                    continue
                if _expr_is_tainted(a, src_bytes, tainted, depth + 1):
                    return True
        return False
    if t in ("binary_expression", "template_string", "template_substitution", "parenthesized_expression", "unary_expression"):
        for c in node.children:
            if _expr_is_tainted(c, src_bytes, tainted, depth + 1):
                return True
        return False
    if t == "await_expression":
        return _expr_is_tainted(node.child_by_field_name("argument"), src_bytes, tainted, depth + 1)
    if t in ("array", "object", "pair"):
        for c in node.children:
            if _expr_is_tainted(c, src_bytes, tainted, depth + 1):
                return True
        return False
    return False


class JSTSScanner:
    def __init__(self, lang_kind):
        self.lang_kind = lang_kind
        self._lang = None
        if TREE_SITTER_OK:
            try:
                if lang_kind == "typescript":
                    fn = getattr(tree_sitter_typescript, "language", None)
                    self._lang = Language(fn()) if callable(fn) else Language(tree_sitter_typescript.language_typescript())
                else:
                    self._lang = Language(tree_sitter_javascript.language())
            except Exception:
                self._lang = None
        self._parser = Parser(self._lang) if self._lang is not None else None

    @property
    def available(self):
        return self._parser is not None

    def scan(self, src):
        if not self.available:
            return []
        src_bytes = src.encode("utf-8")
        tree = self._parser.parse(src_bytes)
        root = tree.root_node
        tainted = self._propagate(root, src_bytes)
        findings = []
        seen = set()
        lm = _LineMap(src)
        for node in _iter(root):
            if node.type != "call_expression":
                continue
            sink = _sink_for_call(node, src_bytes)
            if sink is None:
                continue
            rule, cwe, sev, msg = sink
            t = self._call_tainted(node, src_bytes, tainted)
            if rule == "Cross-Site Scripting (XSS)" and not t:
                continue
            line = lm.line(node.start_byte)
            col = lm.col(node.start_byte)
            key = (rule, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"rule": rule, "cwe": cwe, "severity": sev,
                             "line": line, "col": col, "message": msg, "tainted": t})
        return findings

    def _call_tainted(self, call, src_bytes, tainted):
        args = call.child_by_field_name("arguments")
        if args is not None:
            for a in args.children:
                if a.type in ("(", ")", ",", "comment"):
                    continue
                if _expr_is_tainted(a, src_bytes, tainted):
                    return True
        return False

    def _propagate(self, root, src_bytes):
        bindings = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "variable_declarator":
                name_node = value_node = None
                for c in node.children:
                    if c.type in ("identifier", "object_pattern", "array_pattern"):
                        name_node = c
                    elif c.type not in ("=", "comment"):
                        value_node = c
                if name_node is not None and value_node is not None:
                    for nm in _destructure_names(name_node, src_bytes):
                        bindings.append((nm, value_node))
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None:
                    bindings.append((_node_text(left, src_bytes), right))
            stack.extend(node.children)

        tainted = set()
        for _ in range(30):
            added = False
            for name, value_node in bindings:
                if name in tainted:
                    continue
                if _expr_is_tainted(value_node, src_bytes, tainted):
                    tainted.add(name)
                    added = True
            if not added:
                break
        return tainted


def _iter(root):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        for c in n.children:
            stack.append(c)


class _LineMap:
    def __init__(self, text):
        self._starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self._starts.append(i + 1)

    def line(self, o):
        import bisect
        return bisect.bisect_right(self._starts, o) - 1 + 1

    def col(self, o):
        import bisect
        idx = bisect.bisect_right(self._starts, o) - 1
        return o - self._starts[idx]
