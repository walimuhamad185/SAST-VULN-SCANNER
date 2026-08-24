"""
sast_agent/multilang_ast.py
===========================
AST-based analysis for the remaining languages via tree-sitter:

    JavaScript, TypeScript, Go, PHP, Ruby, Java, C, C++, C#, Shell

This module provides a language-aware engine that:
  1. parses source into a real syntax tree using tree-sitter grammars,
  2. identifies taint SOURCES (user input) and SINKs (dangerous APIs) by
     language-specific matchers,
  3. propagates taint across variable assignments (including simple
     assignment chains), and
  4. suppresses findings when a sanitizer breaks the taint flow.

If tree-sitter (or a specific grammar) is not installed, scanning falls back
gracefully to the regex engine — there is no hard dependency and no crash.
"""

import re

# ---------------------------------------------------------------------------
# Grammar loading
# ---------------------------------------------------------------------------

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript
    import tree_sitter_typescript
    import tree_sitter_go
    import tree_sitter_php
    import tree_sitter_ruby
    import tree_sitter_java
    import tree_sitter_c
    import tree_sitter_cpp
    import tree_sitter_c_sharp
    import tree_sitter_bash
    TREE_SITTER_OK = True
except Exception:
    TREE_SITTER_OK = False


def _lang_fn(lang):
    """Resolve the Language factory for a language kind; returns callable or None."""
    if not TREE_SITTER_OK:
        return None
    table = {
        "javascript": tree_sitter_javascript.language,
        "typescript": lambda: getattr(tree_sitter_typescript, "language", None)() if hasattr(tree_sitter_typescript, "language") else tree_sitter_typescript.language_typescript(),
        "go": tree_sitter_go.language,
        "php": lambda: tree_sitter_php.language_php(),
        "ruby": tree_sitter_ruby.language,
        "java": tree_sitter_java.language,
        "c": tree_sitter_c.language,
        "cpp": tree_sitter_cpp.language,
        "csharp": tree_sitter_c_sharp.language,
        "shell": tree_sitter_bash.language,
    }
    fn = table.get(lang)
    if fn is None:
        return None
    try:
        return fn()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Language-specific source / sink definitions
# ---------------------------------------------------------------------------


def _languages():
    """Return the set of languages this AST engine can handle."""
    return {"javascript", "typescript", "go", "php", "ruby", "java",
            "c", "cpp", "csharp", "shell"}


def _source_patterns(lang):
    """Regex patterns that mark a source (user-controlled input) for a language."""
    p = {
        "php": [r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b",
                r"\$_SERVER\b", r"\$_FILES\b", r"php://input", r"\$GLOBALS\b"],
        "ruby": [r"\bparams\b", r"\bcookies\b", r"\brequest\.params\b"],
        "java": [r"request\.getParameter\s*\(", r"request\.getHeader\s*\(",
                 r"request\.getParameterValues\s*\(", r"@RequestParam\b", r"@PathVariable\b"],
        "go": [r"r\.URL\.Query\s*\(", r"r\.FormValue\s*\(", r"r\.PostFormValue\s*\(",
               r"os\.Args\b", r"os\.Getenv\s*\(", r"c\.Query\s*\(", r"c\.Param\s*\(",
               r"io\.ReadAll\s*\(", r"\.ReadAll\s*\("],
        "c": [r"\bscanf\s*\(", r"\bgets\s*\(", r"\bfgets\s*\(", r"\bargv\b", r"\bgetenv\s*\("],
        "cpp": [r"\bstd::cin\b", r"\bcin\s*>>", r"\bgets\s*\(", r"\bargv\b", r"\bgetenv\s*\("],
        "csharp": [r"Request\.QueryString\b", r"Request\.Form\b", r"Console\.ReadLine\s*\(",
                   r"Request\.Params\b", r"Request\.Cookies\b"],
        "shell": [r"\$[1-9@]|\$\*|\$\@|\$\{.*\}", r"\$(\(|{)", r"\$USER_INPUT", r"\$INPUT",
                  r"read\s+\w+"],
    }
    # JS/TS handled by js_ast.py (kept here for completeness)
    p["javascript"] = [r"\breq\.(query|body|params|param)\b", r"\bprocess\.argv\b", r"\bprocess\.env\b"]
    p["typescript"] = [r"\breq\.(query|body|params|param)\b", r"\bprocess\.argv\b", r"\bprocess\.env\b"]
    return p.get(lang, [])


def _sink_matchers(lang):
    """Return a list of (compiled_or_str_pattern, rule, cwe, severity, message)."""
    generic = {
        # Commands / eval — true in almost every language
        "cmd": [
            # code injection (language-level eval/execute of a string)
            (r"\b(eval)\s*\(|\beval\s+", "Code Injection (eval/exec)", "CWE-94", "CRITICAL",
             "Dynamic code execution (eval) of user input."),
            # command injection (shell/process execution)
            (r"\b(system|popen|shell_exec|passthru|Runtime\s*\.\s*getRuntime|ProcessBuilder|Process\.Start|exec\.Command|subprocess|os\.system)\b",
             "OS Command Injection", "CWE-78", "CRITICAL",
             "Command/process execution with user input."),
        ],
        "sql": [
            (r"\b(mysql_query|mysqli_query|pg_query|sqlite_query|executemany|execute_query|executeUpdate|executeQuery)\s*\(",
             "SQL Injection", "CWE-89", "CRITICAL", "SQL statement built from user input."),
            (r"\b(?:SELECT|INSERT|UPDATE|DELETE|FROM)\b",
             "SQL Injection", "CWE-89", "CRITICAL", "SQL statement built from user input."),
        ],
        "crypto": [
            (r"\b(md5|sha1|MD5|SHA1)\s*\(", "Insecure Cryptography", "CWE-327", "HIGH",
             "Broken cryptographic hash (MD5/SHA1)."),
        ],
        "random": [
            (r"\b(rand|random|Math\.random|randint)\s*\(", "Insecure Randomness", "CWE-330", "MEDIUM",
             "Non-cryptographic randomness for security-sensitive values."),
        ],
        "deser": [
            (r"\b(pickle\.loads|yaml\.load|Marshal\.load|unserialize|ObjectInputStream\.readObject|BinaryFormatter\.Deserialize|json\.loads)\s*\(",
             "Insecure Deserialization", "CWE-502", "HIGH", "Deserialization of untrusted data."),
        ],
        "xxe": [
            (r"\b(SAXParser|DocumentBuilder|XMLReader|XmlDocument|simplexml_load_string|SimpleXMLElement)\b",
             "XML External Entity (XXE)", "CWE-611", "HIGH", "XML parsed without disabling external entities."),
        ],
        "redirect": [
            (r"\b(redirect|Redirect|header\s*\(\s*[\"']Location|sendRedirect)\s*\(", "Open Redirect", "CWE-601",
             "MEDIUM", "Redirect target derived from user input."),
        ],
        "path": [
            (r"\b(open|fopen|file_get_contents|FileReader|new File\s*\()\s*\(", "Path Traversal", "CWE-22", "HIGH",
             "Filesystem access with a user-controlled path."),
        ],
    }
    return generic


def _sink_text(lang):
    """Extra language-specific sink substrings tuned for AST nodes (call_text)."""
    extra = {
        "javascript": [
            r"\b(eval|Function)\s*\(", r"\binnerHTML\s*=", r"dangerouslySetInnerHTML",
            r"\b(exec|execSync|spawn|spawnSync|fork)\s*\(", r"\bdocument\.write\s*\(",
            r"crypto\.createHash\(['\"]md5['\"]\)", r"crypto\.createHash\(['\"]sha1['\"]\)",
            r"\.query\s*\(", r"\.execute\s*\(", r"res\.(send|write|end)\s*\(",
            r"\.redirect\s*\(", r"fetch\(|axios\.(get|post|request)",
            r"Math\.random\s*\(", r"jwt\.(sign|verify|decode)",
        ],
        "typescript": [
            r"\b(eval|Function)\s*\(", r"\binnerHTML\s*=", r"dangerouslySetInnerHTML",
            r"\b(exec|execSync|spawn|spawnSync|fork)\s*\(", r"\bdocument\.write\s*\(",
            r"crypto\.createHash\(['\"]md5['\"]\)", r"crypto\.createHash\(['\"]sha1['\"]\)",
            r"\.query\s*\(", r"\.execute\s*\(", r"res\.(send|write|end)\s*\(",
            r"\.redirect\s*\(", r"fetch\(|axios\.(get|post|request)",
            r"Math\.random\s*\(", r"jwt\.(sign|verify|decode)",
        ],
        "go": [r"\.Run\s*\(", r"template\.HTML"],
        "php": [r"system\s*\(", r"shell_exec\s*\(", r"eval\s*\(", r"echo\s+"],
        "ruby": [r"`[^`]*`", r"send\s*\("],
        "java": [r"Runtime\.getRuntime\(\)\.exec", r"ProcessBuilder\s*\(", r"\.execute\(\)"],
        "c": [r"system\s*\(", r"popen\s*\(", r"exec\w*\s*\(", r"strcpy\s*\(", r"sprintf\s*\("],
        "cpp": [r"system\s*\(", r"popen\s*\(", r"std::system"],
        "csharp": [r"Process\.Start\s*\(", r"ProcessStartInfo\s*\(", r"cmd\.exe"],
        "shell": [r"\beval\b", r"\bsystem\b", r"`.*`", r"\$\(\s*", r"\bsh\s+-c"],
    }
    return extra.get(lang, [])


def _sanitizer_patterns(lang):
    p = {
        "php": [r"htmlspecialchars\s*\(", r"htmlentities\s*\(", r"addslashes\s*\(",
                r"mysqli_real_escape_string", r"strip_tags\s*\(", r"intval\s*\("],
        "ruby": [r"CGI\.escape", r"ERB::Util\.html_escape", r"\.sanitize", r"\.strip\s*$"],
        "java": [r"StringEscapeUtils\.escapeHtml", r"ESAPI\.encoder", r"\.trim\s*\("],
        "go": [r"html\.EscapeString", r"\.TrimSpace\s*\(", r"url\.QueryEscape"],
        "c": [r"snprintf\s*\("],
        "cpp": [r"std::string\b"],
        "csharp": [r"HttpUtility\.HtmlEncode", r"AntiXssEncoder", r"\.Trim\s*\("],
    }
    return p.get(lang, [])


# ---------------------------------------------------------------------------
# AST engine
# ---------------------------------------------------------------------------



def _attribute_extra_sink(pat):
    """Map a language-specific extra sink regex to a precise rule/CWE/severity."""
    p = pat
    if "md5" in p or "sha1" in p:
        return ("Insecure Cryptography", "CWE-327", "HIGH")
    if ("innerHTML" in p or "dangerouslySetInnerHTML" in p or "document" in p
            or "res." in p or ("send" in p and "write" in p)):
        return ("Cross-Site Scripting (XSS)", "CWE-79", "HIGH")
    if "eval" in p or "Function" in p:
        return ("Code Injection (eval/exec)", "CWE-94", "CRITICAL")
    if ".query" in p or ".execute" in p:
        return ("SQL Injection", "CWE-89", "CRITICAL")
    if "exec" in p or "spawn" in p or "fork" in p or "system" in p or "popen" in p or "Process" in p or "Run" in p or "sh\s+-c" in p or "strcpy" in p or "sprintf" in p or "cmd.exe" in p:
        return ("OS Command Injection", "CWE-78", "CRITICAL")
    if "redirect" in p:
        return ("Open Redirect", "CWE-601", "MEDIUM")
    if "fetch" in p or "axios" in p:
        return ("Server-Side Request Forgery", "CWE-918", "HIGH")
    if "Math.random" in p:
        return ("Insecure Randomness", "CWE-330", "MEDIUM")
    if "jwt" in p:
        return ("Insecure JWT", "CWE-347", "HIGH")
    if "template" in p:
        return ("Server-Side Template Injection", "CWE-1336", "HIGH")
    if "send\s*" in p or "`" in p:
        return ("Code Injection (eval/exec)", "CWE-94", "HIGH")
    if "eval" in p:
        return ("Code Injection (eval/exec)", "CWE-94", "CRITICAL")
    return ("OS Command Injection", "CWE-78", "CRITICAL")


class MultilangScanner:
    def __init__(self, lang):
        self.lang = lang
        self._parser = None
        fn = _lang_fn(lang)
        if fn is not None:
            try:
                self._parser = Parser(Language(fn))
            except Exception:
                self._parser = None

    @property
    def available(self):
        return self._parser is not None

    def scan(self, src: str):
        if not self.available:
            return []
        src_bytes = src.encode("utf-8")
        tree = self._parser.parse(src_bytes)
        root = tree.root_node

        sources = _source_patterns(self.lang)
        sanitizers = _sanitizer_patterns(self.lang)
        extra_sinks = _sink_text(self.lang)

        tainted_names = self._collect_taint(root, src_bytes, sources, sanitizers)

        findings = []
        self._seen = set()
        lm = _LineMap(src)

        # Walk all leaf-ish call nodes and match against sinks
        for node in _iter_nodes(root):
            text = _node_text(node, src_bytes)
            if not text:
                continue
            # Only match call-like nodes and string/command nodes
            if not _is_call_like(node, self.lang):
                continue
            for rule, cwe, sev, msg in self._match_sinks(text, extra_sinks):
                tainted = self._text_tainted(text, tainted_names, src_bytes, node, sanitizers)
                line = lm.line(node.start_byte)
                col = lm.col(node.start_byte)
                key = rule
                if key in self._seen:
                    continue
                self._seen.add(key)
                findings.append({"rule": rule, "cwe": cwe, "severity": sev,
                                 "line": line, "col": col, "message": msg, "tainted": tainted})
        return findings

    def _collect_taint(self, root, src_bytes, sources, sanitizers):
        tainted = set()
        # 1. direct sources in any node text
        for node in _iter_nodes(root):
            text = _node_text(node, src_bytes)
            for pat in sources:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    # try to associate a variable being assigned
                    v = _assigned_var(node, src_bytes, self.lang)
                    if v:
                        tainted.add(v)
                    break
        # 2. fixed-point through assignment chains
        # Map var -> assigned value text
        def var_text(node):
            return _node_text(node, src_bytes)
        assignments = {}
        for node in _iter_nodes(root):
            t = node.type
            if t in ("variable_declarator", "local_variable_declaration",
                     "variable_declaration", "assignment_expression", "assignment",
                     "short_variable_declaration", "let_expression", "const_declaration"):
                v = _assigned_var(node, src_bytes, self.lang)
                val = _assigned_value_text(node, src_bytes, self.lang)
                if v and val:
                    assignments[v] = val
        for _ in range(20):
            added = False
            for v, val in assignments.items():
                if v in tainted:
                    continue
                if any(s in val for s in tainted) or any(
                        re.search(pat, val, re.IGNORECASE) for pat in sources):
                    tainted.add(v)
                    added = True
            if not added:
                break
        return tainted

    def _match_sinks(self, text, extra_sinks):
        # Mask standard console I/O so it is not mistaken for a command sink.
        text = re.sub(r"\bSystem\.(out|err|in)\b", "SystemConsole", text)
        text = re.sub(r"\brequire\s*\(", "requireMODULE(", text)
        out = []
        for group in ("cmd", "sql", "crypto", "random", "deser", "xxe", "redirect", "path"):
            for pat, rule, cwe, sev, msg in _sink_matchers(self.lang)[group]:
                if re.search(pat, text, re.IGNORECASE):
                    out.append((rule, cwe, sev, msg))
                    break
        for pat in extra_sinks:
            if re.search(pat, text, re.IGNORECASE):
                # attribute best-effort rule
                rule, cwe, sev = _attribute_extra_sink(pat)
                out.append((rule, cwe, sev,
                            "Potential injection of user input into a sink."))
        # dedupe preserving order
        seen = set()
        uniq = []
        for r in out:
            if r[0] not in seen:
                seen.add(r[0])
                uniq.append(r)
        return uniq

    def _text_tainted(self, text, tainted_names, src_bytes, node, sanitizers):
        if any(re.search(s, text, re.IGNORECASE) for s in sanitizers):
            return False
        if any(v in text for v in tainted_names):
            return True
        for pat in _source_patterns(self.lang):
            if re.search(pat, text, re.IGNORECASE):
                return True
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_nodes(root):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        for c in n.children:
            stack.append(c)


def _node_text(node, src_bytes):
    return src_bytes[node.start_byte:node.end_byte].decode("utf-8", "ignore")


def _is_call_like(node, lang):
    t = node.type
    call_types = {"call_expression", "function_call_expression", "method_invocation",
                  "invocation_expression", "command", "command_substitution",
                  "scoped_call_expression", "member_call_expression", "call",
                  "binary_expression", "binary", "concatenation", "encapsed_string"}
    return t in call_types


def _assigned_var(node, src_bytes, lang):
    text = _node_text(node, src_bytes)
    # common assignment forms
    patterns = [
        r"(?:var|let|const|local)\s+(\w+)",          # JS/Typescript/Go(short)
        r"(\w+)\s*:=\s*",                              # Go short decl
        r"^\s*(\w+)\s*=\s*",                           # plain assignment
        r"(\w+)\s*=\s*.*Request\.",                    # C# / java-ish
        r"String\s+(\w+)\s*=",                          # Java
        r"std::(\w+)\s+(\w+)\s*=",                      # C++ (type var)
        r"char\s+(\w+)",                                # C
        r"(?:int|float|double|long|string|String)\s+(\w+)\s*=",  # typed
        r"\$(\w+)\s*=",                                 # PHP / shell
        r"\b(\w+)\s*=",                                 # generic fallback
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def _assigned_value_text(node, src_bytes, lang):
    text = _node_text(node, src_bytes)
    m = re.search(r"=\s*(.*)", text, re.DOTALL)
    return m.group(1).strip() if m else None


class _LineMap:
    def __init__(self, text):
        self._starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self._starts.append(i + 1)

    def line(self, byte_offset):
        import bisect
        return bisect.bisect_right(self._starts, byte_offset) - 1 + 1

    def col(self, byte_offset):
        import bisect
        idx = bisect.bisect_right(self._starts, byte_offset) - 1
        return byte_offset - self._starts[idx]
