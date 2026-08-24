"""Taint-tracking / data-flow primitives with interprocedural support."""

import re

SOURCES = {
    "python": [
        r"\binput\s*\(", r"\brequest\.(args|form|values|json|data|get|query_string)\b",
        r"\bos\.environ\b", r"\bsys\.argv\b", r"\braw_input\s*\(",
        r"\.get_data\s*\(", r"\bself\.request\.", r"\bcgi\.FieldStorage\b",
        r"\brequest\.(get|post|put|delete|patch)\.", r"\bflask\.request\b",
        r"\bsocket\.recv\s*\(", r"\brecv\s*\(", r"\burllib\.request\.urlopen\b",
    ],
    "javascript": [
        r"\breq\.(query|body|params|param)\b", r"\bwindow\.location\b",
        r"\bdocument\.(URL|referrer|cookie)\b", r"\blocation\.(hash|search)\b",
        r"\bprocess\.argv\b", r"\bprocess\.env\b", r"\breadFileSync\b",
    ],
    "typescript": [
        r"\breq\.(query|body|params|param)\b", r"\bprocess\.argv\b",
        r"\bprocess\.env\b", r"\bwindow\.location\b",
    ],
    "php": [
        r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b",
        r"\$_SERVER\b", r"\$_FILES\b", r"\$GLOBALS\b", r"php://input",
    ],
    "ruby": [
        r"\bparams\b", r"\bcookies\b", r"\bARGV\b", r"\bENV\b", r"\brequest\.params\b",
    ],
    "java": [
        r"request\.getParameter\s*\(", r"request\.getHeader\s*\(", r"@RequestParam\b",
        r"@PathVariable\b", r"Scanner\s+\w+\s*=\s*new\s+Scanner\s*\(",
    ],
    "go": [
        r"r\.URL\.Query\(\)", r"r\.FormValue\s*\(", r"os\.Args\b", r"os\.Getenv\s*\(",
        r"c\.Query\s*\(", r"c\.Param\s*\(", r"io\.ReadAll\s*\(",
    ],
    "c": [r"\bscanf\s*\(", r"\bgets\s*\(", r"\bfgets\s*\(", r"\bargv\b", r"\bgetenv\s*\("],
    "cpp": [r"\bcin\s*>>", r"\bgets\s*\(", r"\bargv\b", r"\bgetenv\s*\(", r"\bstd::cin\b"],
    "csharp": [
        r"Request\.QueryString\b", r"Request\.Form\b", r"Console\.ReadLine\s*\(",
        r"\.Query\[", r"Request\.Params\b",
    ],
}

# Functions/methods that SANITIZE their argument: taint must NOT propagate through them.
SANITIZER_RETURNS = {
    "python": [
        r"\.strip\s*\(\)", r"\.escape\s*\(\)", r"\bhtml\.escape\s*\(",
        r"\bescape\s*\(\)", r"\burlencode\s*\(", r"\bquote\s*\(",
        r"\bbase64\.b64encode\s*\(", r"\bhashlib\s*\(", r"\bbcrypt\s*\(",
        r"\brescapejs\s*\(\)", r"\bmarkupsafe\.escape\s*\(",
    ],
    "javascript": [
        r"\.trim\s*\(\)", r"\.escape\s*\(\)", r"encodeURIComponent\s*\(",
        r"escapeHTML", r"escapeHtml", r"DOMPurify\.sanitize", r"sanitizeHtml",
    ],
    "typescript": [
        r"\.trim\s*\(\)", r"encodeURIComponent\s*\(", r"escapeHTML", r"sanitizeHtml",
    ],
    "php": [
        r"htmlspecialchars\s*\(", r"htmlentities\s*\(", r"strip_tags\s*\(",
        r"addslashes\s*\(", r"mysqli_real_escape_string",
    ],
    "ruby": [
        r"CGI\.escape", r"ERB::Util\.html_escape", r"\.sanitize", r"\.strip\s*$",
    ],
    "java": [
        r"StringEscapeUtils\.escapeHtml", r"\.trim\s*\(\)", r"ESAPI\.encoder",
    ],
    "go": [
        r"html\.EscapeString", r"\.TrimSpace\s*\(\)", r"url\.QueryEscape",
    ],
    "csharp": [
        r"HttpUtility\.HtmlEncode", r"\.Trim\s*\(\)", r"AntiXssEncoder",
    ],
    "c": [r"snprintf\s*\("],
    "cpp": [r"std::string"],
}

VARIABLE_SOURCE_ASSIGN = [
    r"(\w+)\s*=\s*(?:request|req)\.(?:args|form|values|json|data|query|params|get)\b",
    r"(\w+)\s*=\s*input\s*\(",
    r"(\w+)\s*=\s*os\.environ\b",
    r"(\w+)\s*=\s*sys\.argv\b",
    r"\$(\w+)\s*=\s*\$_GET",
    r"\$(\w+)\s*=\s*\$_POST",
    r"\$(\w+)\s*=\s*\$_REQUEST",
    r"const\s+(\w+)\s*=\s*req\.query",
    r"let\s+(\w+)\s*=\s*req\.query",
    r"var\s+(\w+)\s*=\s*req\.query",
    r"(\w+)\s*:=\s*r\.FormValue",
    r"(\w+)\s*:=\s*r\.URL\.Query",
]


def _re_search(pattern, text):
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return False


def identify_sources(line, language):
    found = []
    for pat in SOURCES.get(language, []):
        if _re_search(pat, line):
            found.append(pat.strip("\\"))
    return found


def assign_tainted_var(line):
    for pat in VARIABLE_SOURCE_ASSIGN:
        m = re.search(pat, line, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def is_sanitizing_call(expr_src, language):
    """Return True if expr_src looks like a sanitizer/encoder call whose
    return value must NOT carry taint."""
    for pat in SANITIZER_RETURNS.get(language, []):
        if _re_search(pat, expr_src):
            return True
    return False


def is_sink(line, language, sinks):
    for pat in sinks.get(language, []):
        try:
            if re.search(pat, line, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False
