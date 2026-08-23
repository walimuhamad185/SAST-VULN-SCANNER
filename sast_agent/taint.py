"""Lightweight taint-tracking / data-flow primitives."""

SOURCES = {
    "python": [
        r"\binput\s*\(", r"\brequest\.(args|form|values|json|data|get|query_string)\b",
        r"\bos\.environ\b", r"\bsys\.argv\b", r"\braw_input\s*\(",
        r"\.get_data\s*\(", r"\bself\.request\.", r"\bcgi\.FieldStorage\b",
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
        r"request\.getParameter\s*\(", r"request\.getHeader\s*(", r"@RequestParam\b",
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


def identify_sources(line: str, language: str):
    found = []
    for pat in SOURCES.get(language, []):
        if _re_search(pat, line):
            found.append(pat.strip("\\"))
    return found


def assign_tainted_var(line: str):
    import re
    for pat in VARIABLE_SOURCE_ASSIGN:
        m = re.search(pat, line, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _re_search(pattern: str, text: str) -> bool:
    import re
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return False


def is_sink(line: str, language: str, sinks: dict):
    import re
    for pat in sinks.get(language, []):
        try:
            if re.search(pat, line, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False
