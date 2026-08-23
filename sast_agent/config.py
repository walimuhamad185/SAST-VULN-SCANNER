"""Central configuration, language detection, and extension mapping."""
import os

LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyw"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "php": {".php", ".php3", ".php4", ".php5", ".phtml"},
    "ruby": {".rb", ".erb"},
    "java": {".java"},
    "go": {".go"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".hxx"},
    "csharp": {".cs"},
    "shell": {".sh", ".bash"},
    "sql": {".sql"},
}

IGNORED_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "venv", ".venv",
    "env", "__pycache__", "dist", "build", ".tox", ".eggs", "site-packages",
    "target", "bin", "obj", ".idea", ".vscode", "coverage",
}

MAX_FILE_SIZE = 5 * 1024 * 1024
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "ollama")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
AI_VERIFY_ENABLED = os.getenv("SAST_AI_VERIFY", "1") == "1"


def detect_language(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if ext in exts:
            return lang
    return "unknown"


def is_text_file(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext not in {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
        ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".woff", ".woff2", ".ttf", ".eot",
    }
