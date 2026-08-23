"""
sast_agent/rules.py
===================
Vulnerability rules: sinks, secure-alternatives, and AST analysis logic.
"""
from .models import Rule

RULES = [
    Rule(name="OS Command Injection", cwe="CWE-78", severity="CRITICAL",
         description="Unsanitized user input reaches a shell / subprocess call.",
         remediation="Use subprocess.run(..., shell=False) with an argument list and never concatenate user input into a command string.",
         languages=["python", "javascript", "php", "ruby", "go", "java", "c", "cpp", "csharp", "shell"]),
    Rule(name="Code Injection (eval/exec)", cwe="CWE-94", severity="CRITICAL",
         description="Dynamic execution of attacker-controlled strings (eval/exec).",
         remediation="Never eval/exec user input. Refactor to safe data structures.",
         languages=["python", "javascript", "php", "ruby"]),
    Rule(name="SQL Injection", cwe="CWE-89", severity="CRITICAL",
         description="SQL built by string concatenation / interpolation of untrusted input.",
         remediation="Use parameterized queries / prepared statements (?, %s placeholders).",
         languages=["python", "javascript", "typescript", "php", "ruby", "java", "go", "csharp"]),
    Rule(name="Insecure Cryptography", cwe="CWE-327", severity="HIGH",
         description="Use of cryptographically broken hashing / cipher (MD5, SHA1, DES, RC4).",
         remediation="Use SHA-256+ / bcrypt / Argon2 for hashing; AES-GCM for encryption.",
         languages=["python", "javascript", "typescript", "php", "ruby", "java", "go", "csharp"]),
    Rule(name="Cross-Site Scripting (XSS)", cwe="CWE-79", severity="HIGH",
         description="User input written unsanitized into HTML/JS output.",
         remediation="HTML-encode output; use a templating engine with auto-escaping.",
         languages=["javascript", "typescript", "php", "python", "ruby"]),
    Rule(name="Path Traversal", cwe="CWE-22", severity="HIGH",
         description="User input used to build a filesystem path without validation.",
         remediation="Canonicalize and validate paths against an allow-list root directory.",
         languages=["python", "javascript", "php", "ruby", "java", "go", "c"]),
    Rule(name="Hardcoded Credential", cwe="CWE-798", severity="HIGH",
         description="Hardcoded password, API key, or secret token in source.",
         remediation="Move secrets to environment variables or a secrets manager.",
         languages=["python", "javascript", "typescript", "php", "ruby", "java", "go", "csharp"]),
    Rule(name="Insecure Deserialization", cwe="CWE-502", severity="CRITICAL",
         description="Deserializing untrusted data (pickle, unserialize, Marshal).",
         remediation="Never deserialize untrusted input; use safe data formats (JSON) with schema validation.",
         languages=["python", "javascript", "php", "ruby", "java", "go", "csharp"]),
    Rule(name="Insecure Randomness", cwe="CWE-330", severity="MEDIUM",
         description="Use of predictable RNG for security-sensitive context.",
         remediation="Use a cryptographically secure generator (secrets, crypto.getRandomValues).",
         languages=["python", "javascript", "typescript", "php", "ruby", "java", "go", "csharp"]),
    Rule(name="Server-Side Request Forgery", cwe="CWE-918", severity="HIGH",
         description="User-controlled URL passed to a server-side HTTP fetch.",
         remediation="Allow-list and validate destination URLs; block internal IPs.",
         languages=["python", "javascript", "typescript", "php", "ruby", "go", "java"]),
]

SINKS = {
    "python": [
        r"\bos\.system\s*\(", r"\bos\.popen\s*\(", r"\bsubprocess\.(call|Popen|run|check_output|check_call)\s*\(",
        r"\beval\s*\(", r"\bexec\s*\(", r"\bpickle\.loads?\s*\(", r"\byaml\.load\s*\(",
        r"\.execute\(\s*.*%|f\"[\s\S]*?%|\.format\([\s\S]*?%",
        r"\bcrypt\b[^\n]*(md5|sha1|des|rc4)|md5\s*\(|sha1\s*\(|\.update\(\s*(?:md5|sha1)",
        r"\bhashlib\.(md5|sha1)\s*\(", r"MD5\s*\(", r"Crypto\.Hash\.(MD5|SHA1|MD4)",
        r"\bopen\s*\([^)]*['\"][a-z]:?/|send_file\s*\([^)]*request",
        r"\bsecrets\.|random\.randint|random\.random\s*\(\)",
        r"cryptography[^\n]*(DES|RC4|Blowfish)",
        r"requests\.(get|post)\s*\([^)]*(request|input|url|args)",
    ],
    "javascript": [
        r"\beval\s*\(", r"\bFunction\s*\(", r"\bexec\s*\(\s*['\"]", r"\bexecSync\s*\(", r"\bspawn\s*\(",
        r"\.query\s*\(\s*['\"][\s\S]*\+|`SELECT[\s\S]*\$\{",
        r"document\.write\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML|insertAdjacentHTML",
        r"crypto\.createHash\s*\(\s*['\"]md5|crypto\.createHash\s*\(\s*['\"]sha1|MD5\s*\(",
        r"Math\.random\s*\(\)",
        r"require\s*\(\s*[\"'][a-z]*path[\"']\).*\+|readFile\s*\([^)]*req|sendFile\s*\([^)]*req",
        r"password\s*[:=]\s*['\"][^'\"]{4,}['\"]|api[_-]?key\s*[:=]\s*['\"]|secret\s*[:=]\s*['\"]|token\s*[:=]\s*['\"][A-Za-z0-9]{8,}",
        r"axios\.(get|post)\s*\([^)]*(req|url|input|location)|fetch\s*\([^)]*(req|url|input|location)",
    ],
    "typescript": [
        r"\beval\s*\(", r"\bexecSync\s*\(", r"\bspawn\s*\(", r"\.query\s*\(\s*['\"][\s\S]*\+",
        r"document\.write\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML",
        r"crypto\.createHash\s*\(\s*['\"]md5|crypto\.createHash\s*\(\s*['\"]sha1",
        r"password\s*[:=]\s*['\"]|api[_-]?key\s*[:=]\s*['\"]|secret\s*[:=]\s*['\"]",
    ],
    "php": [
        r"\bsystem\s*\(|\bexec\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|\beval\s*\(|\bpopen\s*\(",
        r"mysql_query\s*\(|mysqli_query\s*\([^)]*\$|->query\s*\(\s*\$",
        r"\becho\s+\$_|\bprint\s+\$_|\.\$_GET|\.\$_POST",
        r"\bmd5\s*\(|\bsha1\s*\(|hash\s*\(\s*['\"]md5|hash\s*\(\s*['\"]sha1",
        r"unserialize\s*\(|\binclude\s+\$_|\brequire\s+\$_|fopen\s*\([^)]*\$",
        r"\b\$password\s*=\s*['\"]|\$api_key\s*=\s*['\"]|\$secret\s*=\s*['\"]",
        r"file_get_contents\s*\([^)]*\$_(GET|POST|REQUEST)",
    ],
    "ruby": [
        r"\bsystem\s*\(|\bexec\s*\(|\b`[^`]*#\{|\beval\s*\(", r"\bMarshal\.load\s*\(",
        r"\.where\s*\(\s*['\"]?[^'\"]*#\{|find_by_sql\s*\(",
        r"Digest::MD5|Digest::SHA1|OpenSSL::Cipher::(DES|RC4)",
        r"params\[[^\]]*\]\s*\.|render\s*(?:inline|text)\s*=>.*params",
        r"password\s*[:=]\s*['\"]|api_key\s*[:=]\s*['\"]",
        r"net/http[^\n]*uri|Net::HTTP\.get\s*\([^)]*params",
    ],
    "java": [
        r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(",
        r"Statement\.execute(Query|Update)?\s*\([^)]*\+|createStatement\s*\(\)",
        r"MessageDigest\.getInstance\s*\(\s*['\"]MD5|MessageDigest\.getInstance\s*\(\s*['\"]SHA-1",
        r"ObjectInputStream\s*\(|\.readObject\s*\(\)",
        r"new\s+File\s*\([^)]*getParameter|getParameter\([^)]*\)\s*\.",
        r"password\s*=\s*['\"]|API_KEY\s*=\s*['\"]|secret\s*=\s*['\"]",
        r"HttpURLConnection[^\n]*(getParameter|getHeader|input)",
    ],
    "go": [
        r"exec\.Command\s*\([^)]*\.\.\.|os/exec[^\n]*Command",
        r"db\.Query\s*\([^)]*\+|\.Query\s*\(fmt\.Sprintf|\.Exec\s*\(fmt\.Sprintf",
        r"crypto/md5[^\n]*|md5\.(New|Sum)\s*\(|sha1\.(New|Sum)\s*\(",
        r"gob\.NewDecoder\s*\(|json\.Unmarshal\s*\([^)]*\)\s*//.*untrusted",
        r"password\s*[:=]\s*['\"]|apiKey\s*[:=]\s*['\"]|secret\s*[:=]\s*['\"]",
        r"http\.Get\s*\([^)]*\.(Query|FormValue|Param)",
    ],
    "c": [
        r"\bsystem\s*\(|\bpopen\s*\(|\bexeclp?\s*\(|\bexecvp?\s*\(|\bsystem\s*\(",
        r"strcpy\s*\(|strcat\s*\(|\bgets\s*\(|sprintf\s*\([^)]*%s",
        r"MD5\s*\(|SHA1\s*\(|DES_",
    ],
    "cpp": [
        r"\bsystem\s*\(|\bpopen\s*\(|\bstd::system\s*\(|execlp?\s*\(|execvp?\s*\(",
        r"strcpy\s*\(|strcat\s*\(|\bgets\s*\(|sprintf\s*\([^)]*%s",
    ],
    "csharp": [
        r"Process\.Start\s*\(|\bProcessStartInfo\b",
        r"\bCommand\([^)]*\+|SqlCommand\s*\([^)]*\+",
        r"MD5\.Create\s*\(|SHA1\.Create\s*\(|DESCryptoServiceProvider|RC2CryptoServiceProvider",
        r"BinaryFormatter[^\n]*Deserialize|\.Deserialize\s*\([^)]*Request",
        r"Response\.Write\s*\([^)]*Request|innerHTML\s*=.*Request",
        r"password\s*=\s*['\"]|API_KEY\s*=\s*['\"]|secret\s*=\s*['\"]",
    ],
    "shell": [
        r"\beval\s+['\"]?\$", r"\bcurl\b[^\n]*\$(cat|printf)", r"password=\S+|PASSWD=\S+",
    ],
}

SANITIZERS = {
    "python": [
        r"subprocess\.run\s*\(\s*\[", r"\.execute\(\s*['\"][\s\S]*?\?\s*[,)]",
        r"\.execute\(\s*['\"][\s\S]*?%s", r"hashlib\.(sha256|sha512|sha3_256|sha3_512)",
        r"bcrypt\.|argon2|pbkdf2", r"secrets\.(token_|randbelow|choice)", r"subprocess\.\w+\s*\([^)]*shell\s*=\s*False",
    ],
    "javascript": [
        r"createHash\s*\(\s*['\"]sha256|createHash\s*\(\s*['\"]sha512",
        r"crypto\.randomBytes|getRandomValues",
        r"escaped\(|htmlspecialchars|\bencodeURIComponent\s*\(",
        r"\.query\s*\(\s*['\"][\s\S]*\?\s*[,)]|\.query\s*\(\s*['\"][\s\S]*\$1[\s\S]*,\s*\[",
    ],
    "php": [
        r"password_hash\s*\(|password_verify\s*\(|hash\s*\(\s*['\"]sha256",
        r"htmlspecialchars\s*\(|mysqli_prepare\s*\(|PDO::prepare\s*\(|->prepare\s*\(",
        r"random_bytes\s*\(|openssl_random_pseudo_bytes\s*\(",
    ],
    "ruby": [
        r"Digest::SHA256|Digest::SHA512|BCrypt::|OpenSSL::Cipher::AES",
        r"\.where\s*\(\s*['\"]?[a-zA-Z_]+\.eq|where\s*\(\w+:\s*", r"ERB::Util\.h|CGI\.escape",
    ],
    "java": [
        r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-256|MessageDigest\.getInstance\s*\(\s*['\"]SHA-512",
        r"PreparedStatement\b|prepareStatement\s*\(|SecureRandom\b",
    ],
    "go": [
        r"sha256\.(New|Sum)|sha512\.(New|Sum)|bcrypt\.", r"crypto/rand[^\n]*",
        r"\.QueryRow?\s*\([^)]*\?,", r"db\.Prepare\s*\(",
    ],
    "csharp": [
        r"SHA256\.Create\s*\(|SHA512\.Create\s*\(|RNGCryptoServiceProvider|RandomNumberGenerator\b",
        r"Parameters\.AddWithValue|SqlParameter\b",
    ],
}
