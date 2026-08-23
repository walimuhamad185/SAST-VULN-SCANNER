# Intentionally vulnerable Python target — used to validate real detection.
import os
import pickle
import hashlib
import subprocess
import random


class UserController:
    DB_PASSWORD = "SuperSecret123!"   # Hardcoded credential (CWE-798)

    def __init__(self):
        self.api_key = "sk-1234567890abcdef"   # Hardcoded credential

    # Command injection: user input flows to os.system
    def ping(self, request):
        host = request.args.get("host")
        os.system("ping -c 1 " + host)          # CWE-78 command injection

    # Command injection via subprocess
    def run_cmd(self, user_input):
        subprocess.call("ls " + user_input, shell=True)

    # Code injection
    def dynamic(self, code):
        eval(code)                               # CWE-94 code injection

    # SQL injection (string formatting)
    def get_user(self, username):
        query = "SELECT * FROM users WHERE name = '%s'" % username
        return cursor.execute(query)             # CWE-89 SQL injection

    # Insecure cryptography
    def hash_password(self, pw):
        return hashlib.md5(pw.encode()).hexdigest()   # CWE-327 MD5

    # Insecure deserialization
    def load_obj(self, raw):
        return pickle.loads(raw)                 # CWE-502 insecure deserialization

    # Insecure randomness
    def gen_token(self):
        return random.randint(1000, 9999)        # CWE-330 weak random

    # Path traversal
    def read_file(self, name):
        return open("/data/" + name).read()      # CWE-22 path traversal


# Safe code below — should NOT be flagged
import secrets

def safe_hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()   # secure, not flagged

def safe_token():
    return secrets.token_hex(16)                     # secure, not flagged
