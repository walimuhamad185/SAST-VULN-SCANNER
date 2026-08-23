// Intentionally vulnerable JavaScript target — validates multi-language detection.
const crypto = require('crypto');
const { exec, execSync } = require('child_process');

// Command injection (CWE-78)
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host);            // tainted -> sink
});

// Code injection (CWE-94)
function run(userCode) {
  eval(userCode);                       // dangerous eval
}

// XSS (CWE-79)
app.get('/echo', (req, res) => {
  res.send('<div>' + req.query.name + '</div>');   // reflected XSS
});

// SQL injection (CWE-89)
function findUser(name) {
  const q = "SELECT * FROM users WHERE name = '" + name + "'";
  db.query(q);                          // string-built SQL
}

// Insecure crypto (CWE-327)
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');  // MD5
}

// Hardcoded secret (CWE-798)
const API_KEY = "AKIA1234567890SECRETKEY";
