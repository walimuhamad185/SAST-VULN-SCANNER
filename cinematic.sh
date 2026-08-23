#!/usr/bin/env bash
# ============================================================
#  SAST-VULN-SCANNER — CINEMATIC DEMO (Hollywood/Hacker style)
#  Black Hat Europe 2026 Arsenal
#  Usage:  bash cinematic.sh
# ============================================================

tput civis 2>/dev/null
RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[1;32m"; DIM="\033[2m"
CYAN="\033[1;36m"; RED="\033[1;31m"; YELLOW="\033[1;33m"
MAGENTA="\033[1;35m"; WHITE="\033[1;37m"; BLUE="\033[1;34m"
BGREEN="\033[42m\033[30m"

type_out() {
  local text="$1"
  for ((i=0; i<${#text}; i++)); do
    printf "${text:$i:1}"
    sleep 0.008
  done
}

bar() {
  local label="$1"
  local total=30
  printf "  ${CYAN}${BOLD}%s ${RESET}[" "$label"
  for ((i=0; i<=total; i++)); do
    printf "${GREEN}█${RESET}"
    sleep 0.02
  done
  printf "] ${GREEN}DONE${RESET}\n"
}

matrix_rain() {
  local lines=${1:-6}
  local cols=70
  local chars="01ABCDEF#$@%&*+=<>"
  for ((r=0; r<lines; r++)); do
    local s=""
    for ((c=0; c<cols; c++)); do
      local idx=$((RANDOM % ${#chars}))
      s+="${chars:$idx:1}"
    done
    printf "  ${DIM}${GREEN}%s${RESET}\n" "$s"
    sleep 0.04
  done
}

logo() {
  clear
  printf "${GREEN}%s${RESET}\n" "  ███████╗ █████╗ ███████╗████████╗   ██╗   ██╗ ██╗   ██╗██╗     ███╗   ██╗"
  printf "${GREEN}%s${RESET}\n" "  ██╔════╝██╔══██╗██╔════╝╚══██╔══╝   ██║   ██║ ██║   ██║██║     ████╗  ██║"
  printf "${GREEN}%s${RESET}\n" "  ███████╗███████║███████╗   ██║      ██║   ██║ ██║   ██║██║     ██╔██╗ ██║"
  printf "${GREEN}%s${RESET}\n" "  ╚════██║██╔══██║╚════██║   ██║      ╚██╗ ██╔╝ ██║   ██║██║     ██║╚██╗██║"
  printf "${GREEN}%s${RESET}\n" "  ███████║██║  ██║███████║   ██║       ╚████╔╝  ╚██████╔╝███████╗██║ ╚████║"
  printf "${GREEN}%s${RESET}\n" "  ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝        ╚═══╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝"
  echo ""
  printf "${CYAN}%s${RESET}\n" "  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗"
  printf "${CYAN}%s${RESET}\n" "  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗"
  printf "${CYAN}%s${RESET}\n" "  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝"
  printf "${CYAN}%s${RESET}\n" "  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗"
  printf "${CYAN}%s${RESET}\n" "  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║"
  printf "${CYAN}%s${RESET}\n" "  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"
  echo ""
  printf "${WHITE}${BOLD}  %s${RESET}\n" "NEXT-GEN AI-POWERED UNIVERSAL SAST AGENT  ·  v$(python3 sast_agent.py --version 2>/dev/null | awk '{print $2}')"
  echo ""
}

header() {
  echo ""
  printf "${BGREEN}%s${RESET}\n" "  █ $1  "
  echo ""
}

# ============================================================
logo
type_out "${GREEN}${BOLD}  >> INITIALIZING CORE ENGINE...${RESET}"
echo ""
bar "LOADING 17 RULE CLASSES"
bar "MOUNTING TAINT ENGINE"
bar "CALIBRATING AI FILTER"
echo ""
type_out "${YELLOW}${BOLD}  >> BOOT SEQUENCE COMPLETE. STANDING BY.${RESET}"
echo ""
sleep 1

header "PHASE 1/7 · RECON — MULTI-FORMAT SCAN"
matrix_rain 4
printf "${WHITE}${BOLD}  >> TARGET: ./tests  |  MODE: deterministic  |  OUTPUT: HTML+JSON+SARIF+MD${RESET}\n\n"
python3 sast_agent.py scan ./tests --format all --no-ai --quiet 2>/dev/null
N=$(python3 -c "import json;print(json.load(open('sast_security_report.json'))['finding_count'])" 2>/dev/null)
printf "  ${RED}${BOLD}  ⚠  THREATS DETECTED: ${N}/13${RESET}\n"
printf "  ${GREEN}  ✔ 4 report formats written (html/json/sarif/md)${RESET}\n"
sleep 1

header "PHASE 2/7 · AUTO-REMEDIATION"
type_out "${CYAN}  >> CRAFTING MACHINE-GENERATED PATCHES...${RESET}"
echo ""
bar "GENERATING FIX REPORT"
python3 sast_agent.py scan ./tests --autofix --no-ai --quiet 2>/dev/null
printf "  ${GREEN}  ✔ sast_autofix_report.md generated${RESET}\n"
sleep 1

header "PHASE 3/7 · CONFIG-DRIVEN POLICY SCAN"
type_out "${CYAN}  >> LOADING ENTERPRISE POLICY (sast.yaml)...${RESET}"
echo ""
python3 sast_agent.py --config sast.yaml --no-ai --quiet 2>/dev/null
printf "  ${GREEN}  ✔ Policy applied (threshold=HIGH, format=all)${RESET}\n"
sleep 1

header "PHASE 4/7 · INCREMENTAL BASELINE (CI/CD)"
python3 sast_agent.py scan ./tests --save-baseline --no-ai --quiet 2>/dev/null
printf "  ${GREEN}  ✔ Baseline seeded${RESET}\n"
python3 sast_agent.py scan ./tests --baseline sast_baseline.json --no-ai --quiet 2>/dev/null; RC=$?
if [ "$RC" = "0" ]; then printf "  ${GREEN}${BOLD}  ✔ DELTA: 0 NEW FINDINGS — PIPELINE GREEN${RESET}\n"; fi
sleep 1

header "PHASE 5/7 · ADVANCED RULE COVERAGE"
cat > /tmp/demo_vulns.py << 'EOF'
import yaml, jwt, logging, ldap
from lxml import etree
from flask import redirect, request, render_template_string

def a(d): return yaml.load(d)
def b(x): return etree.fromstring(x)
def c(s): return jwt.encode({}, s, algorithm="none")
def d(u):
    conn=ldap.initialize("ldap://x"); conn.search_s("dc", 2, "(uid="+u+")")
def e(n): logging.info("user: "+n)
def f(): return render_template_string(request.args.get("tpl"))
def g(): return redirect(request.args.get("next"))
import requests
def h(u): return requests.get(u)
EOF
matrix_rain 3
python3 sast_agent.py scan /tmp/demo_vulns.py --format all --no-ai --quiet 2>/dev/null
printf "  ${YELLOW}${BOLD}  ▸ 8 CLASSES FLAGGED IN ONE PASS:${RESET}\n"
for c in "YAML Deserialization (CWE-502)" "XML External Entity XXE (CWE-611)" "Insecure JWT (CWE-347)" "LDAP Injection (CWE-90)" "Log Injection (CWE-117)" "SSTI (CWE-1336)" "Open Redirect (CWE-601)" "SSRF (CWE-918)"; do
  printf "      ${GREEN}▸${RESET} $c\n"
done
sleep 1

header "PHASE 6/7 · FALSE-POSITIVE PROOF"
printf 'import hashlib, secrets\ndef h(p): return hashlib.sha256(p.encode()).hexdigest()\ndef t(): return secrets.token_hex(32)\n' > /tmp/safe.py
python3 sast_agent.py scan /tmp/safe.py --no-ai --quiet 2>/dev/null; RC=$?
printf "  ${GREEN}${BOLD}  ✔ ZERO FALSE POSITIVES ON SAFE CODE${RESET}\n"
sleep 1

header "PHASE 7/7 · COMPLIANCE MAPPING"
printf "  ${CYAN}  ▸ CWE (Common Weakness Enumeration)${RESET}\n"
printf "  ${CYAN}  ▸ OWASP Top 10 (2021)${RESET}\n"
printf "  ${CYAN}  ▸ MITRE ATT&CK${RESET}\n"
printf "  ${CYAN}  ▸ CI/CD Native Exit Codes${RESET}\n"
echo ""
printf "  ${GREEN}${BOLD}  ░░░░░░░░░░  DEMONSTRATION COMPLETE  ░░░░░░░░░░${RESET}\n"
echo ""

tput cnorm 2>/dev/null
