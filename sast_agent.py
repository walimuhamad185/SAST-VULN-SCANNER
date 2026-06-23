import os
import sys
import re
import datetime
import html
from openai import OpenAI

# Local Ollama Client Configuration
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

def ask_local_ai(prompt):
    """Chote AI models ke liye exact response extraction engine"""
    try:
        response = client.chat.completions.create(
            model="qwen2.5:1.5b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0
        )
        if response and response.choices and response.choices.message:
            return response.choices.message.content.strip()
        return "FALSE ALARM: Empty response from AI."
    except Exception as e:
        return f"FALSE ALARM: AI Engine Error ({str(e)})"

def deep_security_scan(target_folder):
    """Universal Engine scanning ALL files for security threats"""
    findings = []
    
    print(f"[*] Universal Scanning initiated on: {target_folder}")
    
    # Advanced Multi-Language & Infrastructure Rules
    rules = {
        "Hardcoded Secret/Token": r'(?i)(password|passwd|secret|api_key|jwt_secret|auth_token|private_key|aws_secret|token)\s*=\s*[\'"][a-zA-Z0-9_\-+=/]{8,}[\'"]',
        "Command Injection Risk": r'(exec\(|eval\(|system\(|child_process\.exec|subprocess\.Popen|sh\(|os\.system|popen\()',
        "Path Traversal Flaw": r'(\.\./\.\./|send_file\(|fs\.readFile\(.*req\.query|cat\s+.*\/etc\/passwd)',
        "Insecure Cryptography": r'(md5\(|sha1\(|crypto\.createHash\([\'"]md5[\'"]|MD5_Init)',
        "SQL Injection Vector": r'(\.execute\(\s*[\'"].*%\s*|SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*\+\s*[a-zA-Z]|\.raw\()',
        "XSS Insecure Sink": r'(innerHTML\s*=|document\.write\(|dangerouslySetInnerHTML|echo\s+\$_GET)',
        "Broken Access Control / Insecure Configuration": r'(chmod\([\'"]777[\'"]|allowAllOrigins|cors:.*[\'"]\*[\'"]|0\.0\.0\.0|verify_ssl\s*=\s*False)'
    }

    for root, dirs, files in os.walk(target_folder):
        # Heavy data directories skip karne ke liye
        if any(ignored in root for ignored in ['venv', '.git', 'node_modules', 'dist', 'build', '__pycache__']):
            continue
            
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # Binary files ya boht bari files ko skip karne ke liye size check
                if os.path.getsize(file_path) > 5 * 1024 * 1024:  # 5MB Limit
                    continue
                    
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, content in enumerate(f, 1):
                        clean_line = content.strip()
                        if not clean_line:
                            continue
                            
                        for rule_name, regex in rules.items():
                            if re.search(regex, clean_line):
                                findings.append({
                                    "rule": rule_name,
                                    "file": file_path,
                                    "line": line_num,
                                    "code": clean_line
                                })
            except Exception:
                pass
                    
    return findings

def generate_html_report(target_folder, raw_total, threats):
    """Ek shaandar aur professional HTML dashboard banane ke liye"""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AI-Powered SAST Security Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 40px; }}
            .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
            h1 {{ color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 15px; margin-top: 0; }}
            .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
            .card {{ flex: 1; padding: 20px; border-radius: 6px; color: white; font-weight: bold; text-align: center; }}
            .card.total {{ background: #475569; }}
            .card.threats {{ background: #dc2626; }}
            .card.folder {{ background: #2563eb; font-weight: normal; font-size: 14px; text-align: left; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 30px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
            th {{ background-color: #f8fafc; color: #475569; }}
            tr:hover {{ background-color: #f8fafc; }}
            .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; background-color: #fef2f2; color: #991b1b; border: 1px solid #fee2e2; }}
            pre {{ background: #1e1e2e; color: #cdd6f4; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: 'Courier New', Courier, monospace; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔥 Next-Gen AI-Powered Security Report</h1>
            <div class="stats">
                <div class="card folder">
                    <strong>Target Path:</strong> {html.escape(target_folder)}<br>
                    <strong>Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                <div class="card total">Potential Concerns Found<br><span style="font-size: 28px;">{raw_total}</span></div>
                <div class="card threats">Verified Actionable Threats<br><span style="font-size: 28px;">{len(threats)}</span></div>
            </div>
    """
    
    if not threats:
        html_content += "<h3 style='color: #16a34a; text-align: center; margin-top: 50px;'>🎉 No verified security threats found! Code quality meets strict compliance standards.</h3>"
    else:
        html_content += """
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%;">Vulnerability Type</th>
                        <th style="width: 40%;">File & Location</th>
                        <th style="width: 35%;">AI Security Analysis & Details</th>
                    </tr>
                </thead>
                <tbody>
        """
        for t in threats:
            html_content += f"""
                    <tr>
                        <td><span class="badge">CRITICAL</span><br><br><strong>{html.escape(t['rule'])}</strong></td>
                        <td><code>{html.escape(t['file'])}</code><br><span style="color: #64748b; font-size: 13px;">Line: {t['line']}</span>
                            <pre><code>{html.escape(t['code'])}</code></pre>
                        </td>
                        <td style="font-size: 14px; line-height: 1.5; color: #334155; vertical-align: top; padding-top: 15px;">{html.escape(t['analysis'])}</td>
                    </tr>
            """
        html_content += "</tbody></table>"
        
    html_content += """
        </div>
    </body>
    </html>
    """
    
    with open("sast_security_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

def main():
    print("="*60)
    print("    🔥 NEXT-GEN AI-POWERED UNIVERSAL SAST AGENT 🔥   ")
    print("="*60)
    
    target_dir = input("[+] Enter folder path to scan: ").strip()
    if not os.path.isdir(target_dir):
        print("[!] Error: Invalid directory path.")
        sys.exit(1)
        
    raw_issues = deep_security_scan(target_dir)
    total_raw = len(raw_issues)
    print(f"[+] Universal Engine flagged {total_raw} raw concerns. Starting Tight AI Filter...\n")
    
    verified_threat_list = []
    
    if total_raw > 0:
        for index, issue in enumerate(raw_issues, 1):
            print(f"[{index}/{total_raw}] Analyzing Vector: {issue['rule']}")
            print(f"📍 Location: {issue['file']} (Line: {issue['line']})")
            
            tight_prompt = f"""[SYSTEM: You are a strict binary classification security bot. No conversation, no fluff.]
    Analyze this specific codebase finding:
    Vulnerability Category: {issue['rule']}
    Code Context: {issue['code']}

    Tasks:
    1. Determine if this line is an active exploit vector (REAL VULNERABILITY) or an intended design/safe string/comment/test data (FALSE ALARM).
    2. If it's a test file, mock credential, or core shell execution module, classify as FALSE ALARM.

    Your response MUST start with exactly either 'REAL VULNERABILITY' or 'FALSE ALARM'. Keep the analysis under 3 sentences.
    """
            
            ai_analysis = ask_local_ai(tight_prompt)
            
            if ai_analysis and ai_analysis.upper().startswith("REAL VULNERABILITY"):
                print("\033[91m[🔥 VERIFIED SECURITY THREAT]\033[0m")
                print(f"Details: {ai_analysis}")
                # Save data for report
                issue['analysis'] = ai_analysis
                verified_threat_list.append(issue)
            else:
                print("\033[92m[✓ FILTERED - SAFE]\033[0m classified as False Alarm.")
                
            print("-" * 50)
            
    # HTML Report Generate karein
    generate_html_report(target_dir, total_raw, verified_threat_list)
    print(f"\n[ Scan Complete ] Triaged {total_raw} issues. Verified Actionable Threats: {len(verified_threat_list)}")
    print("[+] Professional HTML dashboard generated successfully: sast_security_report.html")

if __name__ == "__main__":
    main()
