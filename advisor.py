import os
import sys
import json
import urllib.request
import argparse
from datetime import datetime
from scanner import scan_path, Finding

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2") 

# Fallback recommendations if Ollama is unreachable
FALLBACK_ADVICE = {
    "SQLI.AST.TAINTED_NONPARAM": "Use parameterized queries immediately. Do not concatenate strings or use f-strings directly into database execution methods.",
    "SQLI.AST.NONPARAM": "Use parameterized queries. Ensure inputs bind to placeholders rather than substituting string variables.",
    "SQLI.AST.FSTRING": "Remove f-strings from query strings. Use `?` for sqlite3 or `%s` for psycopg2/mysql.",
    "SQLI.JS.TEMPLATE_INJECTION": "Use parameterized queries or ORMs. Never pass unescaped user input inside a template literal query string.",
}

# Severity definitions mapping for CI/CD gates
RULE_SEVERITY = {
    "SQLI.AST.TAINTED_NONPARAM": 9,
    "SQLI.AST.NONPARAM": 8,
    "SQLI.AST.FSTRING": 6,
    "SQLI.JS.TEMPLATE_INJECTION": 9,
}

def generate_roadmap_fallback(findings):
    lines = ["# Security Hardening Roadmap (Rule-based Fallback)", ""]
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Findings Count:** {len(findings)}\n")
    
    for f in findings:
        lines.append(f"### Finding at `{f.path}:{f.line}`")
        lines.append(f"- **Rule:** `{f.rule}`")
        lines.append(f"- **Message:** {f.message}")
        if f.snippet:
            lines.append(f"- **Snippet:** `{f.snippet}`")
        advice = FALLBACK_ADVICE.get(f.rule, "Review the code block and ensure secure design patterns.")
        lines.append(f"- **Remediation Advice:** {advice}\n")
        
    return "\n".join(lines)

def query_ollama(findings):
    summary = "\n".join([f"Path: {f.path}:{f.line} Rule: {f.rule} Snippet: {f.snippet}" for f in findings])
    # Hybrid Ollama generation acting as Senior Security Mentor
    prompt = f"""You are a Senior Security Mentor and DevSecOps expert. 
Review the following code vulnerabilities caught by GuardianAI's Static Analyzer.
Provide a professional, educational "Security Hardening Roadmap" for the developer.
Explain the vulnerabilities clearly and provide code-level remediation steps for each finding.
Make sure to emphasize the difference between concatenation and parameterized binding.

Findings:
{summary}
"""
    
    url = f"{OLLAMA_HOST}/api/generate"
    data = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "options": {"temperature": 0.2}}
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
    
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode('utf-8'))
            return f"# AI Security Hardening Roadmap\n\n{result.get('response', '')}"
    except Exception as e:
        print(f"Ollama AI Mentor unreachable ({e}). Falling back to rule-based advice.")
        return None

def main():
    parser = argparse.ArgumentParser(description="GuardianAI Security Advisor")
    parser.add_argument("target_path", help="Path to scan for vulnerabilities")
    parser.add_argument("--ci", action="store_true", help="Run in CI mode and fail build on high severity issues")
    args = parser.parse_args()
    
    target_path = args.target_path
    
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        
    print(f"Running GuardianAI AST Scanner on {target_path}...")
    findings = scan_path(target_path)
    
    max_severity = 0
    if not findings:
        print("No vulnerabilities found. System is secure.")
        roadmap = "# Security Hardening Roadmap\n\nNo vulnerabilities found! Great job."
    else:
        print(f"Scan complete. Found {len(findings)} issues. Calling AI Mentor...")
        
        # Determine highest severity for CI checks
        for f in findings:
            sev = RULE_SEVERITY.get(f.rule, 5)  # Default moderate
            if sev > max_severity:
                max_severity = sev
                
        roadmap = query_ollama(findings)
        if not roadmap:
            roadmap = generate_roadmap_fallback(findings)
            
    out_file = os.path.join(REPORTS_DIR, f"security_roadmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(roadmap)
        
    print(f"Roadmap generated successfully: {out_file}")
    
    if args.ci and max_severity > 7:
        print(f"\n[!] CI Gate Failed: Found High Severity vulnerabilities (Max: {max_severity} > 7).")
        print("    High Severity Findings Summary:")
        for f in findings:
            if RULE_SEVERITY.get(f.rule, 5) > 7:
                print(f"      - {f.path}:{f.line} [{f.rule}]")
                if f.snippet:
                    print(f"        Code: {f.snippet.strip()}")
        print(f"\n[!] Please check the generated roadmap for full remediation steps: {out_file}")
        sys.exit(1)
    elif args.ci:
        print(f"\n[+] CI Gate Passed: Max severity is {max_severity}. No critical blockers.")

if __name__ == "__main__":
    main()
