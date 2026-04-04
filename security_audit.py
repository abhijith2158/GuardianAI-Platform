from __future__ import annotations

import argparse
import json
import os
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from scanner import DEFAULT_RULES_PATH, Finding, load_custom_rules, scan_path


REPORTS_DIR = Path(__file__).resolve().parent / "reports"
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

FALLBACK_ADVICE = {
    "SQLI.AST.TAINTED_NONPARAM": "Use parameterized queries immediately. Do not concatenate strings or inject variables directly into database execution methods.",
    "SQLI.AST.NONPARAM": "Use placeholders and parameter binding so user-controlled values never become part of the SQL string itself.",
    "SQLI.AST.FSTRING": "Remove f-strings from query construction. Build a constant query and pass values separately as bound parameters.",
    "SQLI.JS.TEMPLATE_INJECTION": "Use parameterized queries or an ORM query builder. Never interpolate user input inside SQL template literals.",
}

RULE_SEVERITY = {
    "SQLI.AST.TAINTED_NONPARAM": 9,
    "SQLI.AST.NONPARAM": 8,
    "SQLI.AST.FSTRING": 6,
    "SQLI.JS.TEMPLATE_INJECTION": 9,
}


@dataclass(frozen=True)
class AuditResult:
    findings: list[Finding]
    markdown_report: str
    cli_report: str
    markdown_path: Path
    cli_path: Path
    pdf_path: Path
    max_severity: int
    ollama_used: bool


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _slug_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _chunk_lines(text: str, width: int = 92) -> list[str]:
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            lines.append("")
            continue
        while len(line) > width:
            lines.append(line[:width])
            line = line[width:]
        lines.append(line)
    return lines or [""]


def _write_basic_pdf(path: Path, title: str, body: str) -> None:
    lines = [title, ""] + _chunk_lines(body)
    page_height = 792
    start_y = 760
    line_height = 14
    lines_per_page = 48

    pages: list[str] = []
    for start in range(0, len(lines), lines_per_page):
        chunk = lines[start : start + lines_per_page]
        content_lines = ["BT", "/F1 11 Tf", "72 760 Td"]
        first = True
        for line in chunk:
            safe_line = _escape_pdf_text(line)
            if first:
                content_lines.append(f"({safe_line}) Tj")
                first = False
            else:
                content_lines.append(f"0 -{line_height} Td ({safe_line}) Tj")
        content_lines.append("ET")
        pages.append("\n".join(content_lines))

    objects: list[str] = []
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{4 + idx * 2} 0 R" for idx in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for idx, content in enumerate(pages):
        page_obj_num = 4 + idx * 2
        content_obj_num = page_obj_num + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 {page_height}] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj_num} 0 R >>"
        )
        encoded = content.encode("latin-1", errors="replace")
        objects.append(f"<< /Length {len(encoded)} >>\nstream\n{content}\nendstream")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n{obj}\nendobj\n".encode("latin-1", errors="replace"))
    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF".encode("latin-1")
    )
    path.write_bytes(pdf)


def is_ollama_available() -> bool:
    probe_url = f"{OLLAMA_HOST}/api/tags"
    req = urllib.request.Request(probe_url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=1) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def _custom_rule_advice() -> str:
    return "Review the matched pattern, validate whether the hit is expected, and either remediate the risky code path or refine the custom rule."


def _rule_severity_map(rules_path: str | None) -> dict[str, int]:
    merged = dict(RULE_SEVERITY)
    for rule in load_custom_rules(rules_path):
        merged[rule.rule_id] = int(rule.severity)
    return merged


def generate_roadmap_fallback(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    lines = [
        "# GuardianAI Security Hardening Roadmap",
        "",
        "## Executive Summary",
        f"- Generated: {_timestamp()}",
        f"- Findings Count: {len(findings)}",
        "- Analysis Mode: Local rule-first audit",
        "",
    ]

    if not findings:
        lines.extend(
            [
                "## Outcome",
                "No high-confidence rule matches were detected in this scan. Continue to run GuardianAI in CI and before releases to catch regressions early.",
            ]
        )
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for finding in findings:
        advice = FALLBACK_ADVICE.get(finding.rule, _custom_rule_advice())
        lines.append(f"### `{finding.rule}` at `{finding.path}:{finding.line}`")
        lines.append(f"- Message: {finding.message}")
        if finding.snippet:
            lines.append(f"- Snippet: `{finding.snippet}`")
        lines.append(f"- Recommended Remediation: {advice}")
        lines.append("")

    lines.extend(
        [
            "## Next Actions",
            "1. Fix the highest-severity findings first and rerun the audit locally.",
            "2. Add regression tests around the vulnerable path so the same issue cannot silently return.",
            "3. Keep `guardian_rules.yaml` under version control for team-wide custom coverage.",
        ]
    )
    return "\n".join(lines)


def query_ollama(findings: Iterable[Finding]) -> str | None:
    try:
        findings = list(findings)
        if not findings or not is_ollama_available():
            return None

        summary = "\n".join(
            f"Path: {finding.path}:{finding.line} Rule: {finding.rule} Snippet: {finding.snippet}"
            for finding in findings
        )
        prompt = f"""You are a Senior Security Mentor and DevSecOps expert.
Review the following code vulnerabilities caught by GuardianAI's local rule-first analyzer.
Provide a concise remediation addendum with code-level guidance.
Focus on practical fixes, secure coding patterns, and rollout advice.

Findings:
{summary}
"""

        url = f"{OLLAMA_HOST}/api/generate"
        data = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
            response_text = str(result.get("response", "")).strip()
            if not response_text:
                return None
            return "## AI Mentor Addendum\n\n" + response_text
    except Exception:
        return None


def _build_cli_report(findings: list[Finding], severity_map: dict[str, int], ollama_used: bool) -> str:
    lines = [
        "GuardianAI Security Audit",
        f"Generated: {_timestamp()}",
        f"Mode: rule-first local audit{' + Ollama addendum' if ollama_used else ''}",
        f"Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No rule matches detected.")
        return "\n".join(lines)

    for finding in findings:
        severity = severity_map.get(finding.rule, 5)
        lines.append(f"[sev={severity}] {finding.path}:{finding.line}:{finding.col} {finding.rule}")
        lines.append(f"  {finding.message}")
        if finding.snippet:
            lines.append(f"  {finding.snippet}")
    return "\n".join(lines)


def _write_reports(markdown_report: str, cli_report: str) -> tuple[Path, Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"security_roadmap_{_slug_timestamp()}"
    markdown_path = REPORTS_DIR / f"{stem}.md"
    cli_path = REPORTS_DIR / f"{stem}.txt"
    pdf_path = REPORTS_DIR / f"{stem}.pdf"

    markdown_path.write_text(markdown_report, encoding="utf-8")
    cli_path.write_text(cli_report, encoding="utf-8")
    _write_basic_pdf(pdf_path, "GuardianAI Security Audit", cli_report)
    return markdown_path, cli_path, pdf_path


def run_audit(target_path: str, *, ci: bool = False, rules_path: str | None = DEFAULT_RULES_PATH) -> AuditResult:
    findings = scan_path(target_path, rules_path=rules_path)
    severity_map = _rule_severity_map(rules_path)
    max_severity = max((severity_map.get(finding.rule, 5) for finding in findings), default=0)

    markdown_report = generate_roadmap_fallback(findings)
    ai_addendum = query_ollama(findings)
    ollama_used = ai_addendum is not None
    if ai_addendum:
        markdown_report = f"{markdown_report}\n\n{ai_addendum}\n"

    cli_report = _build_cli_report(findings, severity_map, ollama_used)
    markdown_path, cli_path, pdf_path = _write_reports(markdown_report, cli_report)

    return AuditResult(
        findings=findings,
        markdown_report=markdown_report,
        cli_report=cli_report,
        markdown_path=markdown_path,
        cli_path=cli_path,
        pdf_path=pdf_path,
        max_severity=max_severity,
        ollama_used=ollama_used,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GuardianAI Security Audit")
    parser.add_argument("target_path", help="Path to scan for vulnerabilities")
    parser.add_argument("--ci", action="store_true", help="Fail when high-severity rule matches are found")
    parser.add_argument(
        "--rules",
        default=DEFAULT_RULES_PATH,
        help="Path to guardian_rules.yaml for custom regex checks",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.target_path):
        print(f"Path not found: {args.target_path}")
        return 2

    print(f"Running GuardianAI rule-first scan on {args.target_path}...")
    result = run_audit(args.target_path, ci=args.ci, rules_path=args.rules)
    severity_map = _rule_severity_map(args.rules)

    if result.findings:
        print(f"Scan complete. Found {len(result.findings)} issues.")
    else:
        print("Scan complete. No vulnerabilities found.")

    if result.ollama_used:
        print("Ollama detected at localhost:11434. AI mentor addendum appended.")
    else:
        print("Ollama not detected. Generated professional local-only reports.")

    print(f"Markdown report: {result.markdown_path}")
    print(f"CLI report: {result.cli_path}")
    print(f"PDF report: {result.pdf_path}")

    if args.ci and result.max_severity > 7:
        print(f"\n[!] CI Gate Failed: High-severity findings detected (max severity {result.max_severity}).")
        for finding in result.findings:
            if severity_map.get(finding.rule, 5) > 7:
                print(f"  - {finding.path}:{finding.line} [{finding.rule}]")
        return 1

    if args.ci:
        print(f"\n[+] CI Gate Passed: Max severity {result.max_severity}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
