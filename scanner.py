from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


DB_EXEC_ATTRS = {"execute", "executemany"}
TEXT_FILE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".sql",
    ".sh",
    ".md",
    ".txt",
}
IGNORED_DIRS = {".venv", "venv", "__pycache__", ".git", "node_modules", "reports", ".pytest_cache"}
DEFAULT_RULES_PATH = "guardian_rules.yaml"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    col: int
    rule: str
    message: str
    snippet: str = ""


@dataclass(frozen=True)
class CustomRegexRule:
    rule_id: str
    message: str
    pattern: re.Pattern[str]
    severity: int = 5
    file_extensions: tuple[str, ...] = ()


def _iter_text_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            full_path = os.path.join(dirpath, fn)
            suffix = Path(fn).suffix.lower()
            if suffix in TEXT_FILE_EXTENSIONS or not suffix:
                yield full_path


def _iter_source_files(root: str) -> Iterable[str]:
    for path in _iter_text_files(root):
        if Path(path).suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx"}:
            yield path


def _is_string_literal(n: ast.AST) -> bool:
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def _is_param_container(n: ast.AST) -> bool:
    return isinstance(n, (ast.Tuple, ast.List, ast.Dict, ast.Name))


def _is_query_built_expr(n: ast.AST) -> bool:
    if _is_string_literal(n):
        return False
    if isinstance(n, ast.JoinedStr):
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
        return True
    return True


def _looks_like_user_input_call(n: ast.AST) -> bool:
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "input":
        return True
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get":
        base = n.func.value
        if isinstance(base, ast.Attribute) and base.attr in {"args", "form", "json"}:
            if isinstance(base.value, ast.Name) and base.value.id in {"request", "req"}:
                return True
    return False


def _names_used(n: ast.AST) -> Set[str]:
    names: Set[str] = set()
    for child in ast.walk(n):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _line_col_from_index(src: str, index: int) -> tuple[int, int]:
    prefix = src[:index]
    line = prefix.count("\n") + 1
    col = index - (prefix.rfind("\n") + 1 if "\n" in prefix else 0)
    return line, max(col, 0)


def _load_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def load_custom_rules(rules_path: str | None = DEFAULT_RULES_PATH) -> list[CustomRegexRule]:
    if not rules_path:
        return []
    path = Path(rules_path)
    if not path.exists() or yaml is None:
        return []

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []

    raw_rules = raw.get("rules", []) if isinstance(raw, dict) else []
    loaded: list[CustomRegexRule] = []
    for entry in raw_rules:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id") or "").strip()
        message = str(entry.get("message") or "Custom rule matched.").strip()
        pattern_text = entry.get("pattern")
        flags = entry.get("flags", "")
        extensions = tuple(str(ext).lower() for ext in entry.get("file_extensions", []) if str(ext).strip())
        if not rule_id or not pattern_text:
            continue

        re_flags = 0
        if "i" in str(flags).lower():
            re_flags |= re.IGNORECASE
        if "m" in str(flags).lower():
            re_flags |= re.MULTILINE

        try:
            compiled = re.compile(str(pattern_text), re_flags)
        except re.error:
            continue

        loaded.append(
            CustomRegexRule(
                rule_id=rule_id,
                message=message,
                pattern=compiled,
                severity=int(entry.get("severity", 5)),
                file_extensions=extensions,
            )
        )
    return loaded


class Scanner(ast.NodeVisitor):
    def __init__(self, path: str, source: str):
        self.path = path
        self.source_lines = source.splitlines()
        self.findings: List[Finding] = []
        self._tainted: Set[str] = set()

    def _add(self, node: ast.AST, *, rule: str, message: str) -> None:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        snippet = ""
        if 1 <= line <= len(self.source_lines):
            snippet = self.source_lines[line - 1].strip()
        self.findings.append(
            Finding(path=self.path, line=int(line), col=int(col), rule=rule, message=message, snippet=snippet)
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if _looks_like_user_input_call(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and _looks_like_user_input_call(node.value):
            if isinstance(node.target, ast.Name):
                self._tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in DB_EXEC_ATTRS:
            self._analyze_db_execute(node)
        self.generic_visit(node)

    def _analyze_db_execute(self, node: ast.Call) -> None:
        if not node.args:
            return

        query = node.args[0]
        params = node.args[1] if len(node.args) >= 2 else None
        built = _is_query_built_expr(query)
        has_params = params is not None and _is_param_container(params)
        uses_taint = bool(_names_used(query) & self._tainted)

        if built and not has_params:
            if uses_taint:
                self._add(
                    node,
                    rule="SQLI.AST.TAINTED_NONPARAM",
                    message="Potential SQL injection: query built from user input and executed without parameters.",
                )
            else:
                self._add(
                    node,
                    rule="SQLI.AST.NONPARAM",
                    message="Potential SQL injection: dynamic query executed without parameter binding.",
                )
            return

        if isinstance(query, ast.JoinedStr):
            self._add(
                node,
                rule="SQLI.AST.FSTRING",
                message="Risky SQL construction: f-string used to build query (prefer placeholders + parameters).",
            )


def _scan_js_template_injection(path: str, src: str) -> List[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(SELECT|UPDATE|INSERT|DELETE).*?\$\{.*?\}", re.IGNORECASE)
    for match in pattern.finditer(src):
        line, col = _line_col_from_index(src, match.start())
        snippet = src.splitlines()[line - 1].strip() if src.splitlines() and line <= len(src.splitlines()) else ""
        findings.append(
            Finding(
                path=path,
                line=line,
                col=col,
                rule="SQLI.JS.TEMPLATE_INJECTION",
                message="Potential SQL injection: unparameterized template literal used in SQL query.",
                snippet=snippet,
            )
        )
    return findings


def _scan_custom_rules(path: str, src: str, custom_rules: list[CustomRegexRule]) -> list[Finding]:
    findings: list[Finding] = []
    suffix = Path(path).suffix.lower()
    lines = src.splitlines()
    for rule in custom_rules:
        if rule.file_extensions and suffix not in rule.file_extensions:
            continue
        for match in rule.pattern.finditer(src):
            line, col = _line_col_from_index(src, match.start())
            snippet = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
            findings.append(
                Finding(
                    path=path,
                    line=line,
                    col=col,
                    rule=rule.rule_id,
                    message=rule.message,
                    snippet=snippet,
                )
            )
    return findings


def scan_path(root: str, rules_path: str | None = DEFAULT_RULES_PATH) -> List[Finding]:
    findings: List[Finding] = []
    custom_rules = load_custom_rules(rules_path)

    for path in _iter_text_files(root):
        src = _load_text(path)
        if src is None:
            continue

        findings.extend(_scan_custom_rules(path, src, custom_rules))

        suffix = Path(path).suffix.lower()
        if suffix in {".js", ".jsx", ".ts", ".tsx"}:
            findings.extend(_scan_js_template_injection(path, src))
            continue

        if suffix != ".py":
            continue

        try:
            tree = ast.parse(src, filename=path)
        except SyntaxError:
            continue
        visitor = Scanner(path, src)
        visitor.visit(tree)
        findings.extend(visitor.findings)

    findings.sort(key=lambda finding: (finding.path, finding.line, finding.col, finding.rule))
    return findings


def main(argv: Sequence[str]) -> int:
    if len(argv) < 2:
        print("Usage: python scanner.py <path> [guardian_rules.yaml]")
        return 2

    root = argv[1]
    rules_path = argv[2] if len(argv) >= 3 else DEFAULT_RULES_PATH
    if not os.path.exists(root):
        print(f"Path not found: {root}")
        return 2

    findings = scan_path(root, rules_path=rules_path)
    if not findings:
        print("No findings.")
        return 0

    for finding in findings:
        print(f"{finding.path}:{finding.line}:{finding.col} [{finding.rule}] {finding.message}")
        if finding.snippet:
            print(f"  {finding.snippet}")
    print(f"\nTotal: {len(findings)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
