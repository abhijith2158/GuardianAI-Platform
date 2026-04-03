from __future__ import annotations

import ast
import os
import sys
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


DB_EXEC_ATTRS = {"execute", "executemany"}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    col: int
    rule: str
    message: str
    snippet: str = ""


def _iter_src_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".venv", "venv", "__pycache__", ".git", "node_modules"}]
        for fn in filenames:
            if fn.endswith(".py") or fn.endswith(".js"):
                yield os.path.join(dirpath, fn)


def _is_string_literal(n: ast.AST) -> bool:
    if isinstance(n, ast.Constant) and isinstance(n.value, str):
        return True
    return False


def _is_param_container(n: ast.AST) -> bool:
    return isinstance(n, (ast.Tuple, ast.List, ast.Dict, ast.Name))


def _is_query_built_expr(n: ast.AST) -> bool:
    # Heuristic: anything other than a literal string is "built".
    if _is_string_literal(n):
        return False
    # f-strings or string concat/formatting are especially risky.
    if isinstance(n, ast.JoinedStr):
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
        return True
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
        return True
    return True


def _looks_like_user_input_call(n: ast.AST) -> bool:
    # input()
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "input":
        return True
    # request.args.get(...) / request.form.get(...)
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
        # x = input()  OR  x = request.args.get(...)
        if _looks_like_user_input_call(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._tainted.add(t.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and _looks_like_user_input_call(node.value):
            if isinstance(node.target, ast.Name):
                self._tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Detect cursor.execute(...) / conn.execute(...)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in DB_EXEC_ATTRS:
            self._analyze_db_execute(node, func)
        self.generic_visit(node)

    def _analyze_db_execute(self, node: ast.Call, func_attr: ast.Attribute) -> None:
        if not node.args:
            return
        query = node.args[0]
        params = node.args[1] if len(node.args) >= 2 else None

        built = _is_query_built_expr(query)
        has_params = params is not None and _is_param_container(params)

        # Taint propagation (shallow): if query references tainted vars, flag harder.
        query_names = _names_used(query)
        uses_taint = bool(query_names & self._tainted)

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

        # Also warn when f-string is used even with params (usually indicates interpolation happened already).
        if isinstance(query, ast.JoinedStr):
            self._add(
                node,
                rule="SQLI.AST.FSTRING",
                message="Risky SQL construction: f-string used to build query (prefer placeholders + parameters).",
            )


def _scan_js(path: str, src: str) -> List[Finding]:
    findings = []
    lines = src.splitlines()
    # Simple regex to catch template literals in queries
    # e.g., `SELECT * FROM users WHERE username = '${username}'`
    # We look for SELECT/UPDATE/INSERT/DELETE with ${...}
    pattern = re.compile(r"(SELECT|UPDATE|INSERT|DELETE).*?\$\{.*?\}", re.IGNORECASE)
    for i, line in enumerate(lines):
        if pattern.search(line):
            findings.append(
                Finding(
                    path=path,
                    line=i + 1,
                    col=0,
                    rule="SQLI.JS.TEMPLATE_INJECTION",
                    message="Potential SQL injection: Unparameterized template literal used in SQL query.",
                    snippet=line.strip()
                )
            )
    return findings


def scan_path(root: str) -> List[Finding]:
    findings: List[Finding] = []
    for path in _iter_src_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError:
            continue
            
        if path.endswith(".js"):
            findings.extend(_scan_js(path, src))
            continue
            
        try:
            tree = ast.parse(src, filename=path)
        except SyntaxError:
            continue
        s = Scanner(path, src)
        s.visit(tree)
        findings.extend(s.findings)
    return findings


def main(argv: Sequence[str]) -> int:
    if len(argv) < 2:
        print("Usage: python scanner.py <path>")
        return 2
    root = argv[1]
    if not os.path.exists(root):
        print(f"Path not found: {root}")
        return 2

    findings = scan_path(root)
    if not findings:
        print("No findings.")
        return 0

    for f in findings:
        loc = f"{f.path}:{f.line}:{f.col}"
        print(f"{loc} [{f.rule}] {f.message}")
        if f.snippet:
            print(f"  {f.snippet}")
    print(f"\nTotal: {len(findings)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

