import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add root folder to sys.path so the audit modules can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import security_audit
from scanner import Finding, scan_path


def _make_local_scratch_dir() -> Path:
    scratch_dir = Path(__file__).resolve().parent / ".tmp" / uuid.uuid4().hex
    scratch_dir.mkdir(parents=True, exist_ok=True)
    return scratch_dir

def test_fallback_roadmap_generation():
    findings = [
        Finding(
            path="foo.py",
            line=10,
            col=5,
            rule="SQLI.AST.TAINTED_NONPARAM",
            message="Test message",
            snippet="x = 1"
        )
    ]
    
    roadmap = security_audit.generate_roadmap_fallback(findings)
    assert "Findings Count: 1" in roadmap
    assert "`foo.py:10`" in roadmap
    assert "Test message" in roadmap
    assert "Use parameterized queries immediately" in roadmap

@patch("security_audit.is_ollama_available", return_value=True)
@patch("security_audit.urllib.request.urlopen")
def test_ollama_query_success(mock_urlopen, _mock_ollama):
    # Mock the HTTP response from Ollama
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"response": "Here is the AI advice."}'
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp
    
    findings = [
        Finding(path="bar.py", line=20, col=0, rule="XSS", message="msg", snippet="foo")
    ]
    
    roadmap = security_audit.query_ollama(findings)
    assert "AI Mentor Addendum" in roadmap
    assert "Here is the AI advice." in roadmap

@patch("security_audit.is_ollama_available", return_value=True)
@patch("security_audit.urllib.request.urlopen")
def test_ollama_query_failure(mock_urlopen, _mock_ollama):
    mock_urlopen.side_effect = Exception("Connection refused")
    findings = []
    
    roadmap = security_audit.query_ollama(findings)
    assert roadmap is None


def test_custom_rules_are_applied():
    tmp_path = _make_local_scratch_dir()
    target = tmp_path / "sample.py"
    target.write_text("api_key = 'abcd1234SECRET'\n", encoding="utf-8")
    rules = tmp_path / "guardian_rules.yaml"
    rules.write_text(
        """
rules:
  - id: CUSTOM.TEST.SECRET
    message: Test custom secret rule.
    pattern: "SECRET"
    severity: 7
    file_extensions:
      - ".py"
""".strip(),
        encoding="utf-8",
    )

    findings = scan_path(str(tmp_path), rules_path=str(rules))
    assert any(f.rule == "CUSTOM.TEST.SECRET" for f in findings)


def test_run_audit_creates_reports_without_ollama(monkeypatch):
    tmp_path = _make_local_scratch_dir()
    target = tmp_path / "app.py"
    target.write_text(
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )
    rules = tmp_path / "guardian_rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    reports_dir = tmp_path / "reports"
    monkeypatch.setattr(security_audit, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(security_audit, "is_ollama_available", lambda: False)

    result = security_audit.run_audit(str(tmp_path), rules_path=str(rules))

    assert result.ollama_used is False
    assert result.markdown_path.exists()
    assert result.cli_path.exists()
    assert result.pdf_path.exists()
    assert "Connection refused" not in result.markdown_report
    assert "Connection refused" not in result.cli_report
