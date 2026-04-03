import sys
import os
import pytest
from unittest.mock import patch, MagicMock

# Add root folder to sys.path so advisor can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import advisor
from scanner import Finding

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
    
    roadmap = advisor.generate_roadmap_fallback(findings)
    assert "**Findings Count:** 1" in roadmap
    assert "`foo.py:10`" in roadmap
    assert "Test message" in roadmap
    assert "Use parameterized queries immediately" in roadmap

@patch('advisor.urllib.request.urlopen')
def test_ollama_query_success(mock_urlopen):
    # Mock the HTTP response from Ollama
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"response": "Here is the AI advice."}'
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp
    
    findings = [
        Finding(path="bar.py", line=20, col=0, rule="XSS", message="msg", snippet="foo")
    ]
    
    roadmap = advisor.query_ollama(findings)
    assert "AI Security Hardening Roadmap" in roadmap
    assert "Here is the AI advice." in roadmap

@patch('advisor.urllib.request.urlopen')
def test_ollama_query_failure(mock_urlopen):
    mock_urlopen.side_effect = Exception("Connection refused")
    findings = []
    
    roadmap = advisor.query_ollama(findings)
    assert roadmap is None
