import sqlite3
import uuid
from pathlib import Path

import pytest

from guardian_sdk import enable
from guardian_sdk.config import GuardianConfig
from guardian_sdk.monitor import GuardianBlocked


def _make_local_scratch_dir() -> Path:
    scratch_dir = Path(__file__).resolve().parent / ".tmp" / uuid.uuid4().hex
    scratch_dir.mkdir(parents=True, exist_ok=True)
    return scratch_dir


def test_enable_accepts_mode_keyword():
    log_path = _make_local_scratch_dir() / "security.log"

    monitor = enable(service_name="python-test-app", log_path=str(log_path), mode="block")

    assert monitor.config.service_name == "python-test-app"
    assert monitor.config.log_path == str(log_path)
    assert monitor.config.mode == "block"


def test_block_mode_blocks_sqli_and_logs_blocked_verdict():
    log_path = _make_local_scratch_dir() / "security.log"

    enable(service_name="python-test-app", log_path=str(log_path), mode="block")

    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    with pytest.raises(GuardianBlocked):
        cur.execute("SELECT * FROM users WHERE username = '' OR 'a'='a' --")

    contents = log_path.read_text(encoding="utf-8")
    assert "verdict=BLOCKED" in contents
    assert "category=sql_injection" in contents


def test_ingest_url_is_normalized_from_env(monkeypatch):
    monkeypatch.setenv("GUARDIAN_INGEST_URL", "http://127.0.0.1:8000/")

    cfg = GuardianConfig.from_env()

    assert cfg.ingest_url == "http://127.0.0.1:8000/v1/telemetry"


def test_ingest_url_keeps_full_telemetry_endpoint(monkeypatch):
    monkeypatch.setenv("GUARDIAN_INGEST_URL", "http://127.0.0.1:8000/v1/telemetry/")

    cfg = GuardianConfig.from_env()

    assert cfg.ingest_url == "http://127.0.0.1:8000/v1/telemetry"
