from __future__ import annotations

import json
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
import psycopg2
from psycopg2.extras import Json, RealDictCursor


DATABASE_URL = os.getenv("DATABASE_URL")
EXPECTED_API_KEY = os.getenv("GUARDIAN_API_KEY", "guardian-dev-key")
_db_lock = threading.Lock()

DEFAULT_POLICY = {
    "mode": os.getenv("GUARDIAN_POLICY_MODE", "block"),
    "enabled": os.getenv("GUARDIAN_POLICY_ENABLED", "1").strip() not in {"0", "false", "False"},
    "severity_threshold": int(os.getenv("GUARDIAN_POLICY_SEVERITY_THRESHOLD", "7")),
}

try:
    SERVICE_POLICIES = json.loads(os.getenv("GUARDIAN_SERVICE_POLICIES", "{}"))
except json.JSONDecodeError:
    SERVICE_POLICIES = {}


class TelemetryPayload(BaseModel):
    ts: str
    service: str
    env: str
    event_type: str
    message: str
    severity: int = Field(default=1)
    category: str | None = None
    verdict: str | None = None
    pid: int | None = None
    host: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class PolicyPayload(BaseModel):
    mode: str = "block"
    enabled: bool = True
    severity_threshold: int = 7


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_db() -> None:
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL must be set for guardian_api.py")

    print(f"Connecting to: {DATABASE_URL[:20]}...")

    with _db_lock:
        try:
            conn = psycopg2.connect(DATABASE_URL)
            with conn.cursor() as cur:
                cur.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id BIGSERIAL PRIMARY KEY,
                    ts TIMESTAMPTZ NOT NULL,
                    service TEXT NOT NULL,
                    env TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    verdict TEXT,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_telemetry_events_created_at
                    ON telemetry_events (created_at DESC)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_telemetry_events_service
                    ON telemetry_events (service)
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_telemetry_events_verdict
                    ON telemetry_events (verdict)
                    """
                )
            conn.commit()
        except Exception as exc:
            print(f"Database connection/init failed: {exc}")
            raise
        finally:
            try:
                conn.close()
            except Exception:
                pass


def _store_event(payload: TelemetryPayload) -> None:
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL must be set for guardian_api.py")

    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO telemetry_events (ts, service, env, event_type, verdict, payload, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    payload.ts,
                    payload.service,
                    payload.env,
                    payload.event_type,
                    payload.verdict,
                    Json(payload.model_dump()),
                    _utc_iso(),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _read_events(limit: int = 50) -> list[dict[str, Any]]:
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL must be set for guardian_api.py")

    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, ts, service, env, event_type, verdict, payload, created_at
                FROM telemetry_events
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    events: list[dict[str, Any]] = []
    for row in rows:
        events.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "service": row["service"],
                "env": row["env"],
                "event_type": row["event_type"],
                "verdict": row["verdict"],
                "created_at": row["created_at"],
                "payload": row["payload"],
            }
        )
    return events


def _resolve_policy(service_name: str | None) -> PolicyPayload:
    policy = dict(DEFAULT_POLICY)
    if service_name and isinstance(SERVICE_POLICIES.get(service_name), dict):
        policy.update(SERVICE_POLICIES[service_name])
    return PolicyPayload(**policy)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Startup Logic: Ensure DB exists
    _ensure_db()
    print("GuardianAI Command Center Active | PostgreSQL ready")
    
    yield # The app runs while this is suspended
    
    # 2. Shutdown Logic (Optional): Close connections if needed
    print("Stopping GuardianAI Ingestor...")

app = FastAPI(title="GuardianAI Ingestor", version="1.1.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/policy")
def get_policy(
    service_name: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> dict[str, Any]:
    if x_api_key != EXPECTED_API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")
    return _resolve_policy(service_name).model_dump()


@app.get("/v1/events")
def list_events(
    limit: int = Query(default=50, ge=1, le=200),
    x_api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> list[dict[str, Any]]:
    if x_api_key != EXPECTED_API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")
    return _read_events(limit=limit)


@app.post("/v1/telemetry")
def ingest_telemetry(
    payload: TelemetryPayload,
    x_api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> dict[str, str]:
    if x_api_key != EXPECTED_API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")

    _store_event(payload)

    if (payload.verdict or "").upper() == "BLOCKED":
        print(
            "RED ALERT:",
            f"service={payload.service}",
            f"env={payload.env}",
            f"event_type={payload.event_type}",
            f"message={payload.message}",
        )

    return {"status": "accepted"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(api_key: str | None = Query(default=None)) -> str:
    if api_key != EXPECTED_API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")
    return """
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>GuardianAI Dashboard</title>
  <style>
    :root {
      --bg: #081218;
      --panel: #10222b;
      --line: #1f3a45;
      --text: #d7e6eb;
      --muted: #8fb0bb;
      --accent: #41d3a2;
      --danger: #ff6b57;
      --warn: #ffc857;
    }
    body {
      margin: 0;
      font-family: \"Segoe UI\", Tahoma, sans-serif;
      background: radial-gradient(circle at top, #12303c 0%, var(--bg) 55%);
      color: var(--text);
    }
    .wrap {
      max-width: 1100px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 2.2rem;
      letter-spacing: 0.03em;
    }
    p {
      margin: 0 0 24px;
      color: var(--muted);
    }
    .status {
      display: inline-block;
      margin-bottom: 18px;
      padding: 8px 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(16, 34, 43, 0.8);
      color: var(--accent);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: rgba(16, 34, 43, 0.82);
      border: 1px solid var(--line);
      border-radius: 14px;
      overflow: hidden;
    }
    th, td {
      text-align: left;
      padding: 12px 14px;
      border-bottom: 1px solid rgba(31, 58, 69, 0.7);
      vertical-align: top;
      font-size: 0.95rem;
    }
    th {
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-size: 0.78rem;
    }
    tr.blocked td:first-child {
      border-left: 4px solid var(--danger);
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
    }
    .badge.blocked { background: rgba(255, 107, 87, 0.15); color: var(--danger); }
    .badge.info { background: rgba(65, 211, 162, 0.12); color: var(--accent); }
    .badge.other { background: rgba(255, 200, 87, 0.12); color: var(--warn); }
    code {
      color: #c5f3ff;
      white-space: pre-wrap;
      word-break: break-word;
    }
    @media (max-width: 820px) {
      th:nth-child(4), td:nth-child(4),
      th:nth-child(6), td:nth-child(6) {
        display: none;
      }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"status\" id=\"status\">Connecting...</div>
    <h1>GuardianAI Live Dashboard</h1>
    <p>Streaming the most recent 50 security events from the centralized ingestor.</p>
    <table>
      <thead>
        <tr>
          <th>Verdict</th>
          <th>Service</th>
          <th>Event</th>
          <th>Environment</th>
          <th>Timestamp</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody id=\"events\"></tbody>
    </table>
  </div>
  <script>
    const statusEl = document.getElementById('status');
    const tbody = document.getElementById('events');
    const apiKey = new URLSearchParams(window.location.search).get('api_key') || '';

    function verdictBadge(verdict) {
      const value = (verdict || 'UNKNOWN').toUpperCase();
      let cls = 'other';
      if (value === 'BLOCKED') cls = 'blocked';
      if (value === 'INFO') cls = 'info';
      return `<span class=\"badge ${cls}\">${value}</span>`;
    }

    async function refresh() {
      try {
        const res = await fetch('/v1/events?limit=50', {
          cache: 'no-store',
          headers: { 'X-API-KEY': apiKey }
        });
        if (!res.ok) {
          throw new Error('unauthorized');
        }
        const events = await res.json();
        statusEl.textContent = 'Live feed connected';
        statusEl.style.color = '#41d3a2';
        tbody.innerHTML = events.map((ev) => {
          const verdict = (ev.verdict || '').toUpperCase();
          const rowClass = verdict === 'BLOCKED' ? 'blocked' : '';
          const msg = ev.payload && ev.payload.message ? ev.payload.message : '';
          return `
            <tr class=\"${rowClass}\">
              <td>${verdictBadge(ev.verdict)}</td>
              <td>${ev.service}</td>
              <td><code>${ev.event_type}</code></td>
              <td>${ev.env}</td>
              <td>${ev.ts}</td>
              <td>${msg}</td>
            </tr>
          `;
        }).join('');
      } catch (err) {
        statusEl.textContent = apiKey ? 'Feed unavailable' : 'Missing api_key in dashboard URL';
        statusEl.style.color = '#ff6b57';
      }
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"""
