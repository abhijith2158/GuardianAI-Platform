from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from psycopg2.extras import Json, RealDictCursor
from psycopg2.pool import SimpleConnectionPool


def _resolve_database_url() -> str | None:
    return (
        os.getenv("SUPABASE_DB_URL")
        or os.getenv("SUPABASE_DATABASE_URL")
        or os.getenv("DATABASE_URL")
    )


DATABASE_URL = _resolve_database_url()
MASTER_API_KEY = os.getenv("GUARDIAN_MASTER_API_KEY")
db_lock = threading.Lock()
db_pool: SimpleConnectionPool | None = None
POOL_MIN_CONN = int(os.getenv("GUARDIAN_DB_POOL_MIN", "1"))
POOL_MAX_CONN = int(os.getenv("GUARDIAN_DB_POOL_MAX", "5"))
DB_RETRY_ATTEMPTS = int(os.getenv("GUARDIAN_DB_RETRY_ATTEMPTS", "3"))
DB_RETRY_DELAY_SECONDS = int(os.getenv("GUARDIAN_DB_RETRY_DELAY_SECONDS", "2"))

DEFAULT_POLICY = {
    "mode": os.getenv("GUARDIAN_POLICY_MODE", "block"),
    "enabled": os.getenv("GUARDIAN_POLICY_ENABLED", "1").strip() not in {"0", "false", "False"},
    "severity_threshold": int(os.getenv("GUARDIAN_POLICY_SEVERITY_THRESHOLD", "7")),
}

try:
    SERVICE_POLICIES = json.loads(os.getenv("GUARDIAN_SERVICE_POLICIES", "{}"))
except json.JSONDecodeError:
    SERVICE_POLICIES = {}

logging.basicConfig(
    level=os.getenv("GUARDIAN_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("guardian.api")


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


class RegisterDeveloperPayload(BaseModel):
    email: str


class DeveloperRecord(BaseModel):
    id: int
    email: str
    api_key: str


class DatabaseUnavailableError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat(timespec="seconds")


def _mask_api_key(api_key: str | None) -> str:
    if not api_key:
        return "<missing>"
    if len(api_key) <= 8:
        return "*" * len(api_key)
    return f"{api_key[:4]}...{api_key[-4:]}"


def _log_unauthorized_access(scope: str, api_key: str | None, reason: str) -> None:
    logger.warning(
        "Unauthorized Access scope=%s api_key=%s reason=%s",
        scope,
        _mask_api_key(api_key),
        reason,
    )


def _database_error_response() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Service temporarily unavailable. Please retry shortly.",
    )


def _unauthorized_response() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized request.",
    )


def _init_db_pool() -> None:
    global db_pool

    if not DATABASE_URL:
        logger.error("Database init skipped: configure SUPABASE_DB_URL or DATABASE_URL.")
        return

    last_error: Exception | None = None
    for attempt in range(1, DB_RETRY_ATTEMPTS + 1):
        try:
            with db_lock:
                if db_pool is None:
                    db_pool = SimpleConnectionPool(
                        POOL_MIN_CONN,
                        POOL_MAX_CONN,
                        DATABASE_URL,
                    )
            logger.info("Database pool initialized on attempt %s.", attempt)
            return
        except Exception as exc:
            last_error = exc
            logger.warning("Database pool init attempt %s failed: %s", attempt, exc)
            if attempt < DB_RETRY_ATTEMPTS:
                time.sleep(DB_RETRY_DELAY_SECONDS)

    logger.error("Database connection/init failed after %s attempts: %s", DB_RETRY_ATTEMPTS, last_error)


def _get_pooled_connection():
    if db_pool is None:
        raise DatabaseUnavailableError("database pool is unavailable")

    last_error: Exception | None = None
    for attempt in range(1, DB_RETRY_ATTEMPTS + 1):
        try:
            return db_pool.getconn()
        except Exception as exc:
            last_error = exc
            logger.warning("Database connection acquisition attempt %s failed: %s", attempt, exc)
            if attempt < DB_RETRY_ATTEMPTS:
                time.sleep(DB_RETRY_DELAY_SECONDS)

    raise DatabaseUnavailableError("database unavailable")


def _release_pooled_connection(conn) -> None:
    if conn is None or db_pool is None:
        return
    try:
        db_pool.putconn(conn)
    except Exception as exc:
        logger.warning("Database connection release failed: %s", exc)


def _ensure_db() -> None:
    conn = None
    try:
        conn = _get_pooled_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS developers (
                    id BIGSERIAL PRIMARY KEY,
                    api_key TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id BIGSERIAL PRIMARY KEY,
                    developer_id BIGINT NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
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
                CREATE INDEX IF NOT EXISTS idx_security_events_created_at
                ON security_events (created_at DESC)
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_security_events_developer_created
                ON security_events (developer_id, created_at DESC)
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_security_events_service
                ON security_events (service)
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_security_events_verdict
                ON security_events (verdict)
                """
            )
        conn.commit()
    except Exception as exc:
        logger.error("Database schema init failed: %s", exc)
        raise DatabaseUnavailableError("database initialization failed") from exc
    finally:
        _release_pooled_connection(conn)


def _probe_database() -> None:
    conn = None
    try:
        conn = _get_pooled_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    except Exception as exc:
        raise DatabaseUnavailableError("database probe failed") from exc
    finally:
        _release_pooled_connection(conn)


def _lookup_developer_by_api_key(api_key: str) -> DeveloperRecord | None:
    conn = None
    try:
        conn = _get_pooled_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, email, api_key
                FROM developers
                WHERE api_key = %s
                LIMIT 1
                """,
                (api_key,),
            )
            row = cur.fetchone()
    except Exception as exc:
        raise DatabaseUnavailableError("developer lookup failed") from exc
    finally:
        _release_pooled_connection(conn)

    if not row:
        return None
    return DeveloperRecord.model_validate(row)


def _register_developer(email: str) -> DeveloperRecord:
    conn = None
    try:
        conn = _get_pooled_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO developers (email, api_key, created_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (email) DO UPDATE
                SET email = EXCLUDED.email
                RETURNING id, email, api_key
                """,
                (email, secrets.token_urlsafe(24)),
            )
            row = cur.fetchone()
        conn.commit()
    except Exception as exc:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        raise DatabaseUnavailableError("developer registration failed") from exc
    finally:
        _release_pooled_connection(conn)

    return DeveloperRecord.model_validate(row)


def _store_event(payload: TelemetryPayload, developer_id: int) -> None:
    conn = None
    try:
        conn = _get_pooled_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_events (
                    developer_id, ts, service, env, event_type, verdict, payload, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    developer_id,
                    payload.ts,
                    payload.service,
                    payload.env,
                    payload.event_type,
                    payload.verdict,
                    Json(payload.model_dump()),
                    _utc_now(),
                ),
            )
        conn.commit()
    except Exception as exc:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        raise DatabaseUnavailableError("event persistence failed") from exc
    finally:
        _release_pooled_connection(conn)


def _read_events(limit: int, developer_id: int) -> list[dict[str, Any]]:
    conn = None
    try:
        conn = _get_pooled_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, developer_id, ts, service, env, event_type, verdict, payload, created_at
                FROM security_events
                WHERE developer_id = %s
                ORDER BY id DESC
                LIMIT %s
                """,
                (developer_id, limit),
            )
            rows = cur.fetchall()
    except Exception as exc:
        raise DatabaseUnavailableError("event retrieval failed") from exc
    finally:
        _release_pooled_connection(conn)

    return [
        {
            "id": row["id"],
            "developer_id": row["developer_id"],
            "ts": row["ts"],
            "service": row["service"],
            "env": row["env"],
            "event_type": row["event_type"],
            "verdict": row["verdict"],
            "created_at": row["created_at"],
            "payload": row["payload"],
        }
        for row in rows
    ]


def _resolve_policy(service_name: str | None) -> PolicyPayload:
    policy = dict(DEFAULT_POLICY)
    if service_name and isinstance(SERVICE_POLICIES.get(service_name), dict):
        policy.update(SERVICE_POLICIES[service_name])
    return PolicyPayload(**policy)


def _authenticate_request(api_key: str | None, *, scope: str) -> DeveloperRecord:
    if not api_key:
        _log_unauthorized_access(scope, api_key, "missing api key")
        raise _unauthorized_response()

    if scope == "policy" and MASTER_API_KEY and api_key == MASTER_API_KEY:
        return DeveloperRecord(id=0, email="guardian-master@local", api_key=api_key)

    try:
        developer = _lookup_developer_by_api_key(api_key)
    except DatabaseUnavailableError as exc:
        raise _database_error_response() from exc

    if developer is None:
        _log_unauthorized_access(scope, api_key, "unknown api key")
        raise _unauthorized_response()

    return developer


def _authenticate_admin_request(api_key: str | None) -> None:
    if not api_key or not MASTER_API_KEY or api_key != MASTER_API_KEY:
        _log_unauthorized_access("register", api_key, "invalid master key")
        raise _unauthorized_response()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db_pool()
    try:
        _ensure_db()
        logger.info("GuardianAI Command Center Active | PostgreSQL ready")
    except DatabaseUnavailableError as exc:
        logger.error("GuardianAI starting without database connectivity")
        logger.debug("Startup database exception: %s", exc)

    yield

    global db_pool
    if db_pool is not None:
        try:
            db_pool.closeall()
        except Exception as exc:
            logger.warning("Database pool shutdown failed: %s", exc)
        finally:
            db_pool = None
    logger.info("Stopping GuardianAI Ingestor...")


app = FastAPI(title="GuardianAI Ingestor", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    if db_pool is None:
        raise _database_error_response()
    try:
        _probe_database()
    except DatabaseUnavailableError as exc:
        raise _database_error_response() from exc
    return {"status": "ok", "database": "connected"}


@app.get("/v1/policy")
def get_policy(
    service_name: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> dict[str, Any]:
    _authenticate_request(x_api_key, scope="policy")
    return _resolve_policy(service_name).model_dump()


@app.get("/v1/events")
def list_events(
    limit: int = Query(default=50, ge=1, le=200),
    api_key: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> list[dict[str, Any]]:
    developer = _authenticate_request(api_key or x_api_key, scope="events")
    try:
        return _read_events(limit=limit, developer_id=developer.id)
    except DatabaseUnavailableError as exc:
        raise _database_error_response() from exc


@app.post("/v1/telemetry")
def ingest_telemetry(
    payload: TelemetryPayload,
    x_api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> dict[str, str]:
    developer = _authenticate_request(x_api_key, scope="telemetry")

    try:
        _store_event(payload, developer.id)
    except DatabaseUnavailableError as exc:
        raise _database_error_response() from exc

    if (payload.verdict or "").upper() == "BLOCKED":
        logger.warning(
            "RED ALERT developer_id=%s service=%s env=%s event_type=%s message=%s",
            developer.id,
            payload.service,
            payload.env,
            payload.event_type,
            payload.message,
        )

    return {"status": "accepted"}


@app.post("/v1/register")
def register_developer(
    payload: RegisterDeveloperPayload,
    x_api_key: str | None = Header(default=None, alias="X-API-KEY"),
) -> dict[str, str]:
    _authenticate_admin_request(x_api_key)

    try:
        developer = _register_developer(payload.email.strip().lower())
    except DatabaseUnavailableError as exc:
        raise _database_error_response() from exc

    return {
        "status": "registered",
        "email": developer.email,
        "api_key": developer.api_key,
    }


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(api_key: str | None = Query(default=None)) -> str:
    developer = _authenticate_request(api_key, scope="dashboard")
    developer_label = developer.email.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GuardianAI Dashboard</title>
  <style>
    :root {{
      --bg: #071017;
      --panel: rgba(12, 26, 34, 0.86);
      --line: rgba(80, 144, 156, 0.25);
      --text: #e4f0f4;
      --muted: #97b7bf;
      --accent: #47d7aa;
      --danger: #ff7a66;
      --warn: #f7c35f;
      --glow: rgba(71, 215, 170, 0.18);
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(71, 215, 170, 0.16), transparent 38%),
        radial-gradient(circle at top right, rgba(67, 166, 255, 0.14), transparent 30%),
        linear-gradient(180deg, #0b1d25 0%, var(--bg) 72%);
      color: var(--text);
      min-height: 100vh;
    }}
    .wrap {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 18px 52px;
    }}
    .hero {{
      display: grid;
      gap: 14px;
      margin-bottom: 24px;
      padding: 24px;
      border: 1px solid var(--line);
      border-radius: 24px;
      background: linear-gradient(180deg, rgba(12, 26, 34, 0.92), rgba(8, 18, 24, 0.9));
      box-shadow: 0 18px 45px rgba(0, 0, 0, 0.24);
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      width: fit-content;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(11, 24, 32, 0.88);
      color: var(--muted);
      font-size: 0.88rem;
    }}
    h1 {{
      margin: 0;
      font-size: clamp(2rem, 4vw, 3rem);
      letter-spacing: 0.02em;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
    }}
    .status {{
      margin-top: 6px;
      padding: 10px 14px;
      border-radius: 14px;
      background: rgba(8, 18, 24, 0.92);
      border: 1px solid var(--line);
      color: var(--warn);
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.02), 0 0 24px var(--glow);
    }}
    .table-wrap {{
      overflow: hidden;
      border-radius: 20px;
      border: 1px solid var(--line);
      background: var(--panel);
      backdrop-filter: blur(10px);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      text-align: left;
      padding: 14px 16px;
      border-bottom: 1px solid rgba(80, 144, 156, 0.14);
      vertical-align: top;
      font-size: 0.95rem;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.74rem;
    }}
    tr.blocked td:first-child {{
      border-left: 4px solid var(--danger);
    }}
    .empty {{
      padding: 30px 18px;
      color: var(--muted);
      text-align: center;
    }}
    .badge {{
      display: inline-block;
      padding: 5px 9px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
    }}
    .badge.blocked {{ background: rgba(255, 122, 102, 0.12); color: var(--danger); }}
    .badge.info {{ background: rgba(71, 215, 170, 0.12); color: var(--accent); }}
    .badge.other {{ background: rgba(247, 195, 95, 0.12); color: var(--warn); }}
    code {{
      color: #c8f5ff;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    @media (max-width: 840px) {{
      .wrap {{
        padding-inline: 12px;
      }}
      th:nth-child(4), td:nth-child(4),
      th:nth-child(6), td:nth-child(6) {{
        display: none;
      }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <span class="pill">GuardianAI v1.0 tenant feed</span>
      <h1>Live Security Events</h1>
      <p>Showing the most recent events for <strong>{developer_label}</strong>. The dashboard refreshes every 10 seconds to stay friendly to free-tier hosting.</p>
      <div class="status" id="status">Waking up server...</div>
    </section>
    <div class="table-wrap">
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
        <tbody id="events">
          <tr><td colspan="6" class="empty">Waiting for the first refresh...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
  <script>
    const statusEl = document.getElementById('status');
    const tbody = document.getElementById('events');
    const apiKey = new URLSearchParams(window.location.search).get('api_key') || '';
    let hasLoadedOnce = false;

    function verdictBadge(verdict) {{
      const value = (verdict || 'UNKNOWN').toUpperCase();
      let cls = 'other';
      if (value === 'BLOCKED') cls = 'blocked';
      if (value === 'INFO') cls = 'info';
      return `<span class="badge ${{cls}}">${{value}}</span>`;
    }}

    function setStatus(message, color) {{
      statusEl.textContent = message;
      statusEl.style.color = color;
    }}

    async function refresh() {{
      if (!apiKey) {{
        setStatus('Missing api_key in dashboard URL', '#ff7a66');
        return;
      }}

      try {{
        const res = await fetch(`/v1/events?limit=50&api_key=${{encodeURIComponent(apiKey)}}`, {{
          cache: 'no-store'
        }});

        if (res.status === 401) {{
          setStatus('Unauthorized request.', '#ff7a66');
          throw new Error('unauthorized');
        }}

        if (!res.ok) {{
          throw new Error('unavailable');
        }}

        const events = await res.json();
        hasLoadedOnce = true;
        setStatus('Live feed connected', '#47d7aa');

        if (!events.length) {{
          tbody.innerHTML = '<tr><td colspan="6" class="empty">No events yet for this developer.</td></tr>';
          return;
        }}

        tbody.innerHTML = events.map((ev) => {{
          const verdict = (ev.verdict || '').toUpperCase();
          const rowClass = verdict === 'BLOCKED' ? 'blocked' : '';
          const msg = ev.payload && ev.payload.message ? ev.payload.message : '';
          return `
            <tr class="${{rowClass}}">
              <td>${{verdictBadge(ev.verdict)}}</td>
              <td>${{ev.service}}</td>
              <td><code>${{ev.event_type}}</code></td>
              <td>${{ev.env}}</td>
              <td>${{ev.ts}}</td>
              <td>${{msg}}</td>
            </tr>
          `;
        }}).join('');
      }} catch (err) {{
        if (!hasLoadedOnce) {{
          setStatus('Waking up server...', '#f7c35f');
        }} else if (String(err.message || '') !== 'unauthorized') {{
          setStatus('Feed temporarily unavailable', '#f7c35f');
        }}
      }}
    }}

    refresh();
    setInterval(refresh, 10000);
  </script>
</body>
</html>
"""
