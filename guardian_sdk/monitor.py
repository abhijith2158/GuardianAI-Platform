from __future__ import annotations

import functools
import io
import os
import sqlite3
import sys
import time
import traceback
from dataclasses import dataclass, replace
from urllib.parse import urlsplit
from typing import Any, Optional, TypeVar, cast

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    import flask  # type: ignore
except Exception:  # pragma: no cover
    flask = None  # type: ignore

from .config import GuardianConfig
from .detectors import Detection, clamp_severity, detect_sqli, detect_ssrf
from .telemetry import Telemetry


T = TypeVar("T")


class GuardianBlocked(RuntimeError):
    pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_str(x: Any, *, max_len: int = 500) -> str:
    try:
        s = str(x)
    except Exception:
        s = repr(x)
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    if len(s) > max_len:
        return s[:max_len] + "â€¦"
    return s


def _same_url_target(left: str, right: str) -> bool:
    try:
        l = urlsplit(left)
        r = urlsplit(right)
    except Exception:
        return left == right

    l_port = l.port or (443 if l.scheme == "https" else 80)
    r_port = r.port or (443 if r.scheme == "https" else 80)
    return (
        l.scheme == r.scheme
        and l.hostname == r.hostname
        and l_port == r_port
        and l.path == r.path
    )


def _policy_url_from_ingest(ingest_url: str) -> str | None:
    try:
        parsed = urlsplit(ingest_url)
    except Exception:
        return None

    path = parsed.path
    if path.endswith("/v1/telemetry"):
        path = path[: -len("/v1/telemetry")] + "/v1/policy"
    else:
        path = path.rstrip("/") + "/v1/policy"
    return parsed._replace(path=path, query="", fragment="").geturl()


@dataclass
class GuardianMonitor:
    config: GuardianConfig
    telemetry: Telemetry
    _enabled: bool = False
    _sqlite_patched: bool = False
    _requests_patched: bool = False
    _flask_patched: bool = False

    def enable(self) -> None:
        if self._enabled:
            return

        self._check_in_remote_policy()
        if not self.config.enabled:
            self._enabled = True
            return

        self._patch_sqlite3()
        self._patch_requests()
        self._patch_flask()
        self._enabled = True
        self.telemetry.emit(
            event_type="guardian.sdk.enabled",
            message="guardian sdk enabled",
            severity=1,
            category="sdk",
            verdict="INFO",
        )

    def _check_in_remote_policy(self) -> None:
        if not self.config.ingest_url or requests is None:
            return

        policy_url = _policy_url_from_ingest(self.config.ingest_url)
        if not policy_url:
            return

        try:
            resp = requests.get(
                policy_url,
                headers={"X-API-KEY": os.getenv("GUARDIAN_API_KEY", "")},
                params={"service_name": self.config.service_name},
                timeout=1,
            )
            if resp.status_code != 200:
                return
            payload = resp.json()
        except Exception:
            return

        self._apply_remote_policy(payload)

    def _apply_remote_policy(self, payload: dict[str, Any]) -> None:
        new_config = replace(
            self.config,
            mode=(payload.get("mode") or self.config.mode),
            enabled=payload.get("enabled", self.config.enabled),
        )
        self.config = new_config
        self.telemetry.update_config(new_config)
        print(f"GuardianAI remote policy applied: mode={new_config.mode} enabled={new_config.enabled}")

    def _patch_sqlite3(self) -> None:
        if self._sqlite_patched:
            return

        original_connect = sqlite3.connect
        telemetry = self.telemetry
        cfg = self.config

        @functools.wraps(original_connect)
        def connect_wrapper(*args: Any, **kwargs: Any):
            conn = original_connect(*args, **kwargs)
            return _SQLiteConnectionProxy(conn, telemetry=telemetry, config=cfg)

        sqlite3.connect = cast(Any, connect_wrapper)
        self._sqlite_patched = True

    def _patch_requests(self) -> None:
        if self._requests_patched:
            return
        if requests is None:
            return

        telemetry = self.telemetry
        cfg = self.config

        try:
            original = requests.sessions.Session.request
        except Exception:
            return

        @functools.wraps(original)
        def request_wrapper(self_obj, method: str, url: str, *args: Any, **kwargs: Any):
            if cfg.ingest_url and _same_url_target(url, cfg.ingest_url):
                return original(self_obj, method, url, *args, **kwargs)
            det = detect_ssrf(url)
            if det:
                _emit_detection(
                    telemetry,
                    cfg,
                    det,
                    event_type="guardian.rasp.requests",
                    extra={"method": _safe_str(method), "url": _safe_str(url)},
                )
                if cfg.mode == "block":
                    raise GuardianBlocked(det.reason)
            return original(self_obj, method, url, *args, **kwargs)

        requests.sessions.Session.request = cast(Any, request_wrapper)
        self._requests_patched = True

    def _patch_flask(self) -> None:
        if self._flask_patched:
            return
        if flask is None:
            return

        telemetry = self.telemetry
        cfg = self.config

        try:
            original_wsgi_app = flask.Flask.wsgi_app
        except Exception:
            return

        @functools.wraps(original_wsgi_app)
        def wsgi_app_wrapper(app_self, environ, start_response):
            if not cfg.enabled:
                return original_wsgi_app(app_self, environ, start_response)

            path = environ.get("PATH_INFO", "") or ""
            query_string = environ.get("QUERY_STRING", "") or ""
            body_bytes = b""
            wsgi_input = environ.get("wsgi.input")
            try:
                content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            except (TypeError, ValueError):
                content_length = 0

            if wsgi_input is not None and content_length > 0:
                try:
                    body_bytes = wsgi_input.read(content_length)
                except Exception:
                    body_bytes = b""
                environ["wsgi.input"] = io.BytesIO(body_bytes)
            environ["CONTENT_LENGTH"] = str(len(body_bytes))

            body_text = body_bytes.decode("utf-8", errors="replace")
            request_target = path
            if query_string:
                request_target = f"{path}?{query_string}"

            det = _detect_request_threat(request_target, query_string, body_text)
            if det:
                _emit_detection(
                    telemetry,
                    cfg,
                    det,
                    event_type="guardian.rasp.request",
                    extra={
                        "method": _safe_str(environ.get("REQUEST_METHOD", "")),
                        "url": _safe_str(request_target, max_len=1200),
                        "source": "flask_wsgi",
                    },
                )
                if cfg.mode == "block":
                    payload = b'{"error":"Blocked by GuardianAI: request blocked"}'
                    headers = [
                        ("Content-Type", "application/json"),
                        ("Content-Length", str(len(payload))),
                    ]
                    start_response("403 FORBIDDEN", headers)
                    return [payload]

            return original_wsgi_app(app_self, environ, start_response)

        flask.Flask.wsgi_app = cast(Any, wsgi_app_wrapper)
        self._flask_patched = True


class _SQLiteCursorProxy:
    def __init__(self, cursor: sqlite3.Cursor, *, telemetry: Telemetry, config: GuardianConfig):
        self._cursor = cursor
        self._telemetry = telemetry
        self._config = config

    def execute(self, sql: str, parameters: Any = None):
        det = detect_sqli(_safe_str(sql, max_len=1200))
        if det:
            _emit_detection(
                self._telemetry,
                self._config,
                det,
                event_type="guardian.rasp.sqlite3",
                extra={
                    "op": "cursor.execute",
                    "sql": _safe_str(sql, max_len=1200),
                    "parameters": _safe_str(parameters),
                },
            )
            if self._config.mode == "block":
                raise GuardianBlocked(det.reason)
        if parameters is not None:
            return self._cursor.execute(sql, parameters)
        return self._cursor.execute(sql)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)


class _SQLiteConnectionProxy:
    def __init__(self, connection: sqlite3.Connection, *, telemetry: Telemetry, config: GuardianConfig):
        self._connection = connection
        self._telemetry = telemetry
        self._config = config

    def execute(self, sql: str, parameters: Any = None):
        det = detect_sqli(_safe_str(sql, max_len=1200))
        if det:
            _emit_detection(
                self._telemetry,
                self._config,
                det,
                event_type="guardian.rasp.sqlite3",
                extra={
                    "op": "execute",
                    "sql": _safe_str(sql, max_len=1200),
                    "parameters": _safe_str(parameters),
                },
            )
            if self._config.mode == "block":
                raise GuardianBlocked(det.reason)
        if parameters is not None:
            return self._connection.execute(sql, parameters)
        return self._connection.execute(sql)

    def cursor(self, *args: Any, **kwargs: Any):
        return _SQLiteCursorProxy(
            self._connection.cursor(*args, **kwargs),
            telemetry=self._telemetry,
            config=self._config,
        )

    def __enter__(self):
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._connection.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


def _detect_request_threat(url: str, query_string: str, body_text: str) -> Optional[Detection]:
    ssrf_det = detect_ssrf(url) or detect_ssrf(query_string) or detect_ssrf(body_text)
    if ssrf_det:
        return ssrf_det

    sqli_det = None
    if url:
        sqli_det = detect_sqli(url)
    if not sqli_det and query_string:
        sqli_det = detect_sqli(query_string)
    if not sqli_det and body_text:
        sqli_det = detect_sqli(body_text)
    return sqli_det


def _emit_detection(
    telemetry: Telemetry,
    cfg: GuardianConfig,
    det: Detection,
    *,
    event_type: str,
    extra: dict,
) -> None:
    verdict = det.verdict
    if cfg.mode == "block":
        verdict = "BLOCKED"
    telemetry.emit(
        event_type=event_type,
        message=det.reason,
        severity=clamp_severity(det.severity),
        category=det.category,
        verdict=verdict,
        extra=extra,
    )


def enable(
    service_name: str | GuardianConfig = "default",
    log_path: str = "security.log",
    mode: str = "monitor",
) -> GuardianMonitor:
    print("DEBUG: GuardianAI Initializing...")

    try:
        if isinstance(service_name, GuardianConfig):
            cfg = service_name
        else:
            env_cfg = GuardianConfig.from_env()
            cfg = GuardianConfig(
                service_name=service_name or env_cfg.service_name or "default",
                environment=env_cfg.environment,
                log_path=log_path or env_cfg.log_path,
                ingest_url=env_cfg.ingest_url,
                enabled=env_cfg.enabled,
                mode=(mode or env_cfg.mode or "monitor").strip().lower(),
            )
        mon = GuardianMonitor(config=cfg, telemetry=Telemetry(cfg))
        mon.enable()
        return mon
    except Exception as exc:
        print(f"GuardianAI initialization failed: {exc}", file=sys.stderr)
        traceback.print_exc()
        raise
