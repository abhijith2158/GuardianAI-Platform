from __future__ import annotations

import json
import os
import socket
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from .config import GuardianConfig


_write_lock = threading.Lock()


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class TelemetryEvent:
    ts: str
    service: str
    env: str
    event_type: str
    message: str
    severity: int = 1
    category: Optional[str] = None
    verdict: Optional[str] = None
    pid: int = field(default_factory=os.getpid)
    host: str = field(default_factory=socket.gethostname)
    extra: Dict[str, Any] = field(default_factory=dict)


class FileTelemetrySink:
    def __init__(self, config: GuardianConfig):
        self._config = config

    def update_config(self, config: GuardianConfig) -> None:
        self._config = config

    def emit(self, ev: TelemetryEvent) -> None:
        line = self.format_line(ev)
        path = self._config.log_path or "security.log"
        try:
            with _write_lock:
                with open(path, "a", encoding="utf-8", errors="replace", newline="\n") as f:
                    f.write(line + "\n")
        except OSError:
            return

    def format_line(self, ev: TelemetryEvent) -> str:
        payload = asdict(ev)
        json_blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        date_prefix = ev.ts[:10] if ev.ts else _utc_iso()[:10]

        core = (
            f"{date_prefix} guardian event_type={ev.event_type} "
            f"service={ev.service} env={ev.env} "
            f"severity={ev.severity} "
            f"message={ev.message}"
        )
        if ev.category:
            core += f" category={ev.category}"
        if ev.verdict:
            core += f" verdict={ev.verdict}"
        return core + " | " + json_blob


class RemoteTelemetrySink:
    def __init__(self, config: GuardianConfig):
        self._config = config

    def update_config(self, config: GuardianConfig) -> None:
        self._config = config

    def emit(self, ev: TelemetryEvent) -> None:
        if not self._config.ingest_url:
            return

        headers = {
            "Content-Type": "application/json",
            "X-API-KEY": os.getenv("GUARDIAN_API_KEY", ""),
        }
        payload = asdict(ev)

        try:
            requests.post(
                self._config.ingest_url,
                json=payload,
                headers=headers,
                timeout=1,
            )
        except Exception:
            return


class Telemetry:
    def __init__(self, config: GuardianConfig):
        self._config = config
        self._file_sink = FileTelemetrySink(config)
        self._remote_sink = RemoteTelemetrySink(config)

    def update_config(self, config: GuardianConfig) -> None:
        self._config = config
        self._file_sink.update_config(config)
        self._remote_sink.update_config(config)

    def emit(
        self,
        *,
        event_type: str,
        message: str,
        severity: int = 1,
        category: Optional[str] = None,
        verdict: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self._config.enabled:
            return

        ev = TelemetryEvent(
            ts=_utc_iso(),
            service=self._config.service_name,
            env=self._config.environment,
            event_type=event_type,
            message=message,
            severity=int(severity),
            category=category,
            verdict=verdict,
            extra=extra or {},
        )
        self._file_sink.emit(ev)
        self._remote_sink.emit(ev)
