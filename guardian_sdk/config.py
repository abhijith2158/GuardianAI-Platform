from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


def _normalize_ingest_url(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip()
    if not normalized:
        return None

    try:
        parsed = urlsplit(normalized)
    except Exception:
        trimmed = normalized.rstrip("/")
        if trimmed.endswith("/v1/telemetry"):
            return trimmed
        return f"{trimmed}/v1/telemetry"

    path = parsed.path.rstrip("/")
    if not path or path == "/":
        path = "/v1/telemetry"
    elif not path.endswith("/v1/telemetry"):
        path = f"{path}/v1/telemetry"

    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


@dataclass(frozen=True)
class GuardianConfig:
    """
    Runtime config for the SDK.

    The existing SOC demo tails a text file named `security.log`, so file logging is the
    default transport to stay compatible with today's engine.
    """

    service_name: str = "unknown-service"
    environment: str = "dev"
    log_path: str = "security.log"
    ingest_url: str | None = None
    enabled: bool = True

    # "block" means raise on suspicious operations; "monitor" only logs.
    mode: str = "monitor"

    @staticmethod
    def from_env() -> "GuardianConfig":
        return GuardianConfig(
            service_name=os.getenv("GUARDIAN_SERVICE_NAME", "unknown-service"),
            environment=os.getenv("GUARDIAN_ENV", "dev"),
            log_path=os.getenv("GUARDIAN_LOG_PATH", "security.log"),
            ingest_url=_normalize_ingest_url(os.getenv("GUARDIAN_INGEST_URL")),
            enabled=os.getenv("GUARDIAN_ENABLED", "1").strip() not in {"0", "false", "False"},
            mode=os.getenv("GUARDIAN_MODE", "monitor").strip().lower() or "monitor",
        )

