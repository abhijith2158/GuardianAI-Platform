from __future__ import annotations

import os
from dataclasses import dataclass


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
            ingest_url=os.getenv("GUARDIAN_INGEST_URL") or None,
            enabled=os.getenv("GUARDIAN_ENABLED", "1").strip() not in {"0", "false", "False"},
            mode=os.getenv("GUARDIAN_MODE", "monitor").strip().lower() or "monitor",
        )

