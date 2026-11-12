"""Runtime configuration.

The window length and slot limit are environment-overridable so the behavior
can be exercised quickly in tests; the production defaults match the spec
(60 seconds / 5 slots per account).
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class Settings:
    db_path: str = os.environ.get("LOGIN_DB_PATH", "/data/login.db")
    # Sliding window for completed failed attempts, in seconds.
    error_window_seconds: int = _env_int("ERROR_WINDOW_SECONDS", 60)
    # Max (recent errors + in-flight verifications) admitted per account.
    max_slots: int = _env_int("MAX_SLOTS", 5)
    # Largest simulated verification delay the client may request, in seconds.
    max_delay_seconds: int = _env_int("MAX_DELAY_SECONDS", 10)
    session_ttl_seconds: int = _env_int("SESSION_TTL_SECONDS", 3600)
    process_name: str = os.environ.get("PROCESS_NAME", "login")


settings = Settings()
