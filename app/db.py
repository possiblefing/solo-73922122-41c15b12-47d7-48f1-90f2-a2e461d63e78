"""SQLite-backed shared state for the login service.

Concurrency model
-----------------
Two (or more) uvicorn worker processes share one SQLite database file.

* The database runs in WAL mode, so a reader never blocks a writer and two
  readers never block each other; writers still serialize through the single
  WAL writer, which is exactly the serialization point we need for the
  per-account slot accounting.
* Every state-changing operation opens a *short* ``BEGIN IMMEDIATE``
  transaction. The argon2 hash itself is computed by the caller **outside**
  any transaction (see :mod:`app.security`), so CPU-bound password hashing
  never holds the SQLite write lock.
* There is deliberately no in-process global lock around verification:
  cross-process coordination happens entirely inside SQLite transactions.
* Each request uses its own connection; no connection is ever shared across
  threads.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Iterator, Optional

from .config import settings
from .security import hash_password

# Demo accounts. Only the argon2 hashes are ever persisted; the plaintext
# passwords live here solely so the one-time seed can be generated and are
# shown on the demo page for convenience.
SEED_ACCOUNTS = (
    ("alice", "alice-pass-2026"),
    ("bob", "bob-pass-2026"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS login_errors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_errors_account_time
    ON login_errors(account_id, created_at);

CREATE TABLE IF NOT EXISTS login_inflight (
    slot_id    TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    acquired_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_inflight_account
    ON login_inflight(account_id);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    """Open a brand-new connection with concurrency-friendly settings."""
    os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
    conn = sqlite3.connect(
        settings.db_path,
        timeout=30.0,            # wait on the write lock instead of erroring
        isolation_level=None,    # explicit BEGIN/COMMIT, no implicit txns
        check_same_thread=False,  # connections are per-call, never shared
    )
    conn.row_factory = sqlite3.Row
    # Persistent WAL/journal settings are stored in the DB file itself;
    # re-issuing them on every connection is cheap and makes a fresh file
    # self-initializing even before init_db() runs.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def immediate_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Acquire the WAL write lock up-front and commit/roll back as a unit."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        # An inner block may have rolled back explicitly to bail out cleanly.
        if conn.in_transaction:
            conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def init_db() -> None:
    """Create the schema, seed demo accounts and clear stale in-flight slots.

    Safe to run concurrently from several processes: DDL uses
    ``IF NOT EXISTS`` and account seeding uses ``INSERT OR IGNORE``.
    """
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        now = time.time()
        with immediate_tx(conn):
            for username, password in SEED_ACCOUNTS:
                row = conn.execute(
                    "SELECT id FROM accounts WHERE username = ?", (username,)
                ).fetchone()
                if row is None:
                    # Hashing happens before the write; it is not performed
                    # while holding any lock beyond this short seed txn.
                    conn.execute(
                        "INSERT OR IGNORE INTO accounts"
                        " (username, password_hash, created_at)"
                        " VALUES (?, ?, ?)",
                        (username, hash_password(password), now),
                    )
            # A process restart means every previously in-flight verifier is
            # dead: reclaim all slots. Completed errors are intentionally
            # kept so the rolling window survives the restart.
            conn.execute("DELETE FROM login_inflight")
    finally:
        conn.close()


def get_account(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username, password_hash FROM accounts WHERE username = ?",
        (username,),
    ).fetchone()


def acquire_slot(account_id: int, now: Optional[float] = None) -> Optional[str]:
    """Atomically take one verification slot for an account.

    Counts *completed* errors inside the rolling window plus *in-flight*
    verifications. When the account is at capacity the function returns
    ``None`` without inserting anything (caller returns HTTP 429 and must
    not hash the password).
    """
    now = time.time() if now is None else now
    cutoff = now - settings.error_window_seconds
    slot_id = uuid.uuid4().hex
    conn = connect()
    try:
        with immediate_tx(conn):
            conn.execute(
                "DELETE FROM login_errors WHERE created_at < ?", (cutoff,)
            )
            errors = conn.execute(
                "SELECT COUNT(*) AS c FROM login_errors WHERE account_id = ?",
                (account_id,),
            ).fetchone()["c"]
            inflight = conn.execute(
                "SELECT COUNT(*) AS c FROM login_inflight WHERE account_id = ?",
                (account_id,),
            ).fetchone()["c"]
            if errors + inflight >= settings.max_slots:
                return None
            conn.execute(
                "INSERT INTO login_inflight (slot_id, account_id, acquired_at)"
                " VALUES (?, ?, ?)",
                (slot_id, account_id, now),
            )
            return slot_id
    finally:
        conn.close()


def settle(
    slot_id: str,
    account_id: int,
    success: bool,
    now: Optional[float] = None,
    session_token: Optional[str] = None,
    session_expires_at: Optional[float] = None,
) -> bool:
    """Book a finished verification and, on success, issue the session.

    The slot release, the error record (or error-window reset) and the
    session row are written in one transaction, so settlement and session
    issuance commit together or not at all.

    On success the currently completed errors of the account are cleared.
    Other in-flight attempts are untouched: if they fail when they finish,
    their failures are still recorded and start a fresh window.

    Returns ``True`` when the slot was settled normally, ``False`` when the
    slot no longer existed (e.g. a startup cleanup after a crash reclaimed
    it while the verifier was still finishing). A missing slot means the
    accounting was already reconciled, so the caller must not treat this as
    a hard failure.
    """
    now = time.time() if now is None else now
    conn = connect()
    try:
        with immediate_tx(conn):
            cur = conn.execute(
                "DELETE FROM login_inflight WHERE slot_id = ?", (slot_id,)
            )
            if cur.rowcount == 0:
                # Slot was reclaimed out from under us (crash/startup
                # cleanup). Roll back the no-op delete and let the caller
                # decide; no error/session rows are written for a slot we no
                # longer own.
                conn.execute("ROLLBACK")
                return False
            if success:
                conn.execute(
                    "DELETE FROM login_errors WHERE account_id = ?", (account_id,)
                )
                if session_token is None or session_expires_at is None:
                    raise RuntimeError("successful settlement requires a session")
                conn.execute(
                    "INSERT INTO sessions"
                    " (token, account_id, created_at, expires_at)"
                    " VALUES (?, ?, ?, ?)",
                    (session_token, account_id, now, session_expires_at),
                )
            else:
                # Error is counted at *completion* time, not acquisition time.
                conn.execute(
                    "INSERT INTO login_errors (account_id, created_at)"
                    " VALUES (?, ?)",
                    (account_id, now),
                )
        return True
    finally:
        conn.close()


def get_session(token: str, now: Optional[float] = None) -> Optional[sqlite3.Row]:
    now = time.time() if now is None else now
    conn = connect()
    try:
        return conn.execute(
            "SELECT s.token, s.expires_at, a.id AS account_id, a.username"
            " FROM sessions s JOIN accounts a ON a.id = s.account_id"
            " WHERE s.token = ? AND s.expires_at > ?",
            (token, now),
        ).fetchone()
    finally:
        conn.close()


def delete_session(token: str) -> None:
    conn = connect()
    try:
        with immediate_tx(conn):
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    finally:
        conn.close()


def account_stats(now: Optional[float] = None) -> list[dict]:
    """Snapshot of every account: windowed errors, in-flight, slots left."""
    now = time.time() if now is None else now
    cutoff = now - settings.error_window_seconds
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT a.id, a.username,
                   (SELECT COUNT(*) FROM login_errors e
                     WHERE e.account_id = a.id AND e.created_at >= ?) AS errors,
                   (SELECT COUNT(*) FROM login_inflight f
                     WHERE f.account_id = a.id) AS inflight
              FROM accounts a
             ORDER BY a.username
            """,
            (cutoff,),
        ).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        used = row["errors"] + row["inflight"]
        out.append(
            {
                "account_id": row["id"],
                "username": row["username"],
                "window_errors": row["errors"],
                "inflight": row["inflight"],
                "used_slots": used,
                "remaining_slots": max(0, settings.max_slots - used),
                "max_slots": settings.max_slots,
                "window_seconds": settings.error_window_seconds,
            }
        )
    return out


def next_retry_after(account_id: int, now: Optional[float] = None) -> float:
    """Seconds until at least one occupied slot frees up (for Retry-After)."""
    now = time.time() if now is None else now
    cutoff = now - settings.error_window_seconds
    conn = connect()
    try:
        oldest_error = conn.execute(
            "SELECT MIN(created_at) AS t FROM login_errors"
            " WHERE account_id = ? AND created_at >= ?",
            (account_id, cutoff),
        ).fetchone()["t"]
        oldest_inflight = conn.execute(
            "SELECT MIN(acquired_at) AS t FROM login_inflight WHERE account_id = ?",
            (account_id,),
        ).fetchone()["t"]
    finally:
        conn.close()
    candidates = []
    if oldest_error is not None:
        candidates.append(oldest_error + settings.error_window_seconds - now)
    if oldest_inflight is not None:
        # In-flight work has no known deadline from SQL's perspective; the
        # caller's requested delay bounds it, but a safe answer is to wait
        # for the oldest error to age out. Fall back to one window if the
        # account is saturated purely by in-flight attempts.
        candidates.append(settings.error_window_seconds)
    return max(1.0, min(candidates) if candidates else 1.0)
