"""Password hashing (argon2) and random session token generation."""
from __future__ import annotations

import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Deliberately interactive-grade parameters: this is the expensive operation
# that must run *outside* the SQLite write transaction/lock.
ph = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-ish argon2 verification. Never raises on a wrong password."""
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        # Malformed hash etc. treat as authentication failure rather than
        # leaking a 500 that differentiates accounts.
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return ph.check_needs_rehash(password_hash)
    except Exception:
        return False


def new_session_token() -> str:
    """256 bits of CSPRNG randomness, URL-safe."""
    return secrets.token_urlsafe(32)


def compare_tokens(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
