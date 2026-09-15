"""Small shared helpers.

Kept dependency-free so both the core service and the edge tier can import it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any


def utcnow() -> datetime:
    """Timezone-aware UTC now.

    Every timestamp in this system is UTC and tz-aware. Naive datetimes have caused
    real incidents in alerting systems (an hour of missed alerts at a DST boundary),
    so the rule is enforced at the single point where time enters the application.
    """
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    """Coerce a datetime to tz-aware UTC.

    SQLite round-trips datetimes without tzinfo, so values loaded from the database
    need re-attaching before they can be compared with :func:`utcnow`.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso(value: datetime | None) -> str | None:
    """Render a datetime as an ISO-8601 UTC string."""
    if value is None:
        return None
    return as_utc(value).isoformat()


def within_skew(timestamp: datetime, max_skew_seconds: int) -> bool:
    """True if ``timestamp`` sits inside the accepted clock-skew window.

    Used to reject replayed or back-dated edge events. The window is two-sided:
    a far-future timestamp is as suspicious as a stale one.
    """
    delta = abs((utcnow() - as_utc(timestamp)).total_seconds())
    return delta <= max_skew_seconds


def canonical_json(payload: Any) -> str:
    """Deterministic JSON for signing and hashing.

    Signatures computed over non-canonical JSON are a classic source of
    intermittent verification failures: key order must not change the bytes.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: str | bytes, message: str | bytes) -> str:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    """Timing-safe string comparison.

    A naive ``==`` on a MAC leaks information through response timing. Cheap to get
    right, so there is no excuse for getting it wrong.
    """
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def new_nonce(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)


def hours_from_now(hours: int) -> datetime:
    return utcnow() + timedelta(hours=hours)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))
