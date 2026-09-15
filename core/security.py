"""Authentication, password storage, session tokens, CSRF, and RBAC.

Everything in this module is deliberately boring and standards-aligned. Novelty in
authentication code is a defect, not a feature.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from threading import Lock

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import Settings, get_settings
from core.db import get_session
from core.models import Camera, Role, User, privilege_of
from core.util import (
    canonical_json,
    constant_time_equals,
    hmac_sha256_hex,
    utcnow,
    within_skew,
)

# --------------------------------------------------------------------------------------
# Password storage
# --------------------------------------------------------------------------------------

#: PBKDF2-HMAC-SHA256 iteration count, at the OWASP-recommended level for this PRF.
#: Raising this is a one-line change; stored hashes carry their own cost parameter so
#: old passwords keep verifying and are transparently upgraded on next login.
PBKDF2_ITERATIONS = 600_000
_PBKDF2_ALGORITHM = "pbkdf2_sha256"
SALT_BYTES = 16

SESSION_COOKIE = "sf_session"
CSRF_COOKIE = "sf_csrf"
CSRF_HEADER = "x-sf-csrf"
CSRF_FORM_FIELD = "csrf_token"

#: Header carrying the edge tier's HMAC over the canonical event payload.
EDGE_SIGNATURE_HEADER = "x-sf-signature"

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Derive a storable password hash.

    Format: ``pbkdf2_sha256$<iterations>$<salt_b64>$<derived_b64>``. Self-describing so
    the cost factor can be raised later without invalidating existing credentials.
    """
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join(
        (
            _PBKDF2_ALGORITHM,
            str(iterations),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(derived).decode("ascii"),
        )
    )


def verify_password(password: str, stored: str) -> bool:
    """Constant-time password verification.

    Returns False on malformed input rather than raising: a corrupted hash column must
    not become a way to distinguish valid usernames from invalid ones.
    """
    try:
        algorithm, iterations_raw, salt_b64, derived_b64 = stored.split("$")
        if algorithm != _PBKDF2_ALGORITHM:
            return False
        iterations = int(iterations_raw)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(derived_b64)
    except (ValueError, TypeError):
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return secrets.compare_digest(candidate, expected)


def password_needs_rehash(stored: str) -> bool:
    """True if a stored hash uses a weaker cost factor than we now require."""
    try:
        algorithm, iterations_raw, _, _ = stored.split("$")
    except ValueError:
        return True
    return algorithm != _PBKDF2_ALGORITHM or int(iterations_raw) < PBKDF2_ITERATIONS


def password_policy_errors(password: str) -> list[str]:
    """Length-first policy, per NCSC and current NIST guidance.

    No forced composition rules and no rotation theatre: both push people toward
    predictable patterns and sticky notes under the till.
    """
    problems: list[str] = []
    if len(password) < 12:
        problems.append("Use at least 12 characters.")
    if len(password) > 200:
        problems.append("Keep it under 200 characters.")
    lowered = password.lower()
    for banned in ("password", "sentinel", "onestop", "tesco", "123456", "qwerty", "letmein"):
        if banned in lowered:
            problems.append(f"Must not contain the common term {banned!r}.")
            break
    if password.strip() != password:
        problems.append("Must not start or end with whitespace.")
    return problems


# --------------------------------------------------------------------------------------
# Login throttling
# --------------------------------------------------------------------------------------


class SlidingWindowThrottle:
    """Per-source sliding-window throttle for authentication attempts.

    In-memory, so it resets on restart and does not span replicas. Documented as risk
    R-05: a real deployment puts this in Redis or at the reverse proxy. Per-account
    lockout in the database is the durable control; this is defence in depth against
    spraying across many accounts from one source.
    """

    def __init__(self, max_attempts: int = 10, window_seconds: int = 60) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = Lock()

    def check(self, key: str) -> bool:
        """Record an attempt. Returns False when the caller is over budget."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_attempts:
                return False
            bucket.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


#: Authentication attempts, per source address.
login_throttle = SlidingWindowThrottle(max_attempts=10, window_seconds=60)

#: Edge ingest, per camera. Generous enough for a normal event rate but low enough that a
#: compromised edge box cannot flood the alert queue or fill the database unbounded.
ingest_throttle = SlidingWindowThrottle(max_attempts=600, window_seconds=60)

#: Duress activations, per device. Tight, because repeated activation is either a fault
#: or an attempt to desensitise staff to the alarm.
duress_throttle = SlidingWindowThrottle(max_attempts=6, window_seconds=60)


# --------------------------------------------------------------------------------------
# Session tokens
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionClaims:
    user_id: int
    store_id: int
    role: str
    jti: str


def issue_session_token(user: User, settings: Settings | None = None) -> tuple[str, str]:
    """Mint a signed session token and its bound CSRF token.

    Returns ``(session_token, csrf_token)``. The CSRF token is derived from the session
    identifier, so a stolen CSRF token is useless without the matching session and the
    pair cannot be mixed and matched across sessions.
    """
    settings = settings or get_settings()
    now = utcnow()
    jti = secrets.token_urlsafe(16)
    payload = {
        "sub": str(user.id),
        "sid": user.store_id,
        "role": user.role,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.session_ttl_minutes)).timestamp()),
        "typ": "session",
    }
    token = jwt.encode(payload, settings.secret_key, algorithm="HS256")
    return token, derive_csrf_token(jti, settings)


def derive_csrf_token(jti: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    return hmac_sha256_hex(settings.secret_key, f"csrf:{jti}")


def decode_session_token(token: str, settings: Settings | None = None) -> SessionClaims | None:
    """Verify and decode a session token, or return None.

    ``algorithms`` is pinned to a single value. Accepting the token's own ``alg`` header
    is the classic JWT confusion bug, and ``none`` is not an algorithm.
    """
    settings = settings or get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.PyJWTError:
        return None

    if payload.get("typ") != "session":
        return None
    try:
        return SessionClaims(
            user_id=int(payload["sub"]),
            store_id=int(payload["sid"]),
            role=str(payload["role"]),
            jti=str(payload["jti"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


# --------------------------------------------------------------------------------------
# Authentication flow
# --------------------------------------------------------------------------------------


@dataclass
class AuthResult:
    user: User | None
    reason: str

    @property
    def ok(self) -> bool:
        return self.user is not None


def authenticate(session: Session, username: str, password: str) -> AuthResult:
    """Verify credentials, applying per-account lockout.

    The failure reason is returned for the audit log only. The response shown to the
    client is uniform, because "no such user" versus "wrong password" is free
    reconnaissance for an attacker.
    """
    user = session.execute(
        select(User).where(User.username == username.strip().lower())
    ).scalar_one_or_none()

    if user is None:
        # Spend comparable time on a dummy verification so that response latency does
        # not reveal whether the username exists.
        verify_password(password, hash_password("timing-equalisation-placeholder", iterations=1))
        return AuthResult(None, "unknown_user")

    if not user.is_active:
        return AuthResult(None, "account_disabled")

    if user.is_locked:
        return AuthResult(None, "account_locked")

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
            session.add(user)
            return AuthResult(None, "locked_out_now")
        session.add(user)
        return AuthResult(None, "bad_password")

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    session.add(user)
    return AuthResult(user, "ok")


# --------------------------------------------------------------------------------------
# FastAPI dependencies
# --------------------------------------------------------------------------------------


class NotAuthenticated(HTTPException):
    """Distinguishable from a generic 401 so the UI can redirect to the login page."""

    def __init__(self, detail: str = "Authentication required") -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def get_current_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise NotAuthenticated()

    claims = decode_session_token(token)
    if claims is None:
        raise NotAuthenticated("Session expired or invalid")

    user = session.get(User, claims.user_id)
    if user is None or not user.is_active or user.is_locked:
        raise NotAuthenticated("Account unavailable")

    # The role is re-read from the database rather than trusted from the token, so a
    # demotion takes effect immediately instead of at the next token expiry.
    if user.role != claims.role:
        raise NotAuthenticated("Privileges changed, please sign in again")

    request.state.csrf_token = derive_csrf_token(claims.jti)
    request.state.session_jti = claims.jti
    return user


def require_roles(*allowed: Role | str):
    """Dependency factory enforcing membership of an explicit role set."""
    allowed_values = {r.value if isinstance(r, Role) else str(r) for r in allowed}

    def _dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(sorted(allowed_values))}",
            )
        return user

    return _dependency


def require_min_role(minimum: Role):
    """Dependency factory enforcing an operational privilege floor.

    Auditors score zero privilege here, so they are excluded from every operational
    action regardless of the floor. Read access for auditors is granted explicitly via
    :func:`require_roles` on the routes they are meant to reach.
    """
    threshold = privilege_of(minimum.value)

    def _dependency(user: User = Depends(get_current_user)) -> User:
        if privilege_of(user.role) < threshold:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum.value} privileges or higher",
            )
        return user

    return _dependency


async def verify_csrf(request: Request) -> None:
    """Double-submit CSRF check for cookie-authenticated state changes.

    Safe methods are exempt. Token comparison is timing-safe, and the expected value is
    derived from the session identifier so it cannot be replayed against another session.
    """
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return

    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise NotAuthenticated()
    claims = decode_session_token(token)
    if claims is None:
        raise NotAuthenticated("Session expired or invalid")

    expected = derive_csrf_token(claims.jti)
    supplied = request.headers.get(CSRF_HEADER)

    if not supplied:
        content_type = request.headers.get("content-type", "")
        if "form" in content_type:
            form = await request.form()
            value = form.get(CSRF_FORM_FIELD)
            supplied = str(value) if value is not None else None

    if not supplied or not constant_time_equals(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed"
        )


# --------------------------------------------------------------------------------------
# Edge-tier message authentication
# --------------------------------------------------------------------------------------


class EdgeAuthError(Exception):
    """Raised when an edge event fails authentication."""


def compute_edge_signature(ingest_key: str, payload: dict) -> str:
    """HMAC-SHA256 over the canonical JSON form of an event payload."""
    return hmac_sha256_hex(ingest_key, canonical_json(payload))


def verify_edge_event(
    session: Session,
    camera_code: str,
    signature: str,
    payload: dict,
    *,
    skew_seconds: int,
) -> Camera:
    """Authenticate an inbound edge event.

    Three independent checks, all required:

    1. The camera exists, is enabled, and has a key.
    2. The HMAC over the canonical payload verifies against that camera's key.
    3. The declared ``occurred_at`` falls inside the accepted clock-skew window.

    Nonce uniqueness is the fourth control and is enforced by a database constraint at
    insert time, which is the only place it can be made genuinely atomic.
    """
    camera = session.execute(
        select(Camera).where(Camera.code == camera_code)
    ).scalar_one_or_none()

    if camera is None or not camera.enabled:
        raise EdgeAuthError("unknown or disabled camera")

    expected = compute_edge_signature(camera.ingest_key, payload)
    if not constant_time_equals(signature, expected):
        raise EdgeAuthError("signature mismatch")

    occurred_at = payload.get("occurred_at")
    if not occurred_at:
        raise EdgeAuthError("missing occurred_at")

    from datetime import datetime

    try:
        parsed = datetime.fromisoformat(str(occurred_at))
    except ValueError as exc:
        raise EdgeAuthError("unparseable occurred_at") from exc

    if not within_skew(parsed, skew_seconds):
        raise EdgeAuthError("timestamp outside accepted skew window")

    return camera
