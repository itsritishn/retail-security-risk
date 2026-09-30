"""Authentication, password storage, session tokens, and RBAC primitives."""

from __future__ import annotations

from datetime import timedelta

import jwt
import pytest
from sqlalchemy.orm import Session

from core.config import get_settings
from core.models import Role, privilege_of
from core.security import (
    LOCKOUT_MINUTES,
    MAX_FAILED_LOGINS,
    PBKDF2_ITERATIONS,
    SlidingWindowThrottle,
    authenticate,
    compute_edge_signature,
    decode_session_token,
    derive_csrf_token,
    hash_password,
    issue_session_token,
    password_needs_rehash,
    password_policy_errors,
    verify_password,
)
from core.util import constant_time_equals, utcnow
from tests.conftest import TEST_KDF_ITERATIONS, TEST_PASSWORD

CHEAP = 1_000


# ------------------------------------------------------------------ passwords


def test_hash_and_verify_round_trip():
    stored = hash_password("a decent passphrase here", iterations=CHEAP)
    assert verify_password("a decent passphrase here", stored) is True
    assert verify_password("the wrong passphrase", stored) is False


def test_hashes_are_salted():
    """Identical passwords must not produce identical hashes."""
    first = hash_password("same password", iterations=CHEAP)
    second = hash_password("same password", iterations=CHEAP)
    assert first != second
    assert verify_password("same password", first)
    assert verify_password("same password", second)


def test_hash_format_is_self_describing():
    stored = hash_password("x" * 20, iterations=CHEAP)
    algorithm, iterations, salt, digest = stored.split("$")
    assert algorithm == "pbkdf2_sha256"
    assert int(iterations) == CHEAP
    assert salt and digest


def test_production_iteration_count_meets_owasp_guidance():
    assert PBKDF2_ITERATIONS >= 600_000


def test_weak_cost_factor_triggers_rehash():
    assert password_needs_rehash(hash_password("x" * 20, iterations=CHEAP)) is True
    assert password_needs_rehash(hash_password("x" * 20)) is False


def test_malformed_hash_fails_closed():
    """A corrupted column must not become an authentication bypass."""
    for broken in ("", "garbage", "pbkdf2_sha256$notanumber$a$b", "md5$1$a$b", "a$b$c"):
        assert verify_password("anything", broken) is False


def test_empty_password_is_refused():
    with pytest.raises(ValueError):
        hash_password("")


def test_password_policy_is_length_first():
    assert password_policy_errors("short") != []
    assert password_policy_errors("a-perfectly-fine-long-passphrase") == []
    assert password_policy_errors("password123456789") != []
    assert password_policy_errors("northgate-store-login") != []
    assert password_policy_errors(" leading-space-passphrase") != []


# ------------------------------------------------------------------- sessions


def test_session_token_round_trip(users):
    user = users[Role.ASSISTANT.value]
    token, csrf = issue_session_token(user)

    claims = decode_session_token(token)
    assert claims is not None
    assert claims.user_id == user.id
    assert claims.store_id == user.store_id
    assert claims.role == Role.ASSISTANT.value
    assert csrf == derive_csrf_token(claims.jti)


def test_tampered_token_is_rejected(users):
    token, _ = issue_session_token(users[Role.ADMIN.value])
    header, payload, signature = token.split(".")
    assert decode_session_token(f"{header}.{payload}.{signature[:-4]}abcd") is None


def test_token_signed_with_another_key_is_rejected(users):
    user = users[Role.ADMIN.value]
    forged = jwt.encode(
        {
            "sub": str(user.id),
            "sid": user.store_id,
            "role": "admin",
            "jti": "forged",
            "iat": int(utcnow().timestamp()),
            "exp": int((utcnow() + timedelta(hours=1)).timestamp()),
            "typ": "session",
        },
        "an-attacker-chosen-key",
        algorithm="HS256",
    )
    assert decode_session_token(forged) is None


def test_unsigned_alg_none_token_is_rejected(users):
    """The classic JWT confusion attack. Algorithms are pinned, so this must fail."""
    user = users[Role.ADMIN.value]
    unsigned = jwt.encode(
        {
            "sub": str(user.id),
            "sid": user.store_id,
            "role": "admin",
            "jti": "none-alg",
            "iat": int(utcnow().timestamp()),
            "exp": int((utcnow() + timedelta(hours=1)).timestamp()),
            "typ": "session",
        },
        key="",
        algorithm="none",
    )
    assert decode_session_token(unsigned) is None


def test_expired_token_is_rejected(users, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "session_ttl_minutes", 1, raising=False)

    user = users[Role.ASSISTANT.value]
    expired = jwt.encode(
        {
            "sub": str(user.id),
            "sid": user.store_id,
            "role": user.role,
            "jti": "old",
            "iat": int((utcnow() - timedelta(hours=3)).timestamp()),
            "exp": int((utcnow() - timedelta(hours=2)).timestamp()),
            "typ": "session",
        },
        settings.secret_key,
        algorithm="HS256",
    )
    assert decode_session_token(expired) is None


def test_wrong_token_type_is_rejected(users):
    settings = get_settings()
    user = users[Role.ASSISTANT.value]
    other = jwt.encode(
        {
            "sub": str(user.id),
            "sid": user.store_id,
            "role": user.role,
            "jti": "x",
            "iat": int(utcnow().timestamp()),
            "exp": int((utcnow() + timedelta(hours=1)).timestamp()),
            "typ": "password-reset",
        },
        settings.secret_key,
        algorithm="HS256",
    )
    assert decode_session_token(other) is None


def test_csrf_tokens_are_session_bound():
    """A CSRF token from one session must be useless in another."""
    assert derive_csrf_token("session-a") != derive_csrf_token("session-b")
    assert derive_csrf_token("session-a") == derive_csrf_token("session-a")


# ------------------------------------------------------------ authentication


def test_authenticate_accepts_correct_credentials(session: Session, users):
    result = authenticate(session, "assistant", TEST_PASSWORD)
    assert result.ok is True
    assert result.user is not None
    assert result.user.username == "assistant"


def test_authenticate_is_case_insensitive_on_username(session: Session, users):
    assert authenticate(session, "ASSISTANT", TEST_PASSWORD).ok is True


def test_unknown_user_and_bad_password_both_fail(session: Session, users):
    """Reasons differ for the audit log, but neither authenticates."""
    unknown = authenticate(session, "nobody", TEST_PASSWORD)
    wrong = authenticate(session, "assistant", "not the password")

    assert unknown.ok is False and unknown.reason == "unknown_user"
    assert wrong.ok is False and wrong.reason == "bad_password"


def test_repeated_failures_lock_the_account(session: Session, users):
    for _ in range(MAX_FAILED_LOGINS - 1):
        assert authenticate(session, "assistant", "wrong").reason == "bad_password"

    locking = authenticate(session, "assistant", "wrong")
    assert locking.reason == "locked_out_now"

    # Correct credentials must not open a locked account.
    blocked = authenticate(session, "assistant", TEST_PASSWORD)
    assert blocked.ok is False
    assert blocked.reason == "account_locked"

    # The session is configured with autoflush off, so pending changes have to be flushed
    # before the lock is observable through the ORM.
    session.flush()
    user = users[Role.ASSISTANT.value]
    assert user.is_locked is True
    assert user.locked_until is not None


def test_successful_login_clears_the_failure_counter(session: Session, users):
    authenticate(session, "assistant", "wrong")
    authenticate(session, "assistant", "wrong")

    result = authenticate(session, "assistant", TEST_PASSWORD)
    assert result.ok is True
    assert result.user is not None
    assert result.user.failed_login_count == 0


def test_disabled_account_cannot_authenticate(session: Session, users):
    user = users[Role.ASSISTANT.value]
    user.is_active = False
    session.add(user)
    session.commit()

    result = authenticate(session, "assistant", TEST_PASSWORD)
    assert result.ok is False
    assert result.reason == "account_disabled"


def test_login_upgrades_a_weakly_hashed_password(session: Session, users):
    user = users[Role.ASSISTANT.value]
    user.password_hash = hash_password(TEST_PASSWORD, iterations=CHEAP)
    session.add(user)
    session.commit()

    result = authenticate(session, "assistant", TEST_PASSWORD)
    assert result.ok is True
    assert password_needs_rehash(result.user.password_hash) is False


def test_lockout_duration_is_configured():
    assert LOCKOUT_MINUTES >= 5


# ------------------------------------------------------------------- throttle


def test_throttle_allows_then_blocks():
    throttle = SlidingWindowThrottle(max_attempts=3, window_seconds=60)
    assert throttle.check("k") is True
    assert throttle.check("k") is True
    assert throttle.check("k") is True
    assert throttle.check("k") is False


def test_throttle_is_keyed_per_source():
    throttle = SlidingWindowThrottle(max_attempts=1, window_seconds=60)
    assert throttle.check("a") is True
    assert throttle.check("b") is True
    assert throttle.check("a") is False


def test_throttle_reset_clears_the_bucket():
    throttle = SlidingWindowThrottle(max_attempts=1, window_seconds=60)
    throttle.check("a")
    assert throttle.check("a") is False
    throttle.reset("a")
    assert throttle.check("a") is True


# ----------------------------------------------------------------------- rbac


def test_privilege_ordering():
    assert privilege_of(Role.ADMIN.value) > privilege_of(Role.DUTY_MANAGER.value)
    assert privilege_of(Role.DUTY_MANAGER.value) > privilege_of(Role.ASSISTANT.value)


def test_auditor_has_no_operational_privilege():
    """Separating oversight from operation is the point of the auditor role."""
    assert privilege_of(Role.AUDITOR.value) == 0
    assert privilege_of(Role.AUDITOR.value) < privilege_of(Role.ASSISTANT.value)


# ------------------------------------------------------------ edge signatures


def test_edge_signature_is_stable_and_order_independent():
    """Signatures are computed over canonical JSON, so key order must not matter."""
    key = "0" * 64
    first = compute_edge_signature(key, {"a": 1, "b": {"c": 2, "d": 3}})
    second = compute_edge_signature(key, {"b": {"d": 3, "c": 2}, "a": 1})
    assert first == second


def test_edge_signature_changes_with_payload():
    key = "0" * 64
    assert compute_edge_signature(key, {"score": 0.5}) != compute_edge_signature(
        key, {"score": 0.6}
    )


def test_edge_signature_changes_with_key():
    payload = {"score": 0.5}
    assert compute_edge_signature("a" * 64, payload) != compute_edge_signature(
        "b" * 64, payload
    )


def test_constant_time_compare_behaves_like_equality():
    assert constant_time_equals("abc", "abc") is True
    assert constant_time_equals("abc", "abd") is False
    assert constant_time_equals("abc", "ab") is False
