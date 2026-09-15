"""Application configuration.

All settings are environment-driven with a ``SENTINEL_`` prefix. Defaults are safe for
local development and deliberately unsafe to ship: the application refuses to start
outside debug mode while the placeholder secret is still in place.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

#: The value shipped in ``.env.example``. Treated as a tripwire, never as a usable key.
PLACEHOLDER_SECRET = "CHANGE_ME_dev_only_do_not_use_in_production"


class InsecureConfiguration(RuntimeError):
    """Raised when the service is asked to run with a known-unsafe configuration."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_prefix="SENTINEL_",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Runtime ----
    env: str = "development"
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8000

    # ---- Cryptographic material ----
    secret_key: str = PLACEHOLDER_SECRET
    session_ttl_minutes: int = 45

    # ---- Persistence ----
    database_url: str = f"sqlite:///{BASE_DIR / 'sentinelfloor.db'}"

    # ---- Detection policy ----
    # Biased toward precision rather than recall. A false positive in loss prevention
    # is not a harmless retry: it puts a member of staff in front of an innocent
    # customer. See docs/06-evaluation-plan.md for how these were chosen.
    alert_threshold: float = 0.72
    escalate_threshold: float = 0.88
    alert_cooldown_seconds: int = 90
    event_clock_skew_seconds: int = 30

    # ---- Retention ----
    event_retention_hours: int = 72
    audit_retention_days: int = 365

    # ---- Duress subsystem ----
    duress_silent_first: bool = True
    duress_allow_public_broadcast: bool = False
    duress_counter_window: int = 32

    @field_validator("alert_threshold", "escalate_threshold")
    @classmethod
    def _score_in_unit_interval(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("thresholds must lie in [0.0, 1.0]")
        return value

    @field_validator("session_ttl_minutes")
    @classmethod
    def _session_ttl_sane(cls, value: int) -> int:
        if value < 1:
            raise ValueError("session_ttl_minutes must be at least 1")
        if value > 12 * 60:
            # Shop-floor terminals are shared and often left unattended. A long-lived
            # session on a shared device is an access-control failure waiting to happen.
            raise ValueError("session_ttl_minutes above 12 hours is not permitted")
        return value

    @model_validator(mode="after")
    def _thresholds_ordered(self) -> "Settings":
        if self.escalate_threshold < self.alert_threshold:
            raise ValueError(
                "escalate_threshold must be greater than or equal to alert_threshold"
            )
        return self

    @property
    def secret_is_placeholder(self) -> bool:
        return self.secret_key == PLACEHOLDER_SECRET

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod", "live"}

    def assert_safe_to_serve(self) -> None:
        """Fail closed on configurations that must never reach a real store.

        Called from the application lifespan. Raising here is intentional: a
        misconfigured security tool that silently starts is worse than one that
        refuses to.
        """
        problems: list[str] = []

        if self.secret_is_placeholder and not self.debug:
            problems.append(
                "SENTINEL_SECRET_KEY is still the placeholder value. Generate one with: "
                "python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )

        if self.is_production:
            if self.debug:
                problems.append("SENTINEL_DEBUG must be false when SENTINEL_ENV=production")
            if self.secret_is_placeholder:
                problems.append("SENTINEL_SECRET_KEY must be set in production")
            if self.host == "0.0.0.0":
                problems.append(
                    "Binding 0.0.0.0 directly is not supported in production. Terminate TLS "
                    "at a reverse proxy and bind loopback. See docs/03-threat-model.md."
                )
            if self.database_url.startswith("sqlite"):
                problems.append(
                    "SQLite is single-writer and has no at-rest encryption story here. "
                    "Use PostgreSQL for multi-store deployments."
                )

        if problems:
            raise InsecureConfiguration(
                "Refusing to start:\n  - " + "\n  - ".join(problems)
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
