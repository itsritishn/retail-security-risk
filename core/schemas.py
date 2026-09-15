"""Request and response schemas.

Validation is treated as a security boundary. Every field that crosses from the edge
tier or a browser into the core service is bounded in type, length, and range, because
an ingest endpoint that accepts arbitrary JSON is a denial-of-service primitive and a
storage-exhaustion bug waiting to happen.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from core.models import Disposition, DuressKind, EventType

Code = Annotated[str, StringConstraints(min_length=1, max_length=48, pattern=r"^[A-Za-z0-9_\-]+$")]
ShortText = Annotated[str, StringConstraints(max_length=500)]


# --------------------------------------------------------------------------------------
# Edge ingest
# --------------------------------------------------------------------------------------


class EventIn(BaseModel):
    """A behavioural event published by an edge worker.

    Note what is absent and cannot be added by a caller: ``extra="forbid"`` means an
    edge worker that tries to attach an image, a face descriptor, or any unmodelled
    field gets a 422 rather than silently having it stored.
    """

    model_config = ConfigDict(extra="forbid")

    camera_code: Code
    event_type: str
    track_ref: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    raw_score: float = Field(ge=0.0, le=1.0)
    occurred_at: datetime
    nonce: Annotated[str, StringConstraints(min_length=8, max_length=64)]
    model_version: Annotated[str, StringConstraints(max_length=48)] = "unspecified"
    features: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def _known_event_type(cls, value: str) -> str:
        valid = {item.value for item in EventType}
        if value not in valid:
            raise ValueError(f"event_type must be one of: {', '.join(sorted(valid))}")
        return value

    @field_validator("features")
    @classmethod
    def _bounded_features(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Cap the feature payload.

        Unbounded nested JSON in a high-rate ingest path is a storage and CPU
        amplification vector. The fairness screen in :mod:`core.policy` runs separately
        and rejects prohibited keys outright.
        """
        if len(value) > 40:
            raise ValueError("features may contain at most 40 keys")
        for key, item in value.items():
            if len(str(key)) > 64:
                raise ValueError("feature keys must be 64 characters or fewer")
            if isinstance(item, str) and len(item) > 256:
                raise ValueError(f"feature {key!r} string value exceeds 256 characters")
        return value


class EventAccepted(BaseModel):
    """Ingest acknowledgement.

    ``event_id`` is null for heartbeats, which update camera liveness without being
    persisted as events. Storing one row per heartbeat would dominate the table and
    tell us nothing that ``last_seen_at`` does not.
    """

    event_id: int | None = None
    alert_id: int | None = None
    alerted: bool = False
    score: float = 0.0
    severity: str = "info"
    suppressed_reason: str | None = None


# --------------------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------------------


class AlertOut(BaseModel):
    id: int
    zone: str | None
    camera: str | None
    event_type: str
    score: float
    severity: str
    status: str
    headline: str
    escalated: bool
    created_at: str
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None
    disposition: str | None = None
    rationale: dict = Field(default_factory=dict)
    age_seconds: float = 0.0


class DispositionIn(BaseModel):
    """Staff feedback closing out an alert.

    This is the ground truth the whole evaluation pipeline depends on. Making the note
    mandatory for a false positive is deliberate: it is the only way to learn *why* the
    model was wrong, and a bare tally of false positives teaches nothing.
    """

    model_config = ConfigDict(extra="forbid")

    disposition: str
    note: ShortText = ""

    @field_validator("disposition")
    @classmethod
    def _known_disposition(cls, value: str) -> str:
        valid = {item.value for item in Disposition}
        if value not in valid:
            raise ValueError(f"disposition must be one of: {', '.join(sorted(valid))}")
        return value

    def validate_note_requirement(self) -> None:
        if self.disposition == Disposition.FALSE_POSITIVE.value and not self.note.strip():
            raise ValueError(
                "A short note is required for a false positive so the cause can be reviewed."
            )


# --------------------------------------------------------------------------------------
# Duress
# --------------------------------------------------------------------------------------


class DuressFobIn(BaseModel):
    """A rolling-code activation from a physical fob, relayed by the store gateway."""

    model_config = ConfigDict(extra="forbid")

    serial: Code
    counter: int = Field(ge=0, le=2**31)
    kind: str
    code: Annotated[str, StringConstraints(min_length=16, max_length=64)]
    zone_code: Code | None = None

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, value: str) -> str:
        valid = {item.value for item in DuressKind}
        if value not in valid:
            raise ValueError(f"kind must be one of: {', '.join(sorted(valid))}")
        return value


class DuressManualIn(BaseModel):
    """Activation raised from the dashboard by a signed-in member of staff."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    zone_code: Code | None = None
    note: ShortText = ""
    request_public_broadcast: bool = False

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, value: str) -> str:
        valid = {item.value for item in DuressKind}
        if value not in valid:
            raise ValueError(f"kind must be one of: {', '.join(sorted(valid))}")
        return value


class DuressOut(BaseModel):
    id: int
    kind: str
    silent: bool
    public_broadcast: bool
    zone: str | None
    source: str
    created_at: str
    acknowledged_at: str | None = None
    coded_announcement: str | None = None
    staff_guidance: list[str] = Field(default_factory=list)
    notify_roles: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------------------


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class UserOut(BaseModel):
    id: int
    username: str
    display_name: str
    role: str
    store: str


# --------------------------------------------------------------------------------------
# Health and integrity
# --------------------------------------------------------------------------------------


class HealthOut(BaseModel):
    status: str
    version: str
    time: str


class CameraHealthOut(BaseModel):
    code: str
    name: str
    zone: str | None
    enabled: bool
    stale: bool
    last_seen_at: str | None


class ChainReportOut(BaseModel):
    store_id: int
    ok: bool
    entries_checked: int
    head_hash: str
    problems: list[dict] = Field(default_factory=list)
