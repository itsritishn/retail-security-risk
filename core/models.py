"""Domain model.

Design constraints encoded here, not just documented:

* There is no ``Customer`` table, no face embedding column, and no watchlist entity.
  A subject is referenced only by an ephemeral, per-camera ``track_ref`` that is
  meaningless once the person leaves frame and is never correlated across cameras.
* ``Event`` carries derived behavioural features only. No imagery, ever.
* ``AuditRecord`` is append-only and hash-chained. Nothing in the application layer
  offers an update or delete path for it.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base
from core.util import utcnow


# --------------------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------------------


class Role(str, enum.Enum):
    """Roles are ordered by privilege for the purposes of ``at_least`` checks.

    ``AUDITOR`` sits deliberately outside that ordering. An auditor can read the audit
    log and detection-quality metrics but cannot acknowledge alerts or change policy.
    Separating oversight from operation is the point; a manager who can both act and
    rewrite the record of their actions is not accountable to anyone.
    """

    ASSISTANT = "assistant"
    DUTY_MANAGER = "duty_manager"
    ADMIN = "admin"
    AUDITOR = "auditor"


_PRIVILEGE_ORDER: dict[str, int] = {
    Role.ASSISTANT.value: 10,
    Role.DUTY_MANAGER.value: 20,
    Role.ADMIN.value: 30,
}


def privilege_of(role: str) -> int:
    """Numeric privilege for an operational role. Auditor scores 0 by design."""
    return _PRIVILEGE_ORDER.get(role, 0)


class EventType(str, enum.Enum):
    CONCEALMENT = "concealment"          # hand to shelf, then to body or bag
    SHELF_SWEEP = "shelf_sweep"          # bulk removal in one motion
    PROLONGED_DWELL = "prolonged_dwell"  # extended presence in a high-risk zone
    IN_STORE_CONSUMPTION = "in_store_consumption"
    OBSCURED_VIEW = "obscured_view"      # camera blocked or misaligned: tamper signal
    HEARTBEAT = "heartbeat"              # edge liveness, never alertable


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Disposition(str, enum.Enum):
    """How a prompt actually turned out, recorded by the member of staff.

    This is the ground-truth signal for evaluating the model. Without it the system
    has no idea whether it is useful, and "we think it's working" is not a metric.
    """

    TRUE_POSITIVE_RECOVERED = "true_positive_recovered"
    TRUE_POSITIVE_LOST = "true_positive_lost"
    FALSE_POSITIVE = "false_positive"
    UNCLEAR = "unclear"
    NOT_ATTENDED = "not_attended"


class DuressKind(str, enum.Enum):
    THREAT = "threat"
    THEFT_IN_PROGRESS = "theft_in_progress"
    MEDICAL = "medical"
    TEST = "test"


# --------------------------------------------------------------------------------------
# Estate
# --------------------------------------------------------------------------------------


class Store(Base):
    __tablename__ = "stores"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    reference: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), default="Europe/London")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    zones: Mapped[list["Zone"]] = relationship(back_populates="store")
    cameras: Mapped[list["Camera"]] = relationship(back_populates="store")


class Zone(Base):
    """A named area of the shop floor, for example 'confectionery' or 'front entrance'.

    ``risk_weight`` scales the concealment score during policy evaluation. This is how
    domain knowledge from the shop floor enters the system: staff know that chocolate
    and butter walk out more often than tinned soup, and that knowledge is worth more
    than another epoch of training.
    """

    __tablename__ = "zones"
    __table_args__ = (UniqueConstraint("store_id", "code", name="uq_zone_store_code"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    code: Mapped[str] = mapped_column(String(48), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    risk_weight: Mapped[float] = mapped_column(Float, default=1.0)
    is_high_value: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Text)

    store: Mapped[Store] = relationship(back_populates="zones")


class Camera(Base):
    """A camera and its paired edge worker.

    ``ingest_key`` is the HMAC key the edge tier signs events with. It is per-camera so
    that one compromised edge box cannot forge events for the rest of the estate, and
    can be revoked without touching anything else.

    Known limitation, carried openly: the key is stored here in plaintext. Correct
    handling is a KMS or HSM-backed secret store. Recorded as risk R-07 in
    docs/03-threat-model.md rather than quietly ignored.
    """

    __tablename__ = "cameras"
    __table_args__ = (UniqueConstraint("store_id", "code", name="uq_camera_store_code"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("zones.id"))
    code: Mapped[str] = mapped_column(String(48), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    ingest_key: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    store: Mapped[Store] = relationship(back_populates="cameras")
    zone: Mapped[Zone | None] = relationship()

    @property
    def is_stale(self) -> bool:
        """A camera that stopped reporting is a security event, not a gap in the data.

        Silence is indistinguishable from a disabled camera, a cut cable, or an
        attacker who pulled the edge box. It must surface, so absence of signal is
        treated as signal.
        """
        if self.last_seen_at is None:
            return True
        from core.util import as_utc

        return (utcnow() - as_utc(self.last_seen_at)).total_seconds() > 180


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_user_username"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default=Role.ASSISTANT.value)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    # Online-guessing defence. Lockout is per-account with a cooling-off period.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    store: Mapped[Store] = relationship()

    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        from core.util import as_utc

        return as_utc(self.locked_until) > utcnow()


class DuressDevice(Base):
    """A staff-carried duress fob.

    Authenticated by rolling code: HMAC over a monotonically increasing counter with a
    per-device secret. A captured transmission cannot be replayed because the counter
    has already advanced past it. See docs/05-duress-device-security.md.
    """

    __tablename__ = "duress_devices"
    __table_args__ = (UniqueConstraint("store_id", "serial", name="uq_duress_store_serial"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    serial: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    shared_secret: Mapped[str] = mapped_column(String(128), nullable=False)
    counter: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    battery_percent: Mapped[int | None] = mapped_column(Integer)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    store: Mapped[Store] = relationship()


# --------------------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------------------


class Event(Base):
    """A behavioural observation published by an edge worker.

    Contains no imagery and no biometric data: only a score and the derived features
    that produced it. That makes the record explainable to a member of staff and to a
    regulator, which a raw model logit is not.
    """

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("camera_id", "nonce", name="uq_event_camera_nonce"),
        Index("ix_event_store_time", "store_id", "occurred_at"),
        Index("ix_event_expiry", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    camera_id: Mapped[int] = mapped_column(ForeignKey("cameras.id"), nullable=False)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("zones.id"))

    event_type: Mapped[str] = mapped_column(String(48), nullable=False)

    # Ephemeral, per-camera tracker handle. Not an identity and not stable across
    # cameras or across a re-entry into frame. Used only to suppress duplicate alerts.
    track_ref: Mapped[str] = mapped_column(String(64), nullable=False)

    raw_score: Mapped[float] = mapped_column(Float, nullable=False)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    model_version: Mapped[str] = mapped_column(String(48), default="unknown")

    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: Anti-replay: unique per camera, enforced at the database level.
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)

    camera: Mapped[Camera] = relationship()
    zone: Mapped[Zone | None] = relationship()


class Alert(Base):
    """A prompt shown to staff. Advisory only.

    Nothing downstream of this record is automated. There is no ban list to write to,
    no till lock to trigger, and no message sent to anyone outside the store.
    """

    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alert_store_status", "store_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), nullable=False)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("zones.id"))

    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default=AlertStatus.OPEN.value)
    headline: Mapped[str] = mapped_column(String(200), nullable=False)
    rationale: Mapped[dict] = mapped_column(JSON, default=dict)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    disposition: Mapped[str | None] = mapped_column(String(48))
    disposition_note: Mapped[str | None] = mapped_column(Text)

    event: Mapped[Event] = relationship()
    zone: Mapped[Zone | None] = relationship()
    acknowledged_by: Mapped[User | None] = relationship(foreign_keys=[acknowledged_by_id])
    resolved_by: Mapped[User | None] = relationship(foreign_keys=[resolved_by_id])

    @property
    def time_to_acknowledge_seconds(self) -> float | None:
        if self.acknowledged_at is None:
            return None
        from core.util import as_utc

        return (as_utc(self.acknowledged_at) - as_utc(self.created_at)).total_seconds()


class DuressActivation(Base):
    __tablename__ = "duress_activations"

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("duress_devices.id"))
    raised_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("zones.id"))
    silent: Mapped[bool] = mapped_column(Boolean, default=True)
    public_broadcast: Mapped[bool] = mapped_column(Boolean, default=False)
    counter_value: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32), default="fob")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome_note: Mapped[str | None] = mapped_column(Text)

    device: Mapped[DuressDevice | None] = relationship()
    zone: Mapped[Zone | None] = relationship()
    raised_by: Mapped[User | None] = relationship(foreign_keys=[raised_by_id])
    acknowledged_by: Mapped[User | None] = relationship(foreign_keys=[acknowledged_by_id])


# --------------------------------------------------------------------------------------
# Accountability
# --------------------------------------------------------------------------------------


class AuditRecord(Base):
    """Append-only, hash-chained audit entry.

    Each record commits to its predecessor via ``prev_hash``, so altering or removing
    any historical row invalidates every hash after it. This does not make tampering
    impossible; it makes silent tampering impossible, which is the achievable goal for
    a log that lives in the same database as the data it describes.

    Chain verification lives in :func:`core.audit.verify_chain`, and the auditor role
    can run it from the dashboard.
    """

    __tablename__ = "audit_records"
    __table_args__ = (
        UniqueConstraint("store_id", "seq", name="uq_audit_store_seq"),
        Index("ix_audit_store_time", "store_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    store_id: Mapped[int] = mapped_column(ForeignKey("stores.id"), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)

    actor_type: Mapped[str] = mapped_column(String(24), nullable=False)  # user|edge|device|system
    actor_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(48))
    target_ref: Mapped[str | None] = mapped_column(String(120))
    outcome: Mapped[str] = mapped_column(String(24), default="success")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
