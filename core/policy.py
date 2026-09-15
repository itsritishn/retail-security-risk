"""Alert policy engine.

Turns a scored behavioural event into a decision: prompt a member of staff, or stay
quiet. Three things drive the design.

**Explainability.** Every decision carries a ``rationale`` listing each contribution to
the final score. A member of staff who is asked to walk over to an aisle deserves to
know why, and "the model said 0.81" is not a reason. It is also what makes the system
defensible if a customer complains.

**Alert fatigue is the primary failure mode.** A loss-prevention tool that cries wolf
gets ignored within a week, and then it is worse than nothing because it consumes
attention while providing no coverage. Cooldowns and per-zone budgets are therefore
first-class controls, not tuning knobs.

**Fairness is enforced, not promised.** Features that could encode a protected
characteristic are rejected at ingest. See :data:`PROHIBITED_FEATURE_KEYS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.config import Settings
from core.models import Alert, AlertStatus, Event, EventType, Zone
from core.util import clamp, utcnow

# --------------------------------------------------------------------------------------
# Fairness guard
# --------------------------------------------------------------------------------------

#: Feature names an edge worker must never send. Presence of any of these causes the
#: event to be rejected outright with HTTP 422.
#:
#: This is the single most important dozen lines in the codebase. Retail surveillance AI
#: has a documented history of disproportionately flagging particular groups, and the
#: usual cause is a feature set that quietly proxies for appearance. The system cannot
#: discriminate on an attribute it structurally refuses to receive, and enforcing that
#: in code rather than in a policy document is the difference between a control and an
#: intention.
PROHIBITED_FEATURE_KEYS: frozenset[str] = frozenset(
    {
        "age",
        "age_estimate",
        "age_bracket",
        "gender",
        "sex",
        "ethnicity",
        "race",
        "skin_tone",
        "skin_colour",
        "skin_color",
        "face_embedding",
        "face_descriptor",
        "facial_landmarks",
        "identity",
        "person_id",
        "customer_id",
        "name",
        "gait_signature",
        "iris",
        "clothing_brand",
        "religious_dress",
        "hair_colour",
        "hair_color",
        "disability",
        "mobility_aid",
        "emotion",
        "affect",
        "sentiment",
    }
)


class ProhibitedFeatureError(ValueError):
    """Raised when an event carries a feature that must never be processed."""

    def __init__(self, offending: set[str]) -> None:
        self.offending = sorted(offending)
        super().__init__(
            "Event rejected: features encode or proxy a protected characteristic: "
            + ", ".join(self.offending)
        )


def assert_features_permitted(features: dict) -> None:
    """Reject any feature set touching a prohibited attribute.

    Checks nested dictionaries too, since burying ``{"demographics": {"age": 31}}`` one
    level down would otherwise defeat a flat check.
    """
    offending: set[str] = set()

    def _walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).strip().lower() in PROHIBITED_FEATURE_KEYS:
                    offending.add(str(key))
                _walk(value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item)

    _walk(features)
    if offending:
        raise ProhibitedFeatureError(offending)


# --------------------------------------------------------------------------------------
# Scoring weights
# --------------------------------------------------------------------------------------

#: Per-event-type confidence multipliers.
#:
#: A concealment gesture is a far stronger signal than someone standing in an aisle for
#: a while, and the weights say so explicitly rather than leaving it to a learned bias
#: term nobody can inspect. Prolonged dwell is heavily discounted: browsing is not a
#: crime, and treating it as one is how these systems lose staff trust.
EVENT_TYPE_WEIGHTS: dict[str, float] = {
    EventType.CONCEALMENT.value: 1.00,
    EventType.SHELF_SWEEP.value: 0.95,
    EventType.IN_STORE_CONSUMPTION.value: 0.80,
    EventType.PROLONGED_DWELL.value: 0.55,
    EventType.OBSCURED_VIEW.value: 0.70,
    EventType.HEARTBEAT.value: 0.00,
}

#: Bounded adjustments applied on top of the weighted base score.
#: Each is capped so no single feature can dominate the outcome.
FEATURE_ADJUSTMENTS: dict[str, float] = {
    "bag_interaction": 0.06,
    "repeat_zone_entries": 0.04,
    "tag_removal_motion": 0.08,
    "body_shielding": 0.05,
}

#: Confidence *reducers*. Signals that the observation itself is unreliable must pull
#: the score down, otherwise a half-occluded blur becomes an accusation.
FEATURE_PENALTIES: dict[str, float] = {
    "occlusion_ratio": -0.20,
    "track_fragmentation": -0.15,
    "low_light": -0.10,
    "crowd_density": -0.08,
}

#: Event types that never produce a customer-facing prompt.
NON_ALERTING_TYPES = frozenset({EventType.HEARTBEAT.value})

#: Maximum prompts per zone inside :data:`ZONE_BUDGET_WINDOW_MINUTES`.
ZONE_ALERT_BUDGET = 6
ZONE_BUDGET_WINDOW_MINUTES = 10


# --------------------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------------------


@dataclass
class Contribution:
    label: str
    delta: float
    detail: str = ""

    def as_dict(self) -> dict:
        return {"label": self.label, "delta": round(self.delta, 4), "detail": self.detail}


@dataclass
class PolicyDecision:
    should_alert: bool
    score: float
    severity: str
    headline: str
    escalate: bool = False
    suppressed_reason: str | None = None
    contributions: list[Contribution] = field(default_factory=list)

    def rationale(self) -> dict:
        return {
            "final_score": round(self.score, 4),
            "severity": self.severity,
            "escalate": self.escalate,
            "suppressed_reason": self.suppressed_reason,
            "contributions": [c.as_dict() for c in self.contributions],
            "human_review_required": True,
        }


def severity_for(score: float, settings: Settings) -> str:
    if score >= settings.escalate_threshold:
        return "high"
    if score >= settings.alert_threshold:
        return "medium"
    if score >= settings.alert_threshold * 0.7:
        return "low"
    return "info"


def score_event(
    *,
    event_type: str,
    raw_score: float,
    features: dict,
    zone: Zone | None,
) -> tuple[float, list[Contribution]]:
    """Combine the model score with zone context and reliability signals.

    Pure function: no database access and no clock reads, so it is directly unit
    testable and its behaviour is reproducible from its arguments alone.
    """
    contributions: list[Contribution] = []

    base = clamp(float(raw_score))
    type_weight = EVENT_TYPE_WEIGHTS.get(event_type, 0.5)
    score = base * type_weight

    contributions.append(
        Contribution("model_score", base, f"raw concealment score for {event_type}")
    )
    contributions.append(
        Contribution(
            "event_type_weight",
            score - base,
            f"{event_type} carries weight {type_weight:.2f}",
        )
    )

    if zone is not None:
        # Bounded so that a mis-set risk weight cannot manufacture an alert on its own.
        zone_delta = clamp((zone.risk_weight - 1.0) * 0.12, -0.15, 0.15)
        if zone_delta:
            score += zone_delta
            contributions.append(
                Contribution(
                    "zone_risk", zone_delta, f"zone {zone.code} weight {zone.risk_weight:.2f}"
                )
            )
        if zone.is_high_value:
            score += 0.04
            contributions.append(
                Contribution("high_value_zone", 0.04, f"{zone.name} holds high-loss lines")
            )

    for key, weight in FEATURE_ADJUSTMENTS.items():
        value = features.get(key)
        if value is None:
            continue
        magnitude = _as_unit(value)
        if magnitude <= 0:
            continue
        delta = weight * magnitude
        score += delta
        contributions.append(Contribution(key, delta, f"observed at {magnitude:.2f}"))

    for key, weight in FEATURE_PENALTIES.items():
        value = features.get(key)
        if value is None:
            continue
        magnitude = _as_unit(value)
        if magnitude <= 0:
            continue
        delta = weight * magnitude
        score += delta
        contributions.append(
            Contribution(key, delta, f"reduces confidence, observed at {magnitude:.2f}")
        )

    return clamp(score), contributions


def _as_unit(value: object) -> float:
    """Coerce a feature value into [0, 1]. Booleans map to 1.0 / 0.0."""
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return clamp(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def headline_for(event_type: str, zone: Zone | None) -> str:
    where = zone.name if zone is not None else "unmapped area"
    phrasing = {
        EventType.CONCEALMENT.value: f"Possible concealment in {where}",
        EventType.SHELF_SWEEP.value: f"Rapid multi-item removal in {where}",
        EventType.PROLONGED_DWELL.value: f"Extended dwell in {where}",
        EventType.IN_STORE_CONSUMPTION.value: f"Possible in-store consumption in {where}",
        EventType.OBSCURED_VIEW.value: f"Camera view obstructed covering {where}",
    }
    return phrasing.get(event_type, f"Behavioural signal in {where}")


# --------------------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------------------


class PolicyEngine:
    """Stateful wrapper adding cooldown and budget checks over :func:`score_event`."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(self, session: Session, event: Event, zone: Zone | None) -> PolicyDecision:
        score, contributions = score_event(
            event_type=event.event_type,
            raw_score=event.raw_score,
            features=event.features or {},
            zone=zone,
        )
        severity = severity_for(score, self.settings)
        headline = headline_for(event.event_type, zone)

        if event.event_type in NON_ALERTING_TYPES:
            return PolicyDecision(
                should_alert=False,
                score=score,
                severity="info",
                headline=headline,
                suppressed_reason="non_alerting_event_type",
                contributions=contributions,
            )

        # Camera tampering bypasses the score threshold entirely. An obstructed lens is
        # an integrity failure in the control itself, so it must surface even though the
        # behavioural score is meaningless when the view is blocked.
        if event.event_type == EventType.OBSCURED_VIEW.value:
            return PolicyDecision(
                should_alert=True,
                score=max(score, self.settings.alert_threshold),
                severity="medium",
                headline=headline,
                escalate=True,
                contributions=contributions
                + [Contribution("tamper_override", 0.0, "integrity alert, threshold bypassed")],
            )

        if score < self.settings.alert_threshold:
            return PolicyDecision(
                should_alert=False,
                score=score,
                severity=severity,
                headline=headline,
                suppressed_reason="below_threshold",
                contributions=contributions,
            )

        if self._in_cooldown(session, event):
            return PolicyDecision(
                should_alert=False,
                score=score,
                severity=severity,
                headline=headline,
                suppressed_reason="track_cooldown",
                contributions=contributions,
            )

        if self._zone_budget_exhausted(session, event):
            # Deliberately fails quiet rather than open. A storm of prompts in one aisle
            # means the model is confused or the camera has moved, and burying staff in
            # notifications guarantees they stop reading all of them. The suppression is
            # audited, so the condition is visible to whoever tunes the system.
            return PolicyDecision(
                should_alert=False,
                score=score,
                severity=severity,
                headline=headline,
                suppressed_reason="zone_budget_exhausted",
                contributions=contributions,
            )

        return PolicyDecision(
            should_alert=True,
            score=score,
            severity=severity,
            headline=headline,
            escalate=score >= self.settings.escalate_threshold,
            contributions=contributions,
        )

    def _in_cooldown(self, session: Session, event: Event) -> bool:
        """True if this tracked subject already produced a prompt very recently."""
        cutoff = utcnow() - timedelta(seconds=self.settings.alert_cooldown_seconds)
        existing = session.execute(
            select(func.count(Alert.id))
            .join(Event, Alert.event_id == Event.id)
            .where(
                Event.camera_id == event.camera_id,
                Event.track_ref == event.track_ref,
                Alert.created_at >= cutoff,
            )
        ).scalar_one()
        return int(existing) > 0

    def _zone_budget_exhausted(self, session: Session, event: Event) -> bool:
        if event.zone_id is None:
            return False
        cutoff = utcnow() - timedelta(minutes=ZONE_BUDGET_WINDOW_MINUTES)
        count = session.execute(
            select(func.count(Alert.id)).where(
                Alert.zone_id == event.zone_id,
                Alert.created_at >= cutoff,
                Alert.status != AlertStatus.RESOLVED.value,
            )
        ).scalar_one()
        return int(count) >= ZONE_ALERT_BUDGET
