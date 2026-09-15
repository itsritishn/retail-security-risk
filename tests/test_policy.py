"""Policy engine behaviour.

The fairness tests are the ones that matter most. If :func:`assert_features_permitted` ever
regresses, the system's central constraint is gone and nothing else in the project matters.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from core.config import get_settings
from core.models import Alert, AlertStatus, Camera, Event, EventType, Zone
from core.policy import (
    PROHIBITED_FEATURE_KEYS,
    PolicyEngine,
    ProhibitedFeatureError,
    ZONE_ALERT_BUDGET,
    assert_features_permitted,
    score_event,
    severity_for,
)
from core.util import hours_from_now, utcnow


# ---------------------------------------------------------------- fairness guard


def test_clean_features_are_permitted():
    assert_features_permitted(
        {"concealment_pattern": True, "peak_extension": 2.1, "occlusion_ratio": 0.2}
    )


@pytest.mark.parametrize("key", ["age", "gender", "ethnicity", "skin_tone", "face_embedding"])
def test_prohibited_top_level_features_are_rejected(key: str):
    with pytest.raises(ProhibitedFeatureError) as exc_info:
        assert_features_permitted({key: "anything"})
    assert key in exc_info.value.offending


def test_prohibited_features_are_rejected_when_nested():
    """A flat check would miss this, which is exactly how such a control gets bypassed."""
    with pytest.raises(ProhibitedFeatureError) as exc_info:
        assert_features_permitted(
            {"context": {"demographics": {"age": 31, "gender": "m"}}}
        )
    assert "age" in exc_info.value.offending
    assert "gender" in exc_info.value.offending


def test_prohibited_features_are_rejected_inside_lists():
    with pytest.raises(ProhibitedFeatureError):
        assert_features_permitted({"people": [{"identity": "abc123"}]})


def test_prohibited_key_matching_is_case_insensitive():
    with pytest.raises(ProhibitedFeatureError):
        assert_features_permitted({"Ethnicity": "x"})


def test_emotion_and_affect_are_prohibited():
    """Emotion recognition carries specific duties under the EU AI Act and is out of scope."""
    assert "emotion" in PROHIBITED_FEATURE_KEYS
    assert "affect" in PROHIBITED_FEATURE_KEYS
    with pytest.raises(ProhibitedFeatureError):
        assert_features_permitted({"emotion": "nervous"})


# --------------------------------------------------------------------- scoring


def test_concealment_scores_above_prolonged_dwell():
    """Standing in an aisle must never score like a concealment gesture."""
    concealment, _ = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=0.8,
        features={},
        zone=None,
    )
    dwell, _ = score_event(
        event_type=EventType.PROLONGED_DWELL.value,
        raw_score=0.8,
        features={},
        zone=None,
    )
    assert concealment > dwell
    assert dwell < get_settings().alert_threshold


def test_high_risk_zone_raises_score(zones):
    low, _ = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=0.7,
        features={},
        zone=zones["ambient"],
    )
    high, _ = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=0.7,
        features={},
        zone=zones["confectionery"],
    )
    assert high > low


def test_zone_influence_is_bounded(session: Session, store):
    """A mis-set risk weight must not be able to manufacture an alert on its own."""
    absurd = Zone(
        store_id=store.id, code="absurd", name="Absurd", risk_weight=99.0
    )
    session.add(absurd)
    session.commit()

    score, _ = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=0.10,
        features={},
        zone=absurd,
    )
    assert score < get_settings().alert_threshold


def test_occlusion_reduces_score():
    """An unreliable observation must lower confidence, not be ignored."""
    clear, _ = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=0.85,
        features={},
        zone=None,
    )
    occluded, _ = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=0.85,
        features={"occlusion_ratio": 0.9},
        zone=None,
    )
    assert occluded < clear


def test_score_is_clamped_to_unit_interval():
    score, _ = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=1.0,
        features={
            "bag_interaction": True,
            "tag_removal_motion": True,
            "body_shielding": 1.0,
            "repeat_zone_entries": 1.0,
        },
        zone=None,
    )
    assert 0.0 <= score <= 1.0


def test_contributions_explain_the_score():
    """Every prompt has to be explainable, so the breakdown must not be empty."""
    _, contributions = score_event(
        event_type=EventType.CONCEALMENT.value,
        raw_score=0.8,
        features={"bag_interaction": True, "occlusion_ratio": 0.3},
        zone=None,
    )
    labels = {c.label for c in contributions}
    assert "model_score" in labels
    assert "bag_interaction" in labels
    assert "occlusion_ratio" in labels


def test_severity_bands(settings):
    assert severity_for(0.95, settings) == "high"
    assert severity_for(0.75, settings) == "medium"
    assert severity_for(0.55, settings) == "low"
    assert severity_for(0.10, settings) == "info"


# ---------------------------------------------------------------------- engine


def _make_event(
    session: Session,
    camera: Camera,
    *,
    event_type: str = EventType.CONCEALMENT.value,
    raw_score: float = 0.95,
    track_ref: str = "track-1",
    nonce: str | None = None,
) -> Event:
    event = Event(
        store_id=camera.store_id,
        camera_id=camera.id,
        zone_id=camera.zone_id,
        event_type=event_type,
        track_ref=track_ref,
        raw_score=raw_score,
        features={},
        model_version="test",
        occurred_at=utcnow(),
        expires_at=hours_from_now(72),
        nonce=nonce or f"nonce-{track_ref}-{raw_score}",
    )
    session.add(event)
    session.flush()
    return event


def test_engine_alerts_on_strong_concealment(session: Session, camera: Camera, settings):
    event = _make_event(session, camera, raw_score=0.95)
    decision = PolicyEngine(settings).evaluate(session, event, camera.zone)

    assert decision.should_alert is True
    assert decision.severity in {"medium", "high"}
    assert decision.rationale()["human_review_required"] is True


def test_engine_stays_quiet_below_threshold(session: Session, camera: Camera, settings):
    event = _make_event(session, camera, raw_score=0.2)
    decision = PolicyEngine(settings).evaluate(session, event, camera.zone)

    assert decision.should_alert is False
    assert decision.suppressed_reason == "below_threshold"


def test_heartbeat_never_alerts(session: Session, camera: Camera, settings):
    event = _make_event(
        session, camera, event_type=EventType.HEARTBEAT.value, raw_score=1.0
    )
    decision = PolicyEngine(settings).evaluate(session, event, camera.zone)

    assert decision.should_alert is False
    assert decision.suppressed_reason == "non_alerting_event_type"


def test_obscured_view_bypasses_threshold(session: Session, camera: Camera, settings):
    """Camera tampering is an integrity failure and must surface regardless of score."""
    event = _make_event(
        session, camera, event_type=EventType.OBSCURED_VIEW.value, raw_score=0.05
    )
    decision = PolicyEngine(settings).evaluate(session, event, camera.zone)

    assert decision.should_alert is True
    assert decision.escalate is True


def test_cooldown_suppresses_repeat_alerts_for_one_track(
    session: Session, camera: Camera, settings
):
    first = _make_event(session, camera, track_ref="same-track", nonce="n1")
    decision = PolicyEngine(settings).evaluate(session, first, camera.zone)
    assert decision.should_alert is True

    session.add(
        Alert(
            store_id=camera.store_id,
            event_id=first.id,
            zone_id=camera.zone_id,
            score=decision.score,
            severity=decision.severity,
            status=AlertStatus.OPEN.value,
            headline=decision.headline,
            rationale=decision.rationale(),
        )
    )
    session.flush()

    second = _make_event(session, camera, track_ref="same-track", nonce="n2")
    repeat = PolicyEngine(settings).evaluate(session, second, camera.zone)

    assert repeat.should_alert is False
    assert repeat.suppressed_reason == "track_cooldown"


def test_zone_budget_caps_alert_storms(session: Session, camera: Camera, settings):
    """Alert fatigue is the primary failure mode, so the budget must actually bite."""
    engine = PolicyEngine(settings)

    for index in range(ZONE_ALERT_BUDGET):
        event = _make_event(session, camera, track_ref=f"t{index}", nonce=f"nonce-{index}")
        decision = engine.evaluate(session, event, camera.zone)
        assert decision.should_alert is True
        session.add(
            Alert(
                store_id=camera.store_id,
                event_id=event.id,
                zone_id=camera.zone_id,
                score=decision.score,
                severity=decision.severity,
                status=AlertStatus.OPEN.value,
                headline=decision.headline,
                rationale=decision.rationale(),
            )
        )
        session.flush()

    overflow = _make_event(session, camera, track_ref="t-overflow", nonce="nonce-overflow")
    blocked = engine.evaluate(session, overflow, camera.zone)

    assert blocked.should_alert is False
    assert blocked.suppressed_reason == "zone_budget_exhausted"
