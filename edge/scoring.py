"""Concealment scoring.

A transparent weighted model over the features from :mod:`edge.features`. Every term has a
name and a stated reason, so the score can be explained end to end.

This is a **baseline**, and the docstring says so deliberately rather than dressing it up.
The intended trajectory is:

1. This rule-based scorer, which needs no training data and is fully inspectable. It gets a
   working system in front of staff, which is what generates the labels everything else
   depends on.
2. A temporal model (ST-GCN or a small transformer over pose sequences) trained on PoseLift
   and evaluated against the store's own staff dispositions.
3. Periodic retraining driven by those dispositions, with the threshold sweep in
   :mod:`analytics.metrics` deciding whether a candidate model is actually better.

Starting at step 2 is the common mistake. Without step 1 there are no labels from your own
store, and a model tuned on someone else's aisles will disappoint in yours.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.util import clamp, new_nonce
from edge.backends.base import PoseFrame
from edge.features import (
    ANALYSIS_WINDOW_SECONDS,
    DWELL_ATTENTION_SECONDS,
    extract_features,
)
from edge.tracking import Track

logger = logging.getLogger("sentinelfloor.edge.scoring")

MODEL_VERSION = "rule-baseline-0.1.0"

#: Positive evidence weights. They sum to more than 1.0 before clamping, so a strong
#: pattern saturates rather than needing every term to fire.
EVIDENCE_WEIGHTS: dict[str, float] = {
    # The core signal: reached out, brought the hand inside the body silhouette, kept it
    # there, and did not put anything back.
    "concealment_pattern": 0.58,
    # Longer holds are more consistent with putting something away than with scratching.
    "body_hold_duration": 0.16,
    # A deep reach is more consistent with taking from a shelf than with gesturing.
    "peak_extension": 0.10,
    # Below hip height suggests pocket, waistband, or bag rather than a basket at chest.
    "low_tuck": 0.09,
    # Turning to put the body between hands and camera.
    "body_shielding": 0.08,
    # Repeated cycles without replacing anything.
    "repeat_without_replace": 0.07,
}

#: Score below which nothing is published at all.
#:
#: Set well under the core service's alert threshold on purpose. The edge publishes
#: moderate-confidence events so the core has data to compute analytics and tune thresholds
#: against, while the decision about whether to interrupt a member of staff stays with the
#: core policy engine. Splitting "what did we see" from "should we say something" keeps the
#: judgement in one place.
PUBLISH_FLOOR = 0.35

#: Minimum observations before any behavioural claim is made. Three frames of a person is
#: not evidence of anything.
MIN_OBSERVATIONS = 8


@dataclass
class BehaviourEvent:
    """A scored observation ready for publication."""

    event_type: str
    track_ref: str
    score: float
    features: dict
    occurred_at: str
    nonce: str = field(default_factory=new_nonce)
    model_version: str = MODEL_VERSION

    def as_payload(self, camera_code: str) -> dict:
        return {
            "camera_code": camera_code,
            "event_type": self.event_type,
            "track_ref": self.track_ref,
            "raw_score": round(self.score, 4),
            "features": self.features,
            "occurred_at": self.occurred_at,
            "nonce": self.nonce,
            "model_version": self.model_version,
        }


def score_concealment(features: dict) -> tuple[float, list[tuple[str, float, str]]]:
    """Weighted evidence score with a per-term breakdown.

    Returns ``(score, [(term, contribution, explanation)])``. The breakdown travels with
    the event, which is what lets the dashboard answer "why was this raised?" without
    anyone having to trust the number.
    """
    contributions: list[tuple[str, float, str]] = []
    score = 0.0

    if features.get("concealment_pattern"):
        weight = EVIDENCE_WEIGHTS["concealment_pattern"]
        score += weight
        contributions.append(
            (
                "concealment_pattern",
                weight,
                "reached out, then brought the hand to the body and kept it there",
            )
        )

    hold = float(features.get("longest_body_hold_seconds", 0.0) or 0.0)
    if hold > 0:
        # Saturates at three seconds: beyond that, longer tells us nothing extra.
        magnitude = clamp(hold / 3.0)
        delta = EVIDENCE_WEIGHTS["body_hold_duration"] * magnitude
        score += delta
        contributions.append(
            ("body_hold_duration", delta, f"hand held at the body for {hold:.1f}s")
        )

    peak = float(features.get("peak_extension", 0.0) or 0.0)
    if peak > 1.75:
        magnitude = clamp((peak - 1.75) / 1.0)
        delta = EVIDENCE_WEIGHTS["peak_extension"] * magnitude
        score += delta
        contributions.append(
            ("peak_extension", delta, f"arm extended to {peak:.2f}x shoulder width")
        )

    if features.get("low_tuck"):
        weight = EVIDENCE_WEIGHTS["low_tuck"]
        score += weight
        contributions.append(
            ("low_tuck", weight, "hand came to rest at or below hip height")
        )

    shielding = float(features.get("body_shielding", 0.0) or 0.0)
    if shielding > 0:
        delta = EVIDENCE_WEIGHTS["body_shielding"] * shielding
        score += delta
        contributions.append(
            ("body_shielding", delta, "turned so the body was between hands and camera")
        )

    reaches = int(features.get("reach_count", 0) or 0)
    replaces = int(features.get("return_to_shelf_count", 0) or 0)
    unreplaced = max(0, reaches - replaces)
    if unreplaced >= 2:
        magnitude = clamp((unreplaced - 1) / 3.0)
        delta = EVIDENCE_WEIGHTS["repeat_without_replace"] * magnitude
        score += delta
        contributions.append(
            (
                "repeat_without_replace",
                delta,
                f"{unreplaced} reaches without the hand returning to the shelf",
            )
        )

    # Replacement evidence actively argues against concealment. Someone who put the item
    # back is the single most common benign case, and failing to credit it is how these
    # systems end up flagging ordinary shopping.
    if replaces > 0 and not features.get("concealment_pattern"):
        delta = -0.25 * clamp(replaces / 2.0)
        score += delta
        contributions.append(
            ("item_replaced", delta, f"hand returned to the shelf {replaces} time(s)")
        )

    return clamp(score), contributions


class BehaviourAnalyser:
    """Turns tracks into scored events for one camera."""

    def __init__(self, *, publish_floor: float = PUBLISH_FLOOR) -> None:
        self.publish_floor = publish_floor
        self._dwell_reported: set[str] = set()

    def observe(self, tracks: list[Track], frame: PoseFrame) -> list[BehaviourEvent]:
        events: list[BehaviourEvent] = []

        for track in tracks:
            if track.observation_count < MIN_OBSERVATIONS:
                continue

            features = extract_features(track, frame)
            occurred_at = frame.timestamp.isoformat()

            score, contributions = score_concealment(features)
            features["score_breakdown"] = [
                {"term": term, "delta": round(delta, 4), "why": why}
                for term, delta, why in contributions
            ]

            event_type = self._classify(features)

            if event_type is not None and score >= self.publish_floor:
                # One event of each type per track. Repeated publication of the same
                # gesture would defeat the core's deduplication and inflate every metric.
                if event_type not in track.reported_event_types:
                    track.reported_event_types.add(event_type)
                    events.append(
                        BehaviourEvent(
                            event_type=event_type,
                            track_ref=track.track_ref,
                            score=score,
                            features=features,
                            occurred_at=occurred_at,
                        )
                    )

            dwell_event = self._maybe_dwell(track, features, occurred_at)
            if dwell_event is not None:
                events.append(dwell_event)

        return events

    def _classify(self, features: dict) -> str | None:
        """Map the feature pattern onto an event type."""
        if features.get("rapid_repeat") and features.get("concealment_pattern"):
            return "shelf_sweep"
        if features.get("concealment_pattern"):
            return "concealment"
        return None

    def _maybe_dwell(
        self, track: Track, features: dict, occurred_at: str
    ) -> BehaviourEvent | None:
        """Emit a low-confidence dwell event, once per track.

        Scored low and weighted down further by the core policy engine. Standing in an aisle
        for a while is normal behaviour and must not on its own bring a member of staff over;
        it is published because it is useful context in the analytics, not because it is
        evidence.
        """
        if not features.get("prolonged_dwell"):
            return None
        if track.track_ref in self._dwell_reported:
            return None

        self._dwell_reported.add(track.track_ref)

        dwell = float(features.get("dwell_seconds", 0.0) or 0.0)
        score = clamp(0.30 + 0.20 * clamp((dwell - DWELL_ATTENTION_SECONDS) / 60.0))

        return BehaviourEvent(
            event_type="prolonged_dwell",
            track_ref=track.track_ref,
            score=score,
            features={
                **features,
                "score_breakdown": [
                    {
                        "term": "dwell_seconds",
                        "delta": round(score, 4),
                        "why": (
                            f"present for {dwell:.0f}s, over the "
                            f"{DWELL_ATTENTION_SECONDS:.0f}s attention threshold"
                        ),
                    }
                ],
            },
            occurred_at=occurred_at,
        )

    @staticmethod
    def window_seconds() -> float:
        return ANALYSIS_WINDOW_SECONDS
