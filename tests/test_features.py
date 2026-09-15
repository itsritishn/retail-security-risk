"""Behavioural feature extraction and scoring.

The load-bearing test in this file is
:func:`test_replacing_an_item_is_not_flagged_as_concealment`. Distinguishing "picked it up
and put it back" from "picked it up and pocketed it" is the entire problem. A detector that
cannot do that will flag ordinary shopping all day, staff will stop trusting it within a
week, and the system will be worse than nothing because it consumes attention while
providing no coverage.
"""

from __future__ import annotations

import pytest

from edge.backends.base import PoseFrame
from edge.backends.synthetic import scripted_frames
from edge.features import (
    BODY_HOLD_SECONDS,
    REACH_THRESHOLD,
    extract_features,
    scan_gesture_pattern,
    wrist_extensions,
)
from edge.scoring import BehaviourAnalyser, score_concealment
from edge.tracking import Tracker


def _track_from(scenario: str, **kwargs):
    """Run one scripted behaviour through the tracker and return the resulting track."""
    frames = scripted_frames(scenario, **kwargs)
    tracker = Tracker()
    last_frame: PoseFrame | None = None

    for frame in frames:
        tracker.update(frame)
        last_frame = frame

    tracks = tracker.tracks
    assert tracks, f"no track produced for scenario {scenario!r}"
    assert last_frame is not None
    return max(tracks, key=lambda t: t.observation_count), last_frame


# ------------------------------------------------------------------- geometry


def test_wrist_extension_is_scale_invariant():
    """The same gesture must score the same near and far from the camera.

    Without normalisation by shoulder width, the detector mostly fires on whoever walks
    closest to the lens.
    """
    near = scripted_frames("conceal", scale=1.4)
    far = scripted_frames("conceal", scale=0.7)

    def peak(frames):
        values = []
        for frame in frames:
            state = wrist_extensions(frame.detections[0])
            if state.max_extension is not None:
                values.append(state.max_extension)
        return max(values)

    assert peak(near) == pytest.approx(peak(far), abs=0.25)


def test_reach_produces_high_extension():
    frames = scripted_frames("conceal")
    peaks = [
        wrist_extensions(frame.detections[0]).max_extension or 0.0 for frame in frames
    ]
    assert max(peaks) > REACH_THRESHOLD


# ------------------------------------------------------- the core distinction


def test_concealment_pattern_is_detected():
    track, _ = _track_from("conceal")
    pattern = scan_gesture_pattern(track.window(8.0))

    assert pattern.reach_count >= 1
    assert pattern.longest_body_hold_seconds >= BODY_HOLD_SECONDS
    assert pattern.concealment_pattern is True


def test_replacing_an_item_is_not_flagged_as_concealment():
    """The false positive that matters most. Everyone puts things back."""
    track, _ = _track_from("replace")
    pattern = scan_gesture_pattern(track.window(8.0))

    assert pattern.reach_count >= 1
    assert pattern.return_to_shelf_count >= 1
    assert pattern.concealment_pattern is False


def test_browsing_produces_no_reach_pattern():
    track, _ = _track_from("browse")
    pattern = scan_gesture_pattern(track.window(8.0))

    assert pattern.concealment_pattern is False
    assert pattern.reach_count == 0


def test_shelf_sweep_registers_repeated_reaches():
    track, _ = _track_from("sweep")
    pattern = scan_gesture_pattern(track.window(10.0))

    assert pattern.reach_count >= 3
    assert pattern.rapid_repeat is True


# -------------------------------------------------------------------- scoring


def test_concealment_scores_higher_than_replacement():
    conceal_track, conceal_frame = _track_from("conceal")
    replace_track, replace_frame = _track_from("replace")

    conceal_score, _ = score_concealment(extract_features(conceal_track, conceal_frame))
    replace_score, _ = score_concealment(extract_features(replace_track, replace_frame))

    assert conceal_score > replace_score
    # The margin must be wide enough to survive a threshold anywhere sensible, not just
    # ordered by a hair.
    assert conceal_score - replace_score > 0.25


def test_browsing_scores_near_zero():
    track, frame = _track_from("browse")
    score, _ = score_concealment(extract_features(track, frame))
    assert score < 0.2


def test_score_breakdown_explains_the_decision():
    track, frame = _track_from("conceal")
    _, contributions = score_concealment(extract_features(track, frame))

    assert contributions, "a prompt with no explanation cannot be shown to staff"
    terms = {term for term, _, _ in contributions}
    assert "concealment_pattern" in terms
    for _, _, why in contributions:
        assert why, "every contribution needs a human-readable reason"


def test_replacement_is_credited_against_the_score():
    """Putting the item back must actively reduce the score, not merely fail to raise it."""
    features = {
        "reach_count": 2,
        "return_to_shelf_count": 2,
        "concealment_pattern": False,
        "peak_extension": 2.2,
    }
    score, contributions = score_concealment(features)
    terms = {term for term, _, _ in contributions}

    assert "item_replaced" in terms
    negative = [delta for term, delta, _ in contributions if term == "item_replaced"]
    assert negative and negative[0] < 0
    assert score < 0.2


def test_occlusion_is_reported_so_confidence_can_be_reduced():
    track, frame = _track_from("conceal", occluded=True)
    features = extract_features(track, frame)

    assert features["occlusion_ratio"] > 0.1
    assert "track_fragmentation" in features
    assert "crowd_density" in features


# -------------------------------------------------------------------- analyser


def test_analyser_emits_concealment_event():
    frames = scripted_frames("conceal")
    tracker = Tracker()
    analyser = BehaviourAnalyser()
    events = []

    for frame in frames:
        tracks = tracker.update(frame)
        events.extend(analyser.observe(tracks, frame))

    types = {event.event_type for event in events}
    assert "concealment" in types or "shelf_sweep" in types


def test_analyser_stays_quiet_on_browsing():
    frames = scripted_frames("browse")
    tracker = Tracker()
    analyser = BehaviourAnalyser()
    events = []

    for frame in frames:
        tracks = tracker.update(frame)
        events.extend(analyser.observe(tracks, frame))

    assert [event for event in events if event.event_type == "concealment"] == []


def test_analyser_reports_each_gesture_once_per_track():
    """Repeated publication of the same gesture would defeat deduplication and inflate
    every metric."""
    frames = scripted_frames("conceal")
    tracker = Tracker()
    analyser = BehaviourAnalyser()
    concealment_events = 0

    for frame in frames:
        tracks = tracker.update(frame)
        for event in analyser.observe(tracks, frame):
            if event.event_type == "concealment":
                concealment_events += 1

    assert concealment_events <= 1


def test_events_carry_a_unique_nonce():
    frames = scripted_frames("sweep")
    tracker = Tracker()
    analyser = BehaviourAnalyser()
    nonces = []

    for frame in frames:
        tracks = tracker.update(frame)
        for event in analyser.observe(tracks, frame):
            nonces.append(event.nonce)

    assert len(nonces) == len(set(nonces))


def test_published_features_contain_no_identity_fields():
    """Belt and braces alongside the privacy module's own tests."""
    from edge.privacy import PROHIBITED_FEATURE_KEYS

    track, frame = _track_from("conceal")
    features = extract_features(track, frame)

    assert not (set(features) & PROHIBITED_FEATURE_KEYS)
