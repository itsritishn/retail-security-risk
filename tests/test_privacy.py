"""The privacy boundary.

Every privacy claim this project makes reduces to the assertion that no imagery and no
biometric data crosses from the edge tier to the core service. These tests are what turn
that from a paragraph in a design document into a property of the code.
"""

from __future__ import annotations

import base64

import pytest

from edge.backends.base import HEAD_KEYPOINTS, KEYPOINT_COUNT, LEFT_WRIST, NOSE
from edge.backends.synthetic import scripted_frames
from edge.privacy import (
    MAX_STRING_LENGTH,
    PrivacyViolation,
    assert_no_imagery,
    redact_prohibited_features,
    round_features,
    strip_head_keypoints,
)


# ------------------------------------------------------- what must be allowed


def test_a_normal_event_payload_passes():
    assert_no_imagery(
        {
            "camera_code": "cam-conf-01",
            "event_type": "concealment",
            "track_ref": "a1b2c3d4",
            "raw_score": 0.81,
            "occurred_at": "2026-09-12T15:04:05+00:00",
            "nonce": "deadbeefdeadbeef",
            "features": {
                "concealment_pattern": True,
                "peak_extension": 2.34,
                "longest_body_hold_seconds": 1.2,
                "occlusion_ratio": 0.11,
                "score_breakdown": [
                    {"term": "concealment_pattern", "delta": 0.52, "why": "reach then hold"}
                ],
            },
        }
    )


def test_none_and_scalars_pass():
    assert_no_imagery({"a": None, "b": 1, "c": 1.5, "d": True, "e": "short string"})


# -------------------------------------------------------- what must be blocked


def test_raw_bytes_are_blocked():
    with pytest.raises(PrivacyViolation, match="binary data"):
        assert_no_imagery({"features": {"payload": b"\x89PNG\r\n\x1a\n"}})


def test_data_uri_is_blocked():
    with pytest.raises(PrivacyViolation, match="data URI"):
        assert_no_imagery({"note": "data:image/png;base64,iVBORw0KGgo="})


def test_base64_blob_is_blocked():
    blob = base64.b64encode(b"x" * 400).decode("ascii")
    with pytest.raises(PrivacyViolation):
        assert_no_imagery({"features": {"thing": blob}})


def test_overlong_string_is_blocked():
    with pytest.raises(PrivacyViolation, match="over the"):
        assert_no_imagery({"note": "a" * (MAX_STRING_LENGTH + 1)})


@pytest.mark.parametrize(
    "key", ["image", "frame", "thumbnail", "crop", "face_embedding", "embedding", "jpeg"]
)
def test_forbidden_keys_are_blocked(key: str):
    with pytest.raises(PrivacyViolation, match="forbidden key"):
        assert_no_imagery({"features": {key: 1}})


@pytest.mark.parametrize("key", ["age", "gender", "ethnicity", "skin_tone", "identity"])
def test_prohibited_attributes_are_blocked(key: str):
    with pytest.raises(PrivacyViolation, match="prohibited attribute"):
        assert_no_imagery({"features": {key: "value"}})


def test_long_numeric_array_is_blocked():
    """The shape of a flattened image or a face embedding."""
    with pytest.raises(PrivacyViolation, match="elements"):
        assert_no_imagery({"features": {"values": [0.1] * 512}})


def test_unknown_types_are_refused():
    """Fail closed: an ndarray or a file handle lands here and must not pass."""

    class Sneaky:
        pass

    with pytest.raises(PrivacyViolation, match="unsupported type"):
        assert_no_imagery({"features": {"thing": Sneaky()}})


def test_violation_reports_the_path():
    with pytest.raises(PrivacyViolation) as exc_info:
        assert_no_imagery({"outer": {"inner": {"image": 1}}})
    assert "outer" in str(exc_info.value)


# ---------------------------------------------------------- head keypoints


def test_head_keypoints_are_zeroed():
    frame = scripted_frames("conceal")[0]
    original = frame.detections[0]

    assert original.keypoint(NOSE).confidence > 0

    stripped = strip_head_keypoints(original)

    for index in HEAD_KEYPOINTS:
        keypoint = stripped.keypoint(index)
        assert keypoint.confidence == 0.0
        assert keypoint.x == 0.0
        assert keypoint.y == 0.0


def test_body_keypoints_survive_stripping():
    """The behavioural signal lives in the limbs, so stripping the head must not cost it."""
    frame = scripted_frames("conceal")[10]
    original = frame.detections[0]
    stripped = strip_head_keypoints(original)

    assert stripped.keypoint(LEFT_WRIST).x == original.keypoint(LEFT_WRIST).x
    assert stripped.keypoint(LEFT_WRIST).confidence == original.keypoint(LEFT_WRIST).confidence
    assert len(stripped.keypoints) == KEYPOINT_COUNT


def test_stripping_preserves_index_layout():
    """Zeroed rather than removed, so downstream COCO indexing stays valid."""
    frame = scripted_frames("browse")[0]
    stripped = strip_head_keypoints(frame.detections[0])
    assert len(stripped.keypoints) == KEYPOINT_COUNT


# --------------------------------------------------------------- redaction


def test_prohibited_features_are_redacted_locally():
    cleaned, removed = redact_prohibited_features(
        {"peak_extension": 2.1, "age": 34, "gender": "f"}
    )
    assert cleaned == {"peak_extension": 2.1}
    assert sorted(removed) == ["age", "gender"]


def test_redaction_leaves_clean_features_alone():
    original = {"peak_extension": 2.1, "concealment_pattern": True}
    cleaned, removed = redact_prohibited_features(original)
    assert cleaned == original
    assert removed == []


def test_float_precision_is_reduced():
    """Excess precision in behavioural telemetry aids re-identification."""
    rounded = round_features({"value": 1.23456789012345, "flag": True, "count": 3})
    assert rounded["value"] == 1.2346
    assert rounded["flag"] is True
    assert rounded["count"] == 3


def test_edge_and_core_prohibited_lists_agree():
    """The lists are duplicated for deployment independence, so they must not drift."""
    from core.policy import PROHIBITED_FEATURE_KEYS as core_keys
    from edge.privacy import PROHIBITED_FEATURE_KEYS as edge_keys

    assert core_keys == edge_keys
