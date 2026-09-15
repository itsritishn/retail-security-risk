"""The privacy boundary, enforced in code.

Every claim this project makes about privacy reduces to one assertion: no imagery and no
biometric data crosses from the edge tier to the core service. A design document saying so
is worth very little. This module makes it a runtime check that fails loudly.

Three controls:

1. :func:`assert_no_imagery` walks an outbound payload and rejects anything that looks
   like pixel data, an array, a file handle, or a base64 blob.
2. :func:`strip_head_keypoints` removes facial keypoints before publication. Head geometry
   is not a face template, but it is the only part of a skeleton with any identifying
   potential, and the behavioural features do not need it.
3. :func:`redact_prohibited_features` mirrors the server-side fairness screen locally, so
   a prohibited feature is dropped at source rather than relying on the core to reject the
   whole event.

Control 3 is intentionally redundant with :mod:`core.policy`. Defence in depth means the
check exists on both sides of the trust boundary: the edge drops it because it should never
have been computed, and the core rejects it because the edge cannot be trusted.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from edge.backends.base import HEAD_KEYPOINTS, KEYPOINT_COUNT, Keypoint, PoseDetection

logger = logging.getLogger("sentinelfloor.edge.privacy")


class PrivacyViolation(RuntimeError):
    """Raised when an outbound payload would breach the privacy boundary."""


#: Key names that must never appear in an outbound payload.
FORBIDDEN_KEYS = frozenset(
    {
        "image", "img", "frame", "thumbnail", "thumb", "crop", "snapshot", "jpeg",
        "jpg", "png", "bytes", "buffer", "blob", "pixels", "raw", "b64", "base64",
        "encoded_image", "face", "face_crop", "face_embedding", "embedding",
        "descriptor", "template", "iris", "fingerprint", "voiceprint",
    }
)

#: Mirrors :data:`core.policy.PROHIBITED_FEATURE_KEYS`. Duplicated rather than imported so
#: the edge tier can be deployed and reasoned about independently of the core package.
PROHIBITED_FEATURE_KEYS = frozenset(
    {
        "age", "age_estimate", "age_bracket", "gender", "sex", "ethnicity", "race",
        "skin_tone", "skin_colour", "skin_color", "face_embedding", "face_descriptor",
        "facial_landmarks", "identity", "person_id", "customer_id", "name",
        "gait_signature", "iris", "clothing_brand", "religious_dress", "hair_colour",
        "hair_color", "disability", "mobility_aid", "emotion", "affect", "sentiment",
    }
)

#: Heuristic for a base64-encoded binary blob hiding in a string field.
_BASE64_BLOB = re.compile(r"^[A-Za-z0-9+/]{256,}={0,2}$")

#: Data URI, the other obvious way an image ends up in a JSON string.
_DATA_URI = re.compile(r"^data:[a-z]+/[a-z0-9.+-]+;base64,", re.IGNORECASE)

#: Maximum length for any string in an outbound payload.
MAX_STRING_LENGTH = 256


def assert_no_imagery(payload: Any, *, path: str = "$") -> None:
    """Recursively verify that a payload carries no image or biometric data.

    Raises :class:`PrivacyViolation` on the first problem found. Called immediately before
    signing in :mod:`edge.publisher`, which is the last point at which the check is
    meaningful.
    """
    if isinstance(payload, (bytes, bytearray, memoryview)):
        raise PrivacyViolation(f"binary data at {path}")

    if isinstance(payload, str):
        if len(payload) > MAX_STRING_LENGTH:
            raise PrivacyViolation(
                f"string at {path} is {len(payload)} characters, over the "
                f"{MAX_STRING_LENGTH} limit. Long strings are how imagery gets smuggled."
            )
        if _DATA_URI.match(payload):
            raise PrivacyViolation(f"data URI at {path}")
        if _BASE64_BLOB.match(payload):
            raise PrivacyViolation(f"suspected base64 blob at {path}")
        return

    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lower = str(key).strip().lower()
            if key_lower in FORBIDDEN_KEYS:
                raise PrivacyViolation(f"forbidden key {key!r} at {path}")
            if key_lower in PROHIBITED_FEATURE_KEYS:
                raise PrivacyViolation(f"prohibited attribute {key!r} at {path}")
            assert_no_imagery(value, path=f"{path}.{key}")
        return

    if isinstance(payload, (list, tuple)):
        # Bounded: a long numeric array is the shape of a flattened image or an embedding.
        if len(payload) > 128:
            raise PrivacyViolation(
                f"array at {path} has {len(payload)} elements; arrays that large are "
                "consistent with an embedding or flattened image"
            )
        for index, item in enumerate(payload):
            assert_no_imagery(item, path=f"{path}[{index}]")
        return

    if isinstance(payload, (int, float, bool)) or payload is None:
        return

    # Anything not on the allowlist is refused. Fail closed: an ndarray, a Tensor, or an
    # open file object all land here, and none of them belong in an event.
    raise PrivacyViolation(
        f"unsupported type {type(payload).__name__} at {path}; only JSON scalars, "
        "bounded lists, and dicts may be published"
    )


def strip_head_keypoints(detection: PoseDetection) -> PoseDetection:
    """Return a copy with facial keypoints zeroed out.

    Head points are replaced with zero-confidence placeholders rather than removed, so the
    COCO index layout stays intact and downstream code needs no special cases.

    Facial keypoints are not a face template and cannot be reversed into one, but they are
    the only part of a skeleton that gestures at identity, and no behavioural feature in
    this system uses them. Dropping them costs nothing and removes the argument.
    """
    keypoints: list[Keypoint] = []
    for index in range(KEYPOINT_COUNT):
        if index in HEAD_KEYPOINTS:
            keypoints.append(Keypoint(0.0, 0.0, 0.0))
        else:
            original = detection.keypoints[index]
            keypoints.append(Keypoint(original.x, original.y, original.confidence))

    return PoseDetection(
        bbox=detection.bbox,
        keypoints=keypoints,
        detection_confidence=detection.detection_confidence,
    )


def redact_prohibited_features(features: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Drop prohibited keys locally. Returns the cleaned dict and what was removed."""
    cleaned: dict[str, Any] = {}
    removed: list[str] = []

    for key, value in features.items():
        if str(key).strip().lower() in PROHIBITED_FEATURE_KEYS:
            removed.append(str(key))
            continue
        cleaned[key] = value

    if removed:
        logger.error(
            "redacted prohibited features before publication: %s. This indicates a bug in "
            "feature extraction, not a configuration issue.",
            removed,
        )

    return cleaned, removed


def round_features(features: dict[str, Any], places: int = 4) -> dict[str, Any]:
    """Round floats before publication.

    Data minimisation applied to precision. Sixteen significant figures of wrist
    displacement is more information than the decision needs, and excess precision in
    behavioural telemetry is exactly what makes an ostensibly anonymous record
    re-identifiable when combined with other data.
    """
    rounded: dict[str, Any] = {}
    for key, value in features.items():
        if isinstance(value, bool):
            rounded[key] = value
        elif isinstance(value, float):
            rounded[key] = round(value, places)
        else:
            rounded[key] = value
    return rounded
