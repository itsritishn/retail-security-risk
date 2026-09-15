"""Pose data structures shared by every backend.

Keypoints follow the COCO 17-point convention, which is what almost every off-the-shelf
pose estimator emits, so backends stay interchangeable.

Note what a :class:`PoseDetection` deliberately cannot hold: there is no field for a crop,
a thumbnail, an embedding, or an image buffer of any kind. The structure is the privacy
boundary made concrete, and :func:`edge.privacy.assert_no_imagery` verifies at runtime
that nothing has smuggled one in.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime

# COCO keypoint indices.
NOSE = 0
LEFT_EYE = 1
RIGHT_EYE = 2
LEFT_EAR = 3
RIGHT_EAR = 4
LEFT_SHOULDER = 5
RIGHT_SHOULDER = 6
LEFT_ELBOW = 7
RIGHT_ELBOW = 8
LEFT_WRIST = 9
RIGHT_WRIST = 10
LEFT_HIP = 11
RIGHT_HIP = 12
LEFT_KNEE = 13
RIGHT_KNEE = 14
LEFT_ANKLE = 15
RIGHT_ANKLE = 16

KEYPOINT_COUNT = 17

KEYPOINT_NAMES = (
    "nose", "left_eye", "right_eye", "left_ear", "right_ear",
    "left_shoulder", "right_shoulder", "left_elbow", "right_elbow",
    "left_wrist", "right_wrist", "left_hip", "right_hip",
    "left_knee", "right_knee", "left_ankle", "right_ankle",
)

#: Head keypoints. Tracked separately because they are the only points that could
#: contribute to identifying someone, and they are dropped before publication by
#: :func:`edge.privacy.strip_head_keypoints`.
HEAD_KEYPOINTS = (NOSE, LEFT_EYE, RIGHT_EYE, LEFT_EAR, RIGHT_EAR)


@dataclass
class Keypoint:
    x: float
    y: float
    confidence: float

    @property
    def visible(self) -> bool:
        return self.confidence >= 0.3


@dataclass
class PoseDetection:
    """One person in one frame, expressed purely as geometry."""

    bbox: tuple[float, float, float, float]  # x1, y1, x2, y2 in pixels
    keypoints: list[Keypoint]
    detection_confidence: float = 1.0

    def __post_init__(self) -> None:
        if len(self.keypoints) != KEYPOINT_COUNT:
            raise ValueError(
                f"expected {KEYPOINT_COUNT} COCO keypoints, got {len(self.keypoints)}"
            )

    @property
    def centre(self) -> tuple[float, float]:
        x1, y1, x2, y2 = self.bbox
        return ((x1 + x2) / 2.0, (y1 + y2) / 2.0)

    @property
    def width(self) -> float:
        return max(1e-6, self.bbox[2] - self.bbox[0])

    @property
    def height(self) -> float:
        return max(1e-6, self.bbox[3] - self.bbox[1])

    @property
    def area(self) -> float:
        return self.width * self.height

    def keypoint(self, index: int) -> Keypoint:
        return self.keypoints[index]

    def visibility_ratio(self) -> float:
        """Fraction of all keypoints detected with usable confidence."""
        return sum(1 for kp in self.keypoints if kp.visible) / float(KEYPOINT_COUNT)

    def body_visibility_ratio(self) -> float:
        """Fraction of *body* keypoints detected with usable confidence.

        Head points are excluded, and this is the ratio the occlusion estimate must use.

        Facial keypoints are deliberately zeroed early in the pipeline for privacy
        (:func:`edge.privacy.strip_head_keypoints`). Counting them as missing would make the
        privacy control masquerade as a 29% occlusion penalty on every single observation,
        quietly suppressing genuine detections. Occlusion has to be measured over the
        keypoints the behavioural model actually uses.
        """
        body = [
            kp for index, kp in enumerate(self.keypoints) if index not in HEAD_KEYPOINTS
        ]
        if not body:
            return 0.0
        return sum(1 for kp in body if kp.visible) / float(len(body))

    def torso_centre(self) -> tuple[float, float] | None:
        """Midpoint of shoulders and hips, the reference for hand-position features."""
        points = [
            self.keypoint(index)
            for index in (LEFT_SHOULDER, RIGHT_SHOULDER, LEFT_HIP, RIGHT_HIP)
        ]
        usable = [p for p in points if p.visible]
        if len(usable) < 2:
            return None
        return (
            sum(p.x for p in usable) / len(usable),
            sum(p.y for p in usable) / len(usable),
        )

    def shoulder_width(self) -> float | None:
        """Pixel distance between shoulders.

        Used to normalise distances so that features do not change meaning with a person's
        distance from the camera. Without this, the same gesture scores differently at the
        end of an aisle than it does up close, which is a classic source of false
        positives near the lens.
        """
        left = self.keypoint(LEFT_SHOULDER)
        right = self.keypoint(RIGHT_SHOULDER)
        if not (left.visible and right.visible):
            return None
        distance = math.dist((left.x, left.y), (right.x, right.y))
        return distance if distance > 1e-3 else None

    def scale_reference(self) -> float:
        """Best available normalisation scale, falling back to bbox height."""
        return self.shoulder_width() or (self.height * 0.25)


@dataclass
class PoseFrame:
    """All detections from a single frame, plus frame-level context."""

    timestamp: datetime
    detections: list[PoseDetection] = field(default_factory=list)
    frame_index: int = 0
    width: int = 1920
    height: int = 1080
    #: Mean luminance in [0, 1], if the backend can supply it cheaply. Low light degrades
    #: pose quality, so it is carried through as a confidence reducer.
    brightness: float | None = None

    @property
    def crowd_size(self) -> int:
        return len(self.detections)


class PoseBackend(ABC):
    """Source of pose frames.

    Implementations must discard image data before yielding. A backend that retains or
    forwards pixels breaks the system's central privacy claim.
    """

    name: str = "abstract"

    @abstractmethod
    def frames(self) -> Iterator[PoseFrame]:
        """Yield pose frames until the source is exhausted."""

    def close(self) -> None:
        """Release any resources. Safe to call more than once."""

    def __enter__(self) -> "PoseBackend":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
