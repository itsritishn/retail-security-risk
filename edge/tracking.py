"""Lightweight multi-object tracking.

Greedy IoU association with a short tolerance for missed frames. Deliberately simple:
a heavier tracker (ByteTrack, BoT-SORT) is a drop-in improvement, but association quality
is not the bottleneck for the behavioural signal this system looks for, and a simple
tracker with no learned appearance model has a useful property here.

That property is the important part. Appearance-based re-identification is exactly what
this system must not do. A tracker that can recognise the same person returning tomorrow is
a tracker that has built an identity, which is the line the whole design refuses to cross.
Association is therefore geometric and short-lived by construction.

Track references are random, not sequential. A sequential id leaks how many people have
been through the store and, worse, invites treating the id as a stable handle for a person.
"""

from __future__ import annotations

import logging
import secrets
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from core.util import as_utc
from edge.backends.base import PoseDetection, PoseFrame

logger = logging.getLogger("sentinelfloor.edge.tracking")


def iou(box_a: tuple[float, float, float, float], box_b: tuple[float, float, float, float]) -> float:
    """Intersection over union for two xyxy boxes."""
    ax1, ay1, ax2, ay2 = box_a
    bx1, by1, bx2, by2 = box_b

    ix1 = max(ax1, bx1)
    iy1 = max(ay1, by1)
    ix2 = min(ax2, bx2)
    iy2 = min(ay2, by2)

    if ix2 <= ix1 or iy2 <= iy1:
        return 0.0

    intersection = (ix2 - ix1) * (iy2 - iy1)
    area_a = max(0.0, ax2 - ax1) * max(0.0, ay2 - ay1)
    area_b = max(0.0, bx2 - bx1) * max(0.0, by2 - by1)
    union = area_a + area_b - intersection

    return intersection / union if union > 0 else 0.0


@dataclass
class Observation:
    timestamp: datetime
    detection: PoseDetection
    frame_index: int


@dataclass
class Track:
    """A person followed across frames within a single camera view.

    ``track_ref`` is meaningless outside this process and this visit. It exists solely to
    let the core service suppress duplicate prompts about the same ongoing behaviour.
    """

    track_ref: str
    first_seen: datetime
    last_seen: datetime
    history: deque[Observation] = field(default_factory=lambda: deque(maxlen=120))
    missed_frames: int = 0
    fragment_count: int = 0
    #: Set once an event has been published, so the same gesture is not reported twice.
    reported_event_types: set[str] = field(default_factory=set)

    @property
    def latest(self) -> Observation | None:
        return self.history[-1] if self.history else None

    @property
    def duration_seconds(self) -> float:
        return (as_utc(self.last_seen) - as_utc(self.first_seen)).total_seconds()

    @property
    def observation_count(self) -> int:
        return len(self.history)

    def add(self, observation: Observation) -> None:
        if self.missed_frames > 0:
            # Reacquired after a gap. Recorded because a fragmented track means the
            # behavioural window has holes, which must lower confidence in any conclusion.
            self.fragment_count += 1
        self.history.append(observation)
        self.last_seen = observation.timestamp
        self.missed_frames = 0

    def window(self, seconds: float) -> list[Observation]:
        """Observations within the trailing ``seconds``."""
        if not self.history:
            return []
        cutoff = as_utc(self.last_seen) - timedelta(seconds=seconds)
        return [obs for obs in self.history if as_utc(obs.timestamp) >= cutoff]


class Tracker:
    """Greedy IoU tracker."""

    def __init__(
        self,
        *,
        iou_threshold: float = 0.25,
        max_missed_frames: int = 8,
        max_track_age_seconds: float = 180.0,
        history_length: int = 120,
    ) -> None:
        self.iou_threshold = iou_threshold
        self.max_missed_frames = max_missed_frames
        self.max_track_age_seconds = max_track_age_seconds
        self.history_length = history_length
        self._tracks: dict[str, Track] = {}

    @property
    def tracks(self) -> list[Track]:
        return list(self._tracks.values())

    def update(self, frame: PoseFrame) -> list[Track]:
        """Associate detections with tracks. Returns tracks updated in this frame."""
        unmatched_detections = list(enumerate(frame.detections))
        matched: list[Track] = []
        claimed: set[int] = set()

        # Longest-lived tracks match first. A well-established track is more likely to be
        # the correct owner of an ambiguous box than one created two frames ago.
        for track in sorted(
            self._tracks.values(), key=lambda t: -t.observation_count
        ):
            latest = track.latest
            if latest is None:
                continue

            best_index: int | None = None
            best_score = self.iou_threshold

            for index, detection in unmatched_detections:
                if index in claimed:
                    continue
                score = iou(latest.detection.bbox, detection.bbox)
                if score > best_score:
                    best_score = score
                    best_index = index

            if best_index is None:
                track.missed_frames += 1
                continue

            claimed.add(best_index)
            detection = frame.detections[best_index]
            track.add(
                Observation(
                    timestamp=frame.timestamp,
                    detection=detection,
                    frame_index=frame.frame_index,
                )
            )
            matched.append(track)

        for index, detection in unmatched_detections:
            if index in claimed:
                continue
            track = self._create(frame, detection)
            matched.append(track)

        self._retire(frame.timestamp)
        return matched

    def _create(self, frame: PoseFrame, detection: PoseDetection) -> Track:
        # 64 bits of randomness: collision-free in practice and carries no information
        # about ordering, count, or arrival time.
        track_ref = secrets.token_hex(8)
        track = Track(
            track_ref=track_ref,
            first_seen=frame.timestamp,
            last_seen=frame.timestamp,
            history=deque(maxlen=self.history_length),
        )
        track.add(
            Observation(
                timestamp=frame.timestamp,
                detection=detection,
                frame_index=frame.frame_index,
            )
        )
        self._tracks[track_ref] = track
        return track

    def _retire(self, now: datetime) -> None:
        """Drop tracks that are stale or too old.

        The age cap is a privacy control as much as a memory one: a track that persists
        indefinitely accumulates a long movement history for one person, which is more data
        than any single behavioural decision needs.
        """
        expired: list[str] = []

        for track_ref, track in self._tracks.items():
            if track.missed_frames > self.max_missed_frames:
                expired.append(track_ref)
                continue
            age = (as_utc(now) - as_utc(track.first_seen)).total_seconds()
            if age > self.max_track_age_seconds:
                expired.append(track_ref)

        for track_ref in expired:
            self._tracks.pop(track_ref, None)

        if expired:
            logger.debug("retired %s tracks", len(expired))

    def reset(self) -> None:
        self._tracks.clear()
