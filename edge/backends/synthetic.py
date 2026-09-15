"""Synthetic pose generator.

Exists so that the entire system is runnable, testable, and demonstrable with no ML
dependencies, no video files, and crucially **no real CCTV footage**. That last point is
not a convenience: real store footage belongs to the retailer and to the customers in
frame, and using it for a personal project without written authorisation from the data
controller is a UK GDPR breach. This backend removes any temptation.

It produces four behaviour patterns whose geometry is drawn from what the pose literature
describes as the shoplifting signal, principally an outward reach toward a shelf followed
by the hand returning close to the torso and staying there, rather than returning to the
shelf as it would when replacing an item.

To be clear about what this is and is not: this generates plausible *geometry* for
developing and testing the pipeline. It is not a substitute for training or evaluating on
real annotated data. For that, use PoseLift (WACV 2025), which contains anonymised pose
data collected in a real store, or UCF-Crime and DCSASS. See docs/06-evaluation-plan.md.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import timedelta

from edge.backends.base import (
    KEYPOINT_COUNT,
    LEFT_ANKLE,
    LEFT_EAR,
    LEFT_ELBOW,
    LEFT_EYE,
    LEFT_HIP,
    LEFT_KNEE,
    LEFT_SHOULDER,
    LEFT_WRIST,
    NOSE,
    RIGHT_ANKLE,
    RIGHT_EAR,
    RIGHT_ELBOW,
    RIGHT_EYE,
    RIGHT_HIP,
    RIGHT_KNEE,
    RIGHT_SHOULDER,
    RIGHT_WRIST,
    Keypoint,
    PoseBackend,
    PoseDetection,
    PoseFrame,
)
from core.util import utcnow

#: Behaviour scripts. ``phases`` are (name, duration_seconds) and drive arm extension.
#:
#: ``browse`` and ``replace`` are the negatives that matter. A detector that cannot tell
#: "picked it up and put it back" from "picked it up and pocketed it" is useless in a
#: shop, because the first is what most customers do all day.
SCENARIOS: dict[str, tuple[tuple[str, float], ...]] = {
    "browse": (
        ("walk", 3.0),
        ("dwell", 2.0),
        ("walk", 3.0),
    ),
    # The hard negative, and the reason this scenario exists. The shopper takes an item,
    # brings it in to read the label, then puts it back. Geometrically this is nearly the
    # concealment sequence: the only difference is that the hand goes back to the shelf
    # instead of moving away. A detector that cannot separate these two is useless in a shop.
    "replace": (
        ("walk", 2.0),
        ("dwell", 1.0),
        ("reach", 0.9),
        ("to_body", 0.4),
        ("hold_body", 0.7),
        ("reach", 0.9),
        ("walk", 2.5),
    ),
    "conceal": (
        ("walk", 2.0),
        ("dwell", 0.8),
        ("reach", 0.8),
        ("to_body", 0.5),
        ("hold_body", 1.6),
        ("walk", 3.0),
    ),
    "sweep": (
        ("walk", 1.5),
        ("reach", 0.5),
        ("to_body", 0.4),
        ("reach", 0.5),
        ("to_body", 0.4),
        ("reach", 0.5),
        ("to_body", 0.4),
        ("hold_body", 1.0),
        ("walk", 2.0),
    ),
}

#: Arm extension per phase, as a multiple of shoulder width from the torso centre.
#: ``hold_body`` sits below 0.5, meaning the hand is tucked against the body, which is
#: the geometric signature the feature extractor is looking for.
PHASE_EXTENSION: dict[str, float] = {
    "walk": 0.85,
    "dwell": 0.95,
    "reach": 2.30,
    "hold_out": 2.10,
    "to_body": 1.10,
    "hold_body": 0.38,
}


@dataclass
class _Shopper:
    """One synthetic person moving through frame."""

    person_id: str
    scenario: str
    enters_at: float
    start_x: float
    lane_y: float
    speed: float
    scale: float
    reaching_arm: str  # "left" or "right"
    jitter: random.Random
    occluded: bool = False
    phases: tuple[tuple[str, float], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self.phases = SCENARIOS[self.scenario]

    @property
    def duration(self) -> float:
        return sum(duration for _, duration in self.phases)

    def phase_at(self, elapsed: float) -> tuple[str, float]:
        """Return (phase_name, progress_in_phase) for a time since entry."""
        cursor = 0.0
        for name, duration in self.phases:
            if elapsed < cursor + duration:
                return name, (elapsed - cursor) / duration
            cursor += duration
        return "walk", 1.0

    def travelled(self, elapsed: float) -> float:
        """Horizontal distance covered, pausing while the hands are busy."""
        moving_phases = {"walk"}
        distance = 0.0
        cursor = 0.0
        for name, duration in self.phases:
            span = min(duration, max(0.0, elapsed - cursor))
            if name in moving_phases:
                distance += span * self.speed
            cursor += duration
            if cursor >= elapsed:
                break
        return distance


def _blend(previous: float, target: float, progress: float) -> float:
    """Smooth interpolation, so limbs do not teleport between phases."""
    eased = 0.5 - 0.5 * math.cos(math.pi * min(1.0, max(0.0, progress)))
    return previous + (target - previous) * eased


class SyntheticBackend(PoseBackend):
    """Deterministic synthetic pose source."""

    name = "synthetic"

    def __init__(self, config: dict | None = None) -> None:
        config = config or {}
        self.fps: float = float(config.get("fps", 8.0))
        self.duration_seconds: float = float(config.get("duration_seconds", 180.0))
        self.frame_width: int = int(config.get("frame_width", 1920))
        self.frame_height: int = int(config.get("frame_height", 1080))
        self.seed: int = int(config.get("seed", 20260912))
        self.max_concurrent: int = int(config.get("max_concurrent_shoppers", 3))

        #: Mix of behaviours. Heavily weighted toward normal shopping, because that is
        #: what a real store looks like. Testing against a balanced set would flatter the
        #: detector and hide the false-positive rate that actually decides whether staff
        #: keep using it.
        self.scenario_weights: dict[str, float] = dict(
            config.get(
                "scenario_weights",
                {"browse": 0.60, "replace": 0.24, "conceal": 0.12, "sweep": 0.04},
            )
        )

        self._rng = random.Random(self.seed)
        self._shoppers: list[_Shopper] = self._plan()
        self._closed = False

    # ------------------------------------------------------------------ plan

    def _plan(self) -> list[_Shopper]:
        shoppers: list[_Shopper] = []
        names = list(self.scenario_weights)
        weights = [self.scenario_weights[name] for name in names]

        arrival = 2.0
        index = 0
        while arrival < self.duration_seconds:
            scenario = self._rng.choices(names, weights=weights, k=1)[0]
            index += 1
            shoppers.append(
                _Shopper(
                    person_id=f"p{index:03d}",
                    scenario=scenario,
                    enters_at=arrival,
                    start_x=self._rng.uniform(120.0, 320.0),
                    lane_y=self._rng.uniform(
                        self.frame_height * 0.42, self.frame_height * 0.62
                    ),
                    speed=self._rng.uniform(48.0, 82.0),
                    scale=self._rng.uniform(0.85, 1.25),
                    reaching_arm=self._rng.choice(("left", "right")),
                    jitter=random.Random(self._rng.randrange(1 << 30)),
                    # Roughly one in eight is partly obscured, which is realistic for a
                    # convenience store full of end-of-aisle displays and stacked crates.
                    occluded=self._rng.random() < 0.12,
                )
            )
            arrival += self._rng.uniform(3.0, 11.0)

        return shoppers

    @property
    def ground_truth(self) -> dict[str, str]:
        """Planned behaviour per synthetic person, for offline evaluation only.

        Never published to the core service. The core has no concept of a label and must
        not: its ground truth comes from staff dispositions, which is the only source that
        exists in a real deployment.
        """
        return {shopper.person_id: shopper.scenario for shopper in self._shoppers}

    # ----------------------------------------------------------------- pose

    def _build_detection(self, shopper: _Shopper, elapsed: float) -> PoseDetection:
        phase, progress = shopper.phase_at(elapsed)

        # Previous phase extension, so transitions are smooth rather than stepped.
        cursor = 0.0
        previous_phase = phase
        for name, duration in shopper.phases:
            if elapsed < cursor + duration:
                break
            previous_phase = name
            cursor += duration

        target = PHASE_EXTENSION.get(phase, 0.9)
        previous = PHASE_EXTENSION.get(previous_phase, 0.9)
        extension = _blend(previous, target, progress)

        shoulder = 62.0 * shopper.scale
        body_height = 300.0 * shopper.scale

        x = shopper.start_x + shopper.travelled(elapsed)
        y = shopper.lane_y + shopper.jitter.uniform(-2.0, 2.0)

        torso_x = x
        torso_y = y

        # Shelving is modelled as being above and to the reaching side, so a reach moves
        # the wrist outward and upward relative to the torso.
        direction = -1.0 if shopper.reaching_arm == "left" else 1.0
        reach_x = torso_x + direction * extension * shoulder * 0.75
        reach_y = torso_y - extension * shoulder * 0.55

        idle_ext = PHASE_EXTENSION["walk"]
        idle_x = torso_x - direction * idle_ext * shoulder * 0.55
        idle_y = torso_y + idle_ext * shoulder * 0.30

        def jitter(value: float, amount: float = 1.6) -> float:
            return value + shopper.jitter.uniform(-amount, amount)

        keypoints = [Keypoint(0.0, 0.0, 0.0) for _ in range(KEYPOINT_COUNT)]

        head_y = torso_y - body_height * 0.42
        keypoints[NOSE] = Keypoint(jitter(torso_x), jitter(head_y), 0.92)
        keypoints[LEFT_EYE] = Keypoint(jitter(torso_x - 8), jitter(head_y - 4), 0.88)
        keypoints[RIGHT_EYE] = Keypoint(jitter(torso_x + 8), jitter(head_y - 4), 0.88)
        keypoints[LEFT_EAR] = Keypoint(jitter(torso_x - 16), jitter(head_y), 0.80)
        keypoints[RIGHT_EAR] = Keypoint(jitter(torso_x + 16), jitter(head_y), 0.80)

        shoulder_y = torso_y - body_height * 0.24
        keypoints[LEFT_SHOULDER] = Keypoint(
            jitter(torso_x - shoulder / 2), jitter(shoulder_y), 0.94
        )
        keypoints[RIGHT_SHOULDER] = Keypoint(
            jitter(torso_x + shoulder / 2), jitter(shoulder_y), 0.94
        )

        hip_y = torso_y + body_height * 0.10
        keypoints[LEFT_HIP] = Keypoint(jitter(torso_x - shoulder * 0.38), jitter(hip_y), 0.90)
        keypoints[RIGHT_HIP] = Keypoint(jitter(torso_x + shoulder * 0.38), jitter(hip_y), 0.90)

        if shopper.reaching_arm == "left":
            keypoints[LEFT_WRIST] = Keypoint(jitter(reach_x), jitter(reach_y), 0.86)
            keypoints[RIGHT_WRIST] = Keypoint(jitter(idle_x), jitter(idle_y), 0.84)
            keypoints[LEFT_ELBOW] = Keypoint(
                jitter((reach_x + torso_x) / 2), jitter((reach_y + shoulder_y) / 2), 0.82
            )
            keypoints[RIGHT_ELBOW] = Keypoint(
                jitter((idle_x + torso_x) / 2), jitter((idle_y + shoulder_y) / 2), 0.82
            )
        else:
            keypoints[RIGHT_WRIST] = Keypoint(jitter(reach_x), jitter(reach_y), 0.86)
            keypoints[LEFT_WRIST] = Keypoint(jitter(idle_x), jitter(idle_y), 0.84)
            keypoints[RIGHT_ELBOW] = Keypoint(
                jitter((reach_x + torso_x) / 2), jitter((reach_y + shoulder_y) / 2), 0.82
            )
            keypoints[LEFT_ELBOW] = Keypoint(
                jitter((idle_x + torso_x) / 2), jitter((idle_y + shoulder_y) / 2), 0.82
            )

        knee_y = torso_y + body_height * 0.30
        ankle_y = torso_y + body_height * 0.50

        # An obscured lower body is the common case in a convenience store: displays,
        # crates, and stacked baskets all cut the legs off. Dropping confidence rather
        # than the points lets the pipeline discount the observation honestly.
        leg_confidence = 0.18 if shopper.occluded else 0.80
        keypoints[LEFT_KNEE] = Keypoint(
            jitter(torso_x - shoulder * 0.30), jitter(knee_y), leg_confidence
        )
        keypoints[RIGHT_KNEE] = Keypoint(
            jitter(torso_x + shoulder * 0.30), jitter(knee_y), leg_confidence
        )
        keypoints[LEFT_ANKLE] = Keypoint(
            jitter(torso_x - shoulder * 0.28), jitter(ankle_y), leg_confidence * 0.9
        )
        keypoints[RIGHT_ANKLE] = Keypoint(
            jitter(torso_x + shoulder * 0.28), jitter(ankle_y), leg_confidence * 0.9
        )

        visible_x = [kp.x for kp in keypoints if kp.confidence >= 0.3]
        visible_y = [kp.y for kp in keypoints if kp.confidence >= 0.3]
        pad = 14.0

        bbox = (
            min(visible_x) - pad,
            min(visible_y) - pad,
            max(visible_x) + pad,
            max(visible_y) + pad,
        )

        return PoseDetection(
            bbox=bbox,
            keypoints=keypoints,
            detection_confidence=0.70 if shopper.occluded else 0.93,
        )

    # --------------------------------------------------------------- frames

    def frames(self) -> Iterator[PoseFrame]:
        step = 1.0 / self.fps
        total_frames = int(self.duration_seconds * self.fps)
        origin = utcnow()

        for index in range(total_frames):
            now = index * step
            detections: list[PoseDetection] = []

            active = [
                shopper
                for shopper in self._shoppers
                if shopper.enters_at <= now < shopper.enters_at + shopper.duration
            ]

            for shopper in active[: self.max_concurrent]:
                detections.append(self._build_detection(shopper, now - shopper.enters_at))

            yield PoseFrame(
                timestamp=origin + timedelta(seconds=now),
                detections=detections,
                frame_index=index,
                width=self.frame_width,
                height=self.frame_height,
                # A gentle diurnal cycle so low-light confidence handling gets exercised.
                brightness=0.55 + 0.2 * math.sin(now / 45.0),
            )

    def close(self) -> None:
        self._closed = True


def scripted_frames(
    scenario: str,
    *,
    fps: float = 8.0,
    occluded: bool = False,
    scale: float = 1.0,
    reaching_arm: str = "right",
    seed: int = 7,
) -> list[PoseFrame]:
    """Generate frames for exactly one shopper performing exactly one scenario.

    Provided as a public helper because deterministic single-behaviour sequences are what
    the feature and scoring tests need. Driving those tests through the full random
    generator would make them depend on arrival timing and track association, so a failure
    would not tell you whether the feature extractor or the tracker had broken.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {sorted(SCENARIOS)}")

    backend = SyntheticBackend(
        {
            "fps": fps,
            "duration_seconds": 1.0,
            "seed": seed,
            "scenario_weights": {scenario: 1.0},
        }
    )

    shopper = _Shopper(
        person_id="scripted",
        scenario=scenario,
        enters_at=0.0,
        start_x=200.0,
        lane_y=540.0,
        speed=60.0,
        scale=scale,
        reaching_arm=reaching_arm,
        jitter=random.Random(seed),
        occluded=occluded,
    )

    step = 1.0 / fps
    frame_count = int(shopper.duration * fps)
    origin = utcnow()
    frames: list[PoseFrame] = []

    for index in range(frame_count):
        elapsed = index * step
        frames.append(
            PoseFrame(
                timestamp=origin + timedelta(seconds=elapsed),
                detections=[backend._build_detection(shopper, elapsed)],
                frame_index=index,
                width=backend.frame_width,
                height=backend.frame_height,
                brightness=0.6,
            )
        )

    return frames
