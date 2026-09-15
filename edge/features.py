"""Behavioural feature extraction from pose sequences.

The central quantity is **normalised wrist extension**: the distance from the torso centre
to a wrist, divided by shoulder width. Normalising by shoulder width is what makes the
feature usable at all, because it removes the person's distance from the camera. Without
it, someone reaching for a shelf at the far end of an aisle produces a much smaller number
than the same gesture up close, and the detector ends up firing mainly on people who walk
near the lens.

The behavioural distinction that matters is not "did they reach for a shelf". Everyone
reaches for shelves. It is what the hand does next:

    reach out  →  hand returns toward the shelf        = replaced the item      (benign)
    reach out  →  hand tucks inside the body and stays = concealment candidate  (signal)

Two refinements make that separable in practice, and both were arrived at by watching the
naive version fail:

**Per-arm analysis.** People conceal with one hand while the other stays at rest. Taking the
maximum extension across both wrists reports the resting arm and hides the gesture, so each
arm is followed independently.

**Medial position, not just proximity.** An arm hanging at rest is also close to the torso.
What distinguishes a waistband or inside-jacket tuck is that the wrist moves *inside* the
body silhouette, between the hips. Without that test, every shopper who reaches for a shelf
and then drops their arm looks like a thief.

Every feature here is a scalar or a boolean. No feature encodes appearance, clothing,
demographics, or identity, and :mod:`edge.privacy` enforces that before publication.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass

from core.util import as_utc, clamp
from edge.backends.base import (
    LEFT_HIP,
    LEFT_WRIST,
    RIGHT_HIP,
    RIGHT_WRIST,
    PoseDetection,
    PoseFrame,
)
from edge.tracking import Observation, Track

#: Extension above which a wrist is considered reached out toward a shelf.
REACH_THRESHOLD = 1.75

#: Extension below which a wrist is close to the torso.
#:
#: Proximity alone is not enough to call it a concealment position, because an arm hanging
#: at rest is also close to the torso. :data:`MEDIAL_THRESHOLD` supplies the missing half.
BODY_THRESHOLD = 0.95

#: Horizontal wrist position, as a multiple of the torso half-width, below which the hand is
#: *inside* the body silhouette.
#:
#: This is what separates "hand tucked at the waistband or inside a jacket" from "arm
#: hanging at the side". Both are close to the torso; only one is medial. Without this
#: distinction the detector flags every person who reaches for a shelf and then lets their
#: arm drop, which is everybody.
MEDIAL_THRESHOLD = 1.05

#: How long a hand must stay in the concealment position to count as a hold.
BODY_HOLD_SECONDS = 0.45

#: How long the memory of a recent reach persists. Within this window a hand arriving at the
#: body is interpreted in the context of that reach; afterwards it is just a resting arm.
POST_REACH_MEMORY_SECONDS = 3.0

#: Grace period after the hand leaves the concealment position, during which a reach still
#: counts as putting the item back.
#:
#: Needed because a hand travelling from the waistband back to a shelf passes through an
#: intermediate position on the way. Without the grace window the outbound leg looks like a
#: brand-new reach, the return is never credited, and putting an item back scores the same
#: as pocketing it. This is the difference between a working detector and one that flags
#: every shopper who changes their mind.
RETURN_GRACE_SECONDS = 1.5

#: Window over which the behavioural pattern is assessed.
ANALYSIS_WINDOW_SECONDS = 6.0

#: Dwell above this is unusual for a convenience store aisle. Weak signal on its own.
DWELL_ATTENTION_SECONDS = 25.0

#: Brightness below which pose quality degrades enough to discount the observation.
LOW_LIGHT_THRESHOLD = 0.30


@dataclass
class WristState:
    left_extension: float | None
    right_extension: float | None

    @property
    def max_extension(self) -> float | None:
        values = [v for v in (self.left_extension, self.right_extension) if v is not None]
        return max(values) if values else None

    @property
    def min_extension(self) -> float | None:
        values = [v for v in (self.left_extension, self.right_extension) if v is not None]
        return min(values) if values else None


def wrist_extensions(detection: PoseDetection) -> WristState:
    """Normalised distance from torso centre to each wrist."""
    torso = detection.torso_centre()
    scale = detection.scale_reference()

    if torso is None or scale <= 0:
        return WristState(None, None)

    def extension(index: int) -> float | None:
        wrist = detection.keypoint(index)
        if not wrist.visible:
            return None
        return math.dist((wrist.x, wrist.y), torso) / scale

    return WristState(extension(LEFT_WRIST), extension(RIGHT_WRIST))


def wrist_extension(detection: PoseDetection, wrist_index: int) -> float | None:
    """Normalised torso-to-wrist distance for one specific wrist.

    Per-arm rather than aggregated. Taking the maximum across both wrists hides the very
    thing we are looking for: while one hand tucks something away, the other stays at rest
    in a perfectly ordinary position, and the maximum reflects the ordinary one. People
    conceal with a single hand, so each arm has to be followed separately.
    """
    torso = detection.torso_centre()
    scale = detection.scale_reference()

    if torso is None or scale <= 0:
        return None

    wrist = detection.keypoint(wrist_index)
    if not wrist.visible:
        return None

    return math.dist((wrist.x, wrist.y), torso) / scale


def wrist_medial_ratio(detection: PoseDetection, wrist_index: int) -> float | None:
    """How far the wrist sits from the body's midline, as a multiple of torso half-width.

    Below roughly 1.0 the hand is within the body silhouette, which is where a waistband,
    pocket, or inside-jacket concealment puts it. An arm hanging at rest sits outside that
    line. This is the geometric feature that makes the reach-then-tuck pattern separable
    from the reach-then-drop pattern.
    """
    left_hip = detection.keypoint(LEFT_HIP)
    right_hip = detection.keypoint(RIGHT_HIP)
    wrist = detection.keypoint(wrist_index)

    if not (left_hip.visible and right_hip.visible and wrist.visible):
        return None

    centre_x = (left_hip.x + right_hip.x) / 2.0
    half_width = abs(left_hip.x - right_hip.x) / 2.0

    if half_width < 1e-3:
        return None

    return abs(wrist.x - centre_x) / half_width


def in_concealment_position(detection: PoseDetection, wrist_index: int) -> bool:
    """True when a wrist is both close to the torso and inside the body silhouette."""
    extension = wrist_extension(detection, wrist_index)
    medial = wrist_medial_ratio(detection, wrist_index)

    if extension is None or medial is None:
        return False

    return extension <= BODY_THRESHOLD and medial <= MEDIAL_THRESHOLD


def hip_level(detection: PoseDetection) -> float | None:
    """Mean y of the hips, used to distinguish a waistband tuck from a chest hold."""
    left = detection.keypoint(LEFT_HIP)
    right = detection.keypoint(RIGHT_HIP)
    usable = [kp for kp in (left, right) if kp.visible]
    if not usable:
        return None
    return sum(kp.y for kp in usable) / len(usable)


def wrist_below_hip(detection: PoseDetection) -> bool:
    """True when either wrist sits at or below hip height.

    A low tuck is consistent with a pocket, waistband, or bag; a high tuck is more often
    someone holding a basket or their phone against their chest. Weak on its own, useful
    in combination.
    """
    hips = hip_level(detection)
    if hips is None:
        return False

    for index in (LEFT_WRIST, RIGHT_WRIST):
        wrist = detection.keypoint(index)
        if wrist.visible and wrist.y >= hips - 8.0:
            return True
    return False


@dataclass
class GesturePattern:
    """Result of scanning a track's recent history for the reach/return pattern."""

    reach_count: int = 0
    return_to_shelf_count: int = 0
    body_hold_count: int = 0
    longest_body_hold_seconds: float = 0.0
    peak_extension: float = 0.0
    concealment_pattern: bool = False
    low_tuck: bool = False
    rapid_repeat: bool = False

    def as_dict(self) -> dict:
        return {
            "reach_count": self.reach_count,
            "return_to_shelf_count": self.return_to_shelf_count,
            "body_hold_count": self.body_hold_count,
            "longest_body_hold_seconds": round(self.longest_body_hold_seconds, 3),
            "peak_extension": round(self.peak_extension, 3),
            "concealment_pattern": self.concealment_pattern,
            "low_tuck": self.low_tuck,
            "rapid_repeat": self.rapid_repeat,
        }


def _scan_single_arm(observations: list[Observation], wrist_index: int) -> GesturePattern:
    """State machine over one arm's trajectory.

    States and the transitions that matter:

    ``idle``        nothing of interest. A deep reach moves to ``reached``.
    ``reached``     the hand is out at shelf distance.
    ``post_reach``  the hand has come back in but is not in a concealment position. This
                    state is what remembers that a reach just happened, for a bounded time.
    ``at_body``     the hand is close to the torso *and* inside the body silhouette.
    ``held``        it has stayed there long enough to be deliberate.

    The verdict hinges on how a hold ends:

    * hold ends with the hand returning to the shelf  → the item was replaced, benign, and
      the candidate is withdrawn.
    * hold ends with the hand moving away laterally, or the sequence ends mid-hold → the
      item did not go back, which is the concealment signal.

    Implemented explicitly rather than as a learned sequence model for two reasons. It is
    inspectable, so a rationale can be shown to a member of staff and to an auditor. And it
    needs no training data, which matters when the only lawful data available is a public
    research dataset filmed in someone else's shop.

    A temporal model trained on PoseLift is the intended upgrade, and this feature
    dictionary is designed to be its input rather than its replacement.
    """
    pattern = GesturePattern()
    if len(observations) < 3:
        return pattern

    state = "idle"
    hold_started: float | None = None
    last_reach_at: float | None = None

    #: When the hand most recently left the concealment position. A reach inside
    #: RETURN_GRACE_SECONDS of this counts as putting the item back.
    left_body_at: float | None = None

    #: True when the hold just vacated lasted long enough to be deliberate, and we are
    #: waiting to see whether the item goes back to the shelf.
    hold_awaiting_verdict = False

    concealment_confirmed = False

    for observation in observations:
        detection = observation.detection
        extension = wrist_extension(detection, wrist_index)
        if extension is None:
            continue

        now = as_utc(observation.timestamp).timestamp()
        pattern.peak_extension = max(pattern.peak_extension, extension)

        reaching = extension >= REACH_THRESHOLD
        concealing_position = in_concealment_position(detection, wrist_index)

        # A deliberate hold that was never followed by a return to the shelf. The grace
        # window has now expired, so the item did not go back.
        if (
            hold_awaiting_verdict
            and left_body_at is not None
            and now - left_body_at > RETURN_GRACE_SECONDS
        ):
            concealment_confirmed = True
            hold_awaiting_verdict = False

        if state == "idle":
            if reaching:
                state = "reached"
                last_reach_at = now
                hold_started = None
                pattern.reach_count += 1

        elif state == "reached":
            if concealing_position:
                state = "at_body"
                hold_started = now
            elif not reaching:
                state = "post_reach"
                last_reach_at = now

        elif state == "post_reach":
            if reaching:
                if left_body_at is not None and now - left_body_at <= RETURN_GRACE_SECONDS:
                    # Hand came from the body and is now back at the shelf: item replaced.
                    pattern.return_to_shelf_count += 1
                    hold_awaiting_verdict = False
                left_body_at = None
                state = "reached"
                last_reach_at = now
                hold_started = None
                pattern.reach_count += 1
            elif concealing_position:
                state = "at_body"
                hold_started = now
            elif last_reach_at is not None and now - last_reach_at > POST_REACH_MEMORY_SECONDS:
                # The reach is too long ago to give the hand's position any meaning.
                state = "idle"
                left_body_at = None

        elif state in {"at_body", "held"}:
            if reaching:
                # Straight from the body back out to the shelf, no intermediate frame.
                if hold_started is not None:
                    pattern.longest_body_hold_seconds = max(
                        pattern.longest_body_hold_seconds, now - hold_started
                    )
                pattern.return_to_shelf_count += 1
                hold_awaiting_verdict = False
                left_body_at = None
                state = "reached"
                last_reach_at = now
                hold_started = None
                pattern.reach_count += 1

            elif concealing_position:
                if hold_started is None:
                    hold_started = now
                held_for = now - hold_started
                pattern.longest_body_hold_seconds = max(
                    pattern.longest_body_hold_seconds, held_for
                )
                if held_for >= BODY_HOLD_SECONDS and state != "held":
                    state = "held"
                    pattern.body_hold_count += 1

            else:
                # Hand left the concealment position. Whether that is innocent depends on
                # what happens next, so the verdict is deferred rather than guessed.
                qualified = (
                    hold_started is not None and now - hold_started >= BODY_HOLD_SECONDS
                ) or state == "held"
                if qualified:
                    hold_awaiting_verdict = True
                left_body_at = now
                state = "post_reach"
                hold_started = None
                last_reach_at = now

    # Walked out of frame with the hand still tucked in. The strongest form of the signal.
    if state in {"at_body", "held"} and (
        pattern.longest_body_hold_seconds >= BODY_HOLD_SECONDS
    ):
        concealment_confirmed = True

    pattern.concealment_pattern = concealment_confirmed and pattern.reach_count > 0
    pattern.rapid_repeat = pattern.reach_count >= 3

    return pattern


def scan_gesture_pattern(observations: list[Observation]) -> GesturePattern:
    """Scan both arms and return the stronger signal.

    A confirmed concealment on either arm wins; otherwise the arm that did more reaching is
    reported, since that is the one carrying the information.
    """
    if len(observations) < 3:
        return GesturePattern()

    candidates = [
        _scan_single_arm(observations, LEFT_WRIST),
        _scan_single_arm(observations, RIGHT_WRIST),
    ]

    best = max(
        candidates,
        key=lambda p: (
            p.concealment_pattern,
            p.reach_count,
            p.longest_body_hold_seconds,
            p.peak_extension,
        ),
    )

    # Peak extension is a property of the person, not of one arm, so report the true peak
    # even when the other arm produced the winning pattern.
    best.peak_extension = max(p.peak_extension for p in candidates)
    best.low_tuck = wrist_below_hip(observations[-1].detection)

    return best


def quality_features(track: Track, frame: PoseFrame) -> dict:
    """Confidence reducers.

    Every one of these makes the behavioural inference less reliable, and each maps to a
    negative weight in :data:`core.policy.FEATURE_PENALTIES`. Reporting them is what stops
    the system from being confidently wrong about a blurry, half-occluded figure at the
    back of a dark aisle.
    """
    observations = track.window(ANALYSIS_WINDOW_SECONDS)

    if observations:
        # Body keypoints only. Head points are zeroed for privacy, so including them would
        # turn that control into a permanent occlusion penalty on every observation.
        visibility = statistics.fmean(
            obs.detection.body_visibility_ratio() for obs in observations
        )
        detection_confidence = statistics.fmean(
            obs.detection.detection_confidence for obs in observations
        )
    else:
        visibility = 0.0
        detection_confidence = 0.0

    fragmentation = clamp(track.fragment_count / 4.0)
    crowd = clamp((frame.crowd_size - 1) / 6.0)

    low_light = 0.0
    if frame.brightness is not None and frame.brightness < LOW_LIGHT_THRESHOLD:
        low_light = clamp((LOW_LIGHT_THRESHOLD - frame.brightness) / LOW_LIGHT_THRESHOLD)

    return {
        "occlusion_ratio": round(clamp(1.0 - visibility), 4),
        "detection_confidence": round(detection_confidence, 4),
        "track_fragmentation": round(fragmentation, 4),
        "crowd_density": round(crowd, 4),
        "low_light": round(low_light, 4),
        "observation_count": len(observations),
        "track_duration_seconds": round(track.duration_seconds, 2),
    }


def extract_features(track: Track, frame: PoseFrame) -> dict:
    """Full feature dictionary for one track at one moment.

    Flat, numeric, and small: it is published to the core service, stored as the rationale
    behind any prompt, and has to be explainable to a member of staff who asks why they
    were sent to an aisle.
    """
    observations = track.window(ANALYSIS_WINDOW_SECONDS)
    pattern = scan_gesture_pattern(observations)
    quality = quality_features(track, frame)

    latest = track.latest
    current = wrist_extensions(latest.detection) if latest else WristState(None, None)

    features: dict = {
        **pattern.as_dict(),
        **quality,
        "current_max_extension": (
            round(current.max_extension, 3) if current.max_extension is not None else None
        ),
        "dwell_seconds": round(track.duration_seconds, 2),
        "prolonged_dwell": track.duration_seconds >= DWELL_ATTENTION_SECONDS,
        # Named to match the adjustment keys the core policy engine understands.
        "bag_interaction": bool(pattern.concealment_pattern and pattern.low_tuck),
        "tag_removal_motion": False,  # requires fine hand pose; not implemented, see roadmap
        "body_shielding": _body_shielding(observations),
        "repeat_zone_entries": clamp(track.fragment_count / 3.0),
    }

    return {key: value for key, value in features.items() if value is not None}


def _body_shielding(observations: list[Observation]) -> float:
    """Estimate whether the person turned to put their body between hands and camera.

    Measured as a drop in apparent shoulder width, which narrows when someone rotates away.
    A genuine and commonly reported concealment behaviour, and also produced innocently by
    anyone who simply turns around, so it is returned as a bounded magnitude for the policy
    engine to weight lightly rather than as a boolean claim.
    """
    widths = [
        width
        for width in (obs.detection.shoulder_width() for obs in observations)
        if width is not None
    ]
    if len(widths) < 5:
        return 0.0

    reference = statistics.median(widths)
    if reference <= 0:
        return 0.0

    narrowest = min(widths)
    reduction = (reference - narrowest) / reference
    # Below a 25% narrowing this is indistinguishable from tracking noise.
    return round(clamp((reduction - 0.25) / 0.45), 4)
