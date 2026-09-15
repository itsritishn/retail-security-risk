"""Edge pipeline orchestration.

    pose frames  →  tracking  →  feature extraction  →  scoring  →  signed publication

Plus two things that are easy to forget and matter more than the detector:

* **Heartbeats.** The core service cannot tell a quiet aisle from a dead camera. Silence is
  only informative if liveness is confirmed separately.
* **Integrity monitoring.** Covering a lens is the cheapest way to defeat a system like
  this. A brightness collapse is treated as a security event, not as a data quality note.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime

from core.util import as_utc, utcnow
from edge.backends import PoseBackend, build_backend
from edge.backends.base import PoseFrame
from edge.privacy import strip_head_keypoints
from edge.publisher import EventPublisher
from edge.scoring import BehaviourAnalyser
from edge.tracking import Tracker

logger = logging.getLogger("sentinelfloor.edge.pipeline")

#: Liveness interval. Must be shorter than the core's staleness window (180s).
HEARTBEAT_SECONDS = 60.0

#: Brightness below this, sustained, is consistent with a covered or sprayed lens.
OBSTRUCTION_BRIGHTNESS = 0.08
OBSTRUCTION_SUSTAIN_SECONDS = 10.0

#: Minimum gap between repeated obstruction reports, so a genuinely broken camera does not
#: generate an alert every frame.
OBSTRUCTION_REPORT_COOLDOWN_SECONDS = 300.0


@dataclass
class PipelineStats:
    frames: int = 0
    detections: int = 0
    tracks_created: int = 0
    events_generated: int = 0
    events_published: int = 0
    alerts_raised: int = 0
    heartbeats: int = 0
    obstructions_reported: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    def as_dict(self) -> dict:
        return {
            "frames": self.frames,
            "detections": self.detections,
            "tracks_created": self.tracks_created,
            "events_generated": self.events_generated,
            "events_published": self.events_published,
            "alerts_raised": self.alerts_raised,
            "heartbeats": self.heartbeats,
            "obstructions_reported": self.obstructions_reported,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "frames_per_second": (
                round(self.frames / self.elapsed_seconds, 2)
                if self.elapsed_seconds > 0
                else None
            ),
        }


class _IntegrityMonitor:
    """Detects sustained loss of usable view."""

    def __init__(self) -> None:
        self._dark_since: datetime | None = None
        self._last_report: datetime | None = None

    def assess(self, frame: PoseFrame) -> dict | None:
        """Return obstruction detail when a report should be raised."""
        brightness = frame.brightness
        if brightness is None:
            return None

        now = as_utc(frame.timestamp)

        if brightness > OBSTRUCTION_BRIGHTNESS:
            self._dark_since = None
            return None

        if self._dark_since is None:
            self._dark_since = now
            return None

        sustained = (now - self._dark_since).total_seconds()
        if sustained < OBSTRUCTION_SUSTAIN_SECONDS:
            return None

        if self._last_report is not None:
            since_report = (now - self._last_report).total_seconds()
            if since_report < OBSTRUCTION_REPORT_COOLDOWN_SECONDS:
                return None

        self._last_report = now
        return {
            "brightness": round(brightness, 4),
            "sustained_seconds": round(sustained, 1),
            "reason": "sustained_low_brightness",
            "interpretation": (
                "The view has been effectively dark for a sustained period. Consistent "
                "with a covered, sprayed, or unplugged camera, or with lighting failure."
            ),
        }


@dataclass
class EdgePipeline:
    """Runs one camera end to end."""

    camera_code: str
    publisher: EventPublisher
    backend: PoseBackend
    tracker: Tracker = field(default_factory=Tracker)
    analyser: BehaviourAnalyser = field(default_factory=BehaviourAnalyser)
    stats: PipelineStats = field(default_factory=PipelineStats)
    heartbeat_seconds: float = HEARTBEAT_SECONDS
    dry_run: bool = False

    _integrity: _IntegrityMonitor = field(default_factory=_IntegrityMonitor)
    _seen_track_refs: set[str] = field(default_factory=set)
    _last_heartbeat: datetime | None = None

    @staticmethod
    def _publication_timestamp() -> str:
        """The ``occurred_at`` stamped on a published event.

        Two clocks are in play and conflating them causes a subtle, confusing failure.

        The **frame clock** drives all behavioural reasoning: how long a hand was held at
        the body, how long a person dwelled. During a compressed replay it advances far
        faster than wall time, which is exactly what makes fast testing possible.

        The **wall clock** is what the core service validates against, because its replay
        protection is defined as a window around real now. Publishing frame time during a
        compressed replay sends timestamps minutes into the future, and the core correctly
        rejects every one of them as a possible replay.

        So behaviour is measured on the frame clock and publication is stamped on the wall
        clock. In a live deployment the two differ only by inference latency.
        """
        return utcnow().isoformat()

    @classmethod
    def from_config(cls, config: dict) -> "EdgePipeline":
        camera_code = str(config["camera_code"])
        backend_name = str(config.get("backend", "synthetic"))
        backend_config = dict(config.get("backend_options") or {})

        publisher = EventPublisher(
            core_url=str(config.get("core_url", "http://127.0.0.1:8000")),
            camera_code=camera_code,
            ingest_key=str(config["ingest_key"]),
            timeout_seconds=float(config.get("timeout_seconds", 5.0)),
        )

        tracker = Tracker(
            iou_threshold=float(config.get("iou_threshold", 0.25)),
            max_missed_frames=int(config.get("max_missed_frames", 8)),
            max_track_age_seconds=float(config.get("max_track_age_seconds", 180.0)),
        )

        analyser = BehaviourAnalyser(
            publish_floor=float(config.get("publish_floor", 0.35))
        )

        return cls(
            camera_code=camera_code,
            publisher=publisher,
            backend=build_backend(backend_name, backend_config),
            tracker=tracker,
            analyser=analyser,
            heartbeat_seconds=float(config.get("heartbeat_seconds", HEARTBEAT_SECONDS)),
            dry_run=bool(config.get("dry_run", False)),
        )

    # ------------------------------------------------------------------- run

    def run(self, *, realtime: bool = False, frame_limit: int | None = None) -> PipelineStats:
        """Process frames until the source is exhausted.

        ``realtime`` paces the loop against wall clock, which matters when demonstrating on
        a live dashboard so that alerts appear at a human rate rather than all at once.
        """
        logger.info(
            "edge pipeline starting camera=%s backend=%s dry_run=%s",
            self.camera_code,
            self.backend.name,
            self.dry_run,
        )

        previous_timestamp: datetime | None = None

        try:
            for frame in self.backend.frames():
                if frame_limit is not None and self.stats.frames >= frame_limit:
                    break

                if realtime and previous_timestamp is not None:
                    gap = (as_utc(frame.timestamp) - as_utc(previous_timestamp)).total_seconds()
                    if 0 < gap < 2.0:
                        time.sleep(gap)
                previous_timestamp = frame.timestamp

                self._process_frame(frame)

        except KeyboardInterrupt:
            logger.info("interrupted, shutting down cleanly")
        finally:
            self.backend.close()

        logger.info("edge pipeline finished: %s", self.stats.as_dict())
        return self.stats

    def _process_frame(self, frame: PoseFrame) -> None:
        self.stats.frames += 1
        self.stats.detections += len(frame.detections)

        # Facial keypoints are removed here, at the earliest point after extraction, so no
        # downstream component ever sees them.
        sanitised = PoseFrame(
            timestamp=frame.timestamp,
            detections=[strip_head_keypoints(d) for d in frame.detections],
            frame_index=frame.frame_index,
            width=frame.width,
            height=frame.height,
            brightness=frame.brightness,
        )

        obstruction = self._integrity.assess(sanitised)
        if obstruction is not None:
            self.stats.obstructions_reported += 1
            logger.warning("camera %s view obstructed: %s", self.camera_code, obstruction)
            if not self.dry_run:
                self.publisher.report_obstruction(
                    self._publication_timestamp(), obstruction
                )

        tracks = self.tracker.update(sanitised)

        for track in tracks:
            if track.track_ref not in self._seen_track_refs:
                self._seen_track_refs.add(track.track_ref)
                self.stats.tracks_created += 1

        events = self.analyser.observe(tracks, sanitised)

        for event in events:
            self.stats.events_generated += 1
            # Re-stamped on the wall clock at the moment of publication. See
            # _publication_timestamp for why the frame clock cannot be used here.
            event.occurred_at = self._publication_timestamp()
            payload = event.as_payload(self.camera_code)

            if self.dry_run:
                logger.info(
                    "[dry-run] %s track=%s score=%.3f",
                    event.event_type,
                    event.track_ref,
                    event.score,
                )
                continue

            result = self.publisher.publish(payload)
            if result.ok:
                self.stats.events_published += 1
                if result.alerted:
                    self.stats.alerts_raised += 1
                    logger.info(
                        "ALERT raised: %s score=%.3f (core alert id=%s)",
                        event.event_type,
                        event.score,
                        (result.body or {}).get("alert_id"),
                    )
                else:
                    logger.debug(
                        "event accepted without alert: %s reason=%s",
                        event.event_type,
                        (result.body or {}).get("suppressed_reason"),
                    )
            else:
                logger.warning(
                    "failed to publish %s: %s", event.event_type, result.error
                )

        self._maybe_heartbeat(sanitised)

    def _maybe_heartbeat(self, frame: PoseFrame) -> None:
        now = as_utc(frame.timestamp)

        if self._last_heartbeat is not None:
            elapsed = (now - self._last_heartbeat).total_seconds()
            if elapsed < self.heartbeat_seconds:
                return

        self._last_heartbeat = now
        self.stats.heartbeats += 1

        if not self.dry_run:
            self.publisher.heartbeat(self._publication_timestamp())
