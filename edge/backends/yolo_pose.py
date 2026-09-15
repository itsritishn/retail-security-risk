"""Real pose inference via YOLO-pose.

Imported lazily. Requires ``requirements-edge.txt``.

The frame lifecycle here is the point of the module: a frame is read, passed to the pose
model, converted to keypoints, and dropped before the next iteration. It is never written
to disk, never cached, and never transmitted. The only thing that leaves this process is
geometry.

There is also a deliberate compliance gate. Pointing this at a live camera stream requires
an explicit ``authorisation_reference`` in the config, and the backend refuses to start
without one. That is not bureaucracy for its own sake: the most likely way a project like
this causes real harm is a student pointing it at their employer's CCTV because it was
technically easy, which is a data protection breach and a disciplinary matter. Making the
easy path the authorised path is a control, not a comment.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timezone

from edge.backends.base import (
    KEYPOINT_COUNT,
    Keypoint,
    PoseBackend,
    PoseDetection,
    PoseFrame,
)

logger = logging.getLogger("sentinelfloor.edge.yolo")

#: Source prefixes treated as live camera streams requiring authorisation.
LIVE_SOURCE_PREFIXES = ("rtsp://", "rtsps://", "http://", "https://", "rtmp://")


class AuthorisationRequired(RuntimeError):
    """Raised when a live stream is configured without a recorded authorisation."""


class YoloPoseBackend(PoseBackend):
    name = "yolo_pose"

    def __init__(self, config: dict | None = None) -> None:
        config = config or {}

        # Imported here rather than at module scope so that the absence of these packages
        # is only an error for someone who actually selected this backend.
        import cv2  # noqa: PLC0415
        from ultralytics import YOLO  # noqa: PLC0415

        self._cv2 = cv2

        self.source: str = str(config.get("source", "0"))
        self.weights: str = str(config.get("weights", "yolo11n-pose.pt"))
        self.confidence: float = float(config.get("confidence", 0.35))
        self.frame_stride: int = max(1, int(config.get("frame_stride", 3)))
        self.device: str | None = config.get("device")
        self.max_frames: int | None = config.get("max_frames")
        self.imgsz: int = int(config.get("imgsz", 640))

        self._assert_authorised(config)

        logger.info("loading pose weights: %s", self.weights)
        self._model = YOLO(self.weights)

        self._capture = cv2.VideoCapture(
            int(self.source) if self.source.isdigit() else self.source
        )
        if not self._capture.isOpened():
            raise RuntimeError(f"could not open video source: {self.source!r}")

        self._fps = self._capture.get(cv2.CAP_PROP_FPS) or 12.0
        self._width = int(self._capture.get(cv2.CAP_PROP_FRAME_WIDTH)) or 1920
        self._height = int(self._capture.get(cv2.CAP_PROP_FRAME_HEIGHT)) or 1080

    def _assert_authorised(self, config: dict) -> None:
        """Refuse to open a live stream without a recorded authorisation reference."""
        source_lower = self.source.lower()
        is_live = source_lower.startswith(LIVE_SOURCE_PREFIXES) or source_lower.isdigit()

        if not is_live:
            return

        reference = str(config.get("authorisation_reference", "")).strip()
        if not reference:
            raise AuthorisationRequired(
                "This source looks like a live camera or webcam.\n\n"
                "Set 'authorisation_reference' in the edge config to the record of "
                "written authorisation from the data controller, together with the "
                "completed DPIA reference (see docs/04-dpia-privacy.md).\n\n"
                "If this is your employer's CCTV and you do not have that authorisation "
                "in writing, stop. Use the synthetic backend, PoseLift, UCF-Crime, or "
                "footage you recorded yourself with the informed consent of everyone in "
                "frame."
            )

        logger.warning(
            "live source enabled under authorisation reference %r. Ensure signage, "
            "staff consultation, and retention settings are in place.",
            reference,
        )

    def frames(self) -> Iterator[PoseFrame]:
        index = 0
        emitted = 0

        while True:
            ok, frame = self._capture.read()
            if not ok:
                break

            index += 1
            if index % self.frame_stride != 0:
                # Frame dropped without inference. Reference released immediately.
                frame = None
                continue

            brightness = self._mean_brightness(frame)

            results = self._model.predict(
                frame,
                conf=self.confidence,
                imgsz=self.imgsz,
                device=self.device,
                verbose=False,
            )

            detections = self._to_detections(results)

            # The frame is released here, before anything is yielded. Downstream code
            # never receives a reference to pixel data, so it cannot accidentally persist
            # or forward it.
            del frame

            yield PoseFrame(
                timestamp=datetime.now(timezone.utc),
                detections=detections,
                frame_index=index,
                width=self._width,
                height=self._height,
                brightness=brightness,
            )

            emitted += 1
            if self.max_frames is not None and emitted >= int(self.max_frames):
                break

    def _mean_brightness(self, frame) -> float | None:  # noqa: ANN001
        """Cheap luminance estimate used to discount low-light observations."""
        try:
            grey = self._cv2.cvtColor(frame, self._cv2.COLOR_BGR2GRAY)
            return float(grey.mean()) / 255.0
        except Exception:  # noqa: BLE001
            return None

    def _to_detections(self, results) -> list[PoseDetection]:  # noqa: ANN001
        detections: list[PoseDetection] = []

        for result in results:
            keypoint_block = getattr(result, "keypoints", None)
            boxes = getattr(result, "boxes", None)
            if keypoint_block is None or boxes is None:
                continue

            coordinates = getattr(keypoint_block, "xy", None)
            confidences = getattr(keypoint_block, "conf", None)
            if coordinates is None:
                continue

            for person_index in range(len(coordinates)):
                points = coordinates[person_index].tolist()
                if len(points) < KEYPOINT_COUNT:
                    continue

                if confidences is not None:
                    scores = confidences[person_index].tolist()
                else:
                    scores = [1.0] * KEYPOINT_COUNT

                keypoints = [
                    Keypoint(
                        x=float(points[i][0]),
                        y=float(points[i][1]),
                        confidence=float(scores[i]) if i < len(scores) else 0.0,
                    )
                    for i in range(KEYPOINT_COUNT)
                ]

                try:
                    box = boxes[person_index].xyxy[0].tolist()
                    detection_confidence = float(boxes[person_index].conf[0])
                except Exception:  # noqa: BLE001
                    visible = [kp for kp in keypoints if kp.confidence >= 0.3]
                    if not visible:
                        continue
                    box = [
                        min(kp.x for kp in visible),
                        min(kp.y for kp in visible),
                        max(kp.x for kp in visible),
                        max(kp.y for kp in visible),
                    ]
                    detection_confidence = 0.5

                detections.append(
                    PoseDetection(
                        bbox=(float(box[0]), float(box[1]), float(box[2]), float(box[3])),
                        keypoints=keypoints,
                        detection_confidence=detection_confidence,
                    )
                )

        return detections

    def close(self) -> None:
        capture = getattr(self, "_capture", None)
        if capture is not None:
            capture.release()
