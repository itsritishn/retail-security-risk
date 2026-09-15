"""Signed event publication to the core service.

Uses ``urllib`` from the standard library rather than a third-party HTTP client, so the edge
tier can be deployed on a minimal box with no dependency beyond Python itself when the
synthetic backend is in use.

Every outbound event is:

1. checked against the privacy boundary (:mod:`edge.privacy`),
2. serialised canonically so the signature is reproducible,
3. signed with HMAC-SHA256 under the per-camera ingest key,
4. stamped with a unique nonce for replay rejection at the core.

On failure, events are held in a **bounded in-memory** queue and retried. Deliberately not
spooled to disk: writing behavioural records to local storage on a box in a stock room
creates a data store nobody is managing, with no retention enforcement and no encryption,
in the least physically secure part of the estate. Losing events during an outage is the
better failure mode, and the loss is counted and reported rather than hidden.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field

from core.util import canonical_json, hmac_sha256_hex
from edge.privacy import (
    PrivacyViolation,
    assert_no_imagery,
    redact_prohibited_features,
    round_features,
)

logger = logging.getLogger("sentinelfloor.edge.publisher")

EDGE_SIGNATURE_HEADER = "X-SF-Signature"

#: Bounded retry queue. Small on purpose: this is a buffer for a brief network blip, not a
#: store of record.
RETRY_QUEUE_MAX = 200


@dataclass
class PublisherStats:
    published: int = 0
    rejected_auth: int = 0
    rejected_replay: int = 0
    rejected_validation: int = 0
    privacy_blocked: int = 0
    dropped_queue_full: int = 0
    network_errors: int = 0
    alerts_raised: int = 0

    def as_dict(self) -> dict:
        return {
            "published": self.published,
            "alerts_raised": self.alerts_raised,
            "rejected_auth": self.rejected_auth,
            "rejected_replay": self.rejected_replay,
            "rejected_validation": self.rejected_validation,
            "privacy_blocked": self.privacy_blocked,
            "dropped_queue_full": self.dropped_queue_full,
            "network_errors": self.network_errors,
        }


@dataclass
class PublishResult:
    ok: bool
    status: int | None = None
    body: dict | None = None
    error: str | None = None

    @property
    def alerted(self) -> bool:
        return bool(self.body and self.body.get("alerted"))


@dataclass
class EventPublisher:
    """Signs and delivers events for a single camera."""

    core_url: str
    camera_code: str
    ingest_key: str
    timeout_seconds: float = 5.0
    max_attempts: int = 3
    stats: PublisherStats = field(default_factory=PublisherStats)
    _retry_queue: deque[dict] = field(default_factory=lambda: deque(maxlen=RETRY_QUEUE_MAX))

    @property
    def endpoint(self) -> str:
        return f"{self.core_url.rstrip('/')}/api/v1/events"

    # ------------------------------------------------------------------ send

    def publish(self, payload: dict) -> PublishResult:
        """Sanitise, sign, and send one event."""
        try:
            prepared = self._prepare(payload)
        except PrivacyViolation as exc:
            # Fail closed. A payload that trips the privacy check is a bug in feature
            # extraction, and sending it anyway would break the system's central promise.
            self.stats.privacy_blocked += 1
            logger.error("refusing to publish, privacy boundary violated: %s", exc)
            return PublishResult(False, error=f"privacy_violation: {exc}")

        result = self._send_with_retries(prepared)

        if result.ok:
            self.stats.published += 1
            if result.alerted:
                self.stats.alerts_raised += 1
            self._drain_retry_queue()
        else:
            self._enqueue_retry(prepared)

        return result

    def _prepare(self, payload: dict) -> dict:
        features = dict(payload.get("features") or {})
        features, removed = redact_prohibited_features(features)
        if removed:
            # Counted so the condition is visible even though the event still goes out
            # having been cleaned.
            self.stats.privacy_blocked += 1

        features = round_features(features)

        prepared = {**payload, "features": features}
        assert_no_imagery(prepared)
        return prepared

    def _sign(self, payload: dict) -> str:
        return hmac_sha256_hex(self.ingest_key, canonical_json(payload))

    def _send_with_retries(self, payload: dict) -> PublishResult:
        backoff = 0.4

        for attempt in range(1, self.max_attempts + 1):
            result = self._send_once(payload)

            if result.ok:
                return result

            # Terminal failures. Retrying an authentication failure or a rejected schema
            # will fail identically every time and only adds load.
            if result.status in {401, 403, 409, 413, 422}:
                return result

            if attempt < self.max_attempts:
                time.sleep(backoff)
                backoff *= 2

        return result

    def _send_once(self, payload: dict) -> PublishResult:
        body = canonical_json(payload).encode("utf-8")
        signature = self._sign(payload)

        request = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                EDGE_SIGNATURE_HEADER: signature,
                "User-Agent": f"sentinelfloor-edge/{self.camera_code}",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                parsed = json.loads(raw) if raw else {}
                return PublishResult(True, status=response.status, body=parsed)

        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8")[:500]
            except Exception:  # noqa: BLE001
                pass

            if exc.code == 401:
                self.stats.rejected_auth += 1
                logger.error(
                    "core rejected event authentication for camera %s. Check the ingest "
                    "key and the system clock: a skewed clock looks exactly like a replay.",
                    self.camera_code,
                )
            elif exc.code == 409:
                self.stats.rejected_replay += 1
                logger.warning("nonce already seen, treating as delivered")
                # An idempotent duplicate. The core already has it, so this is success.
                return PublishResult(True, status=409, body={"alerted": False})
            elif exc.code == 422:
                self.stats.rejected_validation += 1
                logger.error("core rejected event as invalid: %s", detail)

            return PublishResult(False, status=exc.code, error=detail or str(exc))

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.stats.network_errors += 1
            logger.warning("network error publishing event: %s", exc)
            return PublishResult(False, error=str(exc))

        except json.JSONDecodeError as exc:
            return PublishResult(False, error=f"unparseable response: {exc}")

    # --------------------------------------------------------------- retries

    def _enqueue_retry(self, payload: dict) -> None:
        if len(self._retry_queue) >= RETRY_QUEUE_MAX:
            self.stats.dropped_queue_full += 1
            logger.warning("retry queue full, dropping oldest event")
        self._retry_queue.append(payload)

    def _drain_retry_queue(self, limit: int = 5) -> None:
        """Opportunistically flush buffered events after a successful send."""
        sent = 0
        while self._retry_queue and sent < limit:
            payload = self._retry_queue.popleft()
            result = self._send_once(payload)
            if not result.ok:
                self._retry_queue.appendleft(payload)
                break
            self.stats.published += 1
            if result.alerted:
                self.stats.alerts_raised += 1
            sent += 1

    @property
    def pending_retries(self) -> int:
        return len(self._retry_queue)

    # -------------------------------------------------------------- liveness

    def heartbeat(self, occurred_at: str) -> PublishResult:
        """Report liveness.

        Necessary because the core cannot distinguish a quiet aisle from a dead camera.
        Absence of events is only meaningful if presence is confirmed some other way.
        """
        from core.util import new_nonce

        return self.publish(
            {
                "camera_code": self.camera_code,
                "event_type": "heartbeat",
                "track_ref": "heartbeat",
                "raw_score": 0.0,
                "features": {},
                "occurred_at": occurred_at,
                "nonce": new_nonce(),
                "model_version": "n/a",
            }
        )

    def report_obstruction(self, occurred_at: str, detail: dict) -> PublishResult:
        """Report that the view appears blocked or the camera has moved.

        Treated as a security event rather than a data quality issue: an obstructed lens is
        an integrity failure in the control itself, and it is a known and trivially easy way
        to defeat one of these systems. The core bypasses the score threshold for this
        event type so it always surfaces.
        """
        from core.util import new_nonce

        return self.publish(
            {
                "camera_code": self.camera_code,
                "event_type": "obscured_view",
                "track_ref": "camera-integrity",
                "raw_score": 0.75,
                "features": detail,
                "occurred_at": occurred_at,
                "nonce": new_nonce(),
                "model_version": "integrity-monitor-0.1.0",
            }
        )
