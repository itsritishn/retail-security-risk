"""Edge event ingest.

This is the most security-sensitive route in the service. It accepts data from devices
sitting on the same network as the cameras, which is the least trustworthy part of any
retail estate: NVRs run firmware from 2016, and the edge box is a small computer in a
stock room that many people can physically reach.

Controls applied here, in order:

1. **Body size cap** before parsing, so a large payload cannot be used to exhaust memory.
2. **HMAC-SHA256 authentication** against a per-camera key, verified over the canonical
   JSON of the received payload.
3. **Timestamp skew window**, rejecting stale and future-dated events.
4. **Nonce uniqueness** per camera, enforced by a database constraint, which is the only
   place the check can be made atomic under concurrency.
5. **Schema validation** with unknown fields forbidden.
6. **Fairness screen** rejecting any feature that encodes a protected characteristic.
7. **Per-camera rate limit**, so one compromised edge box cannot flood the estate.

Signature verification runs against the raw parsed dictionary rather than the
re-serialised Pydantic model. Validating first and then signing over the model's output
would mean verifying a different byte sequence from the one the edge signed, which is a
subtle and very common way to break message authentication.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from core import audit
from core.alerting import alert_message, hub
from core.config import Settings, get_settings
from core.db import SessionFactory
from core.models import Alert, AlertStatus, Camera, Event, EventType
from core.policy import PolicyEngine, ProhibitedFeatureError, assert_features_permitted
from core.schemas import EventAccepted, EventIn
from core.security import (
    EDGE_SIGNATURE_HEADER,
    EdgeAuthError,
    ingest_throttle,
    verify_edge_event,
)
from core.util import hours_from_now, iso, utcnow

logger = logging.getLogger("sentinelfloor.ingest")

router = APIRouter(prefix="/api/v1", tags=["ingest"])

#: A legitimate event is a few hundred bytes. 16 KiB is generous and still bounded.
MAX_EVENT_BODY_BYTES = 16 * 1024


@router.post("/events", response_model=EventAccepted)
async def ingest_event(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> EventAccepted:
    raw = await request.body()

    if len(raw) > MAX_EVENT_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Event payload exceeds {MAX_EVENT_BODY_BYTES} bytes",
        )

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Body is not valid JSON"
        ) from None

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Body must be a JSON object"
        )

    signature = request.headers.get(EDGE_SIGNATURE_HEADER, "")
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing {EDGE_SIGNATURE_HEADER} header",
        )

    source_ip = request.client.host if request.client else "unknown"

    # The database work is synchronous. Offloading it keeps the event loop free so that
    # WebSocket delivery to the dashboard is not stalled behind ingest.
    return await run_in_threadpool(
        _process_event, payload, signature, source_ip, settings
    )


def _process_event(
    payload: dict,
    signature: str,
    source_ip: str,
    settings: Settings,
) -> EventAccepted:
    session: Session = SessionFactory()
    try:
        camera_code = str(payload.get("camera_code", ""))[:48]

        if not ingest_throttle.check(f"ingest:{camera_code or source_ip}"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Ingest rate limit exceeded for this camera",
            )

        try:
            camera = verify_edge_event(
                session,
                camera_code,
                signature,
                payload,
                skew_seconds=settings.event_clock_skew_seconds,
            )
        except EdgeAuthError as exc:
            # Audited: a signature failure is either a misconfigured edge worker or someone
            # probing the ingest endpoint. Both need to be visible. The camera did not
            # authenticate, so there is no trustworthy store to attribute it to and it goes
            # on the system chain.
            audit.record(
                session,
                store_id=audit.system_store_id(session),
                actor_type="edge",
                actor_ref=camera_code or "unknown",
                action="event.rejected",
                outcome="denied",
                detail={"reason": str(exc)},
                source_ip=source_ip,
            )
            session.commit()
            logger.warning("rejected edge event camera=%s reason=%s", camera_code, exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Event authentication failed",
            ) from exc

        try:
            event_in = EventIn.model_validate(payload)
        except ValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=json.loads(exc.json()),
            ) from exc

        try:
            assert_features_permitted(event_in.features)
        except ProhibitedFeatureError as exc:
            # Loud and audited. An edge worker attempting to send demographic features is
            # either a serious misconfiguration or a deliberate attempt to bypass the
            # system's core constraint, and neither should ever pass quietly.
            audit.record(
                session,
                store_id=camera.store_id,
                actor_type="edge",
                actor_ref=camera.code,
                action="event.rejected_prohibited_feature",
                outcome="denied",
                detail={"offending_keys": exc.offending},
                source_ip=source_ip,
            )
            session.commit()
            logger.error(
                "camera=%s attempted prohibited features: %s", camera.code, exc.offending
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

        camera.last_seen_at = utcnow()

        if event_in.event_type == EventType.HEARTBEAT.value:
            session.add(camera)
            session.commit()
            return EventAccepted(suppressed_reason="heartbeat_not_persisted")

        event = Event(
            store_id=camera.store_id,
            camera_id=camera.id,
            zone_id=camera.zone_id,
            event_type=event_in.event_type,
            track_ref=event_in.track_ref,
            raw_score=event_in.raw_score,
            features=event_in.features,
            model_version=event_in.model_version,
            occurred_at=event_in.occurred_at,
            received_at=utcnow(),
            expires_at=hours_from_now(settings.event_retention_hours),
            nonce=event_in.nonce,
        )
        session.add(event)

        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            # Nonce collision. Either a genuine retry from an edge worker that did not
            # see our response, or a replay. Idempotent 409 rather than a duplicate row.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Event nonce already seen for this camera",
            ) from None

        decision = PolicyEngine(settings).evaluate(session, event, camera.zone)

        alert: Alert | None = None
        if decision.should_alert:
            alert = Alert(
                store_id=camera.store_id,
                event_id=event.id,
                zone_id=event.zone_id,
                score=decision.score,
                severity=decision.severity,
                status=AlertStatus.OPEN.value,
                headline=decision.headline,
                rationale=decision.rationale(),
                escalated=decision.escalate,
            )
            session.add(alert)
            session.flush()

            audit.record(
                session,
                store_id=camera.store_id,
                actor_type="system",
                actor_ref="policy-engine",
                action="alert.raised",
                target_type="alert",
                target_ref=str(alert.id),
                detail={
                    "score": round(decision.score, 4),
                    "severity": decision.severity,
                    "event_type": event.event_type,
                    "camera": camera.code,
                    "zone": camera.zone.code if camera.zone else None,
                    "model_version": event.model_version,
                    "escalated": decision.escalate,
                },
                source_ip=source_ip,
            )
        elif decision.suppressed_reason == "zone_budget_exhausted":
            # Recorded because it means staff are *not* being told about something that
            # crossed the threshold. Suppression has to be as auditable as alerting,
            # otherwise the system can go quiet without anyone noticing.
            audit.record(
                session,
                store_id=camera.store_id,
                actor_type="system",
                actor_ref="policy-engine",
                action="alert.suppressed",
                target_type="event",
                target_ref=str(event.id),
                outcome="suppressed",
                detail={
                    "reason": decision.suppressed_reason,
                    "score": round(decision.score, 4),
                    "zone": camera.zone.code if camera.zone else None,
                },
                source_ip=source_ip,
            )

        session.commit()

        if alert is not None:
            hub.publish(
                camera.store_id,
                alert_message(
                    kind="alert.new",
                    payload={
                        "id": alert.id,
                        "headline": alert.headline,
                        "severity": alert.severity,
                        "score": round(alert.score, 3),
                        "zone": camera.zone.name if camera.zone else None,
                        "camera": camera.name,
                        "event_type": event.event_type,
                        "escalated": alert.escalated,
                        "created_at": iso(alert.created_at),
                        "rationale": alert.rationale,
                    },
                ),
            )

        return EventAccepted(
            event_id=event.id,
            alert_id=alert.id if alert else None,
            alerted=alert is not None,
            score=round(decision.score, 4),
            severity=decision.severity,
            suppressed_reason=decision.suppressed_reason,
        )
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        logger.exception("unhandled error processing edge event")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error processing event",
        ) from None
    finally:
        session.close()
