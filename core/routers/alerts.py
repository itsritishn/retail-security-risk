"""Alert queue, disposition capture, and the live WebSocket feed."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.websockets import WebSocket, WebSocketDisconnect

from core import audit
from core.alerting import Subscriber, alert_message, hub
from core.db import get_session
from core.models import Alert, AlertStatus, Camera, Disposition, Role, User
from core.schemas import AlertOut, DispositionIn
from core.security import (
    SESSION_COOKIE,
    decode_session_token,
    get_current_user,
    require_min_role,
    require_roles,
    verify_csrf,
)
from core.util import as_utc, iso, utcnow

logger = logging.getLogger("sentinelfloor.alerts")

router = APIRouter(tags=["alerts"])

#: Roles permitted to work the alert queue. Auditors are excluded by design: their remit
#: is to review what happened, not to take operational action.
OPERATIONAL_ROLES = (Role.ASSISTANT, Role.DUTY_MANAGER, Role.ADMIN)


def _to_out(session: Session, alert: Alert) -> AlertOut:
    camera = session.get(Camera, alert.event.camera_id) if alert.event else None
    return AlertOut(
        id=alert.id,
        zone=alert.zone.name if alert.zone else None,
        camera=camera.name if camera else None,
        event_type=alert.event.event_type if alert.event else "unknown",
        score=round(alert.score, 3),
        severity=alert.severity,
        status=alert.status,
        headline=alert.headline,
        escalated=alert.escalated,
        created_at=iso(alert.created_at) or "",
        acknowledged_at=iso(alert.acknowledged_at),
        acknowledged_by=alert.acknowledged_by.display_name if alert.acknowledged_by else None,
        disposition=alert.disposition,
        rationale=alert.rationale or {},
        age_seconds=round((utcnow() - as_utc(alert.created_at)).total_seconds(), 1),
    )


@router.get("/api/v1/alerts", response_model=list[AlertOut])
def list_alerts(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[AlertOut]:
    """List alerts for the caller's own store.

    Store scoping comes from the authenticated session, never from a query parameter.
    Letting a client name the store it wants to read is how multi-tenant systems leak
    across tenants.
    """
    statement = select(Alert).where(Alert.store_id == user.store_id)

    if status_filter:
        if status_filter not in {item.value for item in AlertStatus}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown status filter"
            )
        statement = statement.where(Alert.status == status_filter)

    statement = statement.order_by(Alert.created_at.desc()).limit(limit)
    alerts = session.execute(statement).scalars().all()
    return [_to_out(session, alert) for alert in alerts]


def _load_own_alert(session: Session, alert_id: int, user: User) -> Alert:
    alert = session.get(Alert, alert_id)
    # A missing alert and another store's alert return the same 404. Distinguishing them
    # would confirm the existence of records the caller has no right to know about.
    if alert is None or alert.store_id != user.store_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.post("/api/v1/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(
    alert_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(*OPERATIONAL_ROLES)),
    _: None = Depends(verify_csrf),
) -> AlertOut:
    alert = _load_own_alert(session, alert_id, user)

    if alert.status != AlertStatus.OPEN.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Alert is already {alert.status}",
        )

    alert.status = AlertStatus.ACKNOWLEDGED.value
    alert.acknowledged_at = utcnow()
    alert.acknowledged_by_id = user.id
    session.add(alert)

    audit.record(
        session,
        store_id=user.store_id,
        actor_type="user",
        actor_ref=user.username,
        action="alert.acknowledged",
        target_type="alert",
        target_ref=str(alert.id),
        detail={"seconds_to_acknowledge": alert.time_to_acknowledge_seconds},
        source_ip=request.client.host if request.client else None,
    )
    session.commit()
    session.refresh(alert)

    hub.publish(
        user.store_id,
        alert_message(
            kind="alert.acknowledged",
            payload={"id": alert.id, "by": user.display_name},
        ),
    )
    return _to_out(session, alert)


@router.post("/api/v1/alerts/{alert_id}/resolve", response_model=AlertOut)
def resolve_alert(
    alert_id: int,
    body: DispositionIn,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(*OPERATIONAL_ROLES)),
    _: None = Depends(verify_csrf),
) -> AlertOut:
    """Close an alert with an outcome.

    The disposition is the only ground-truth signal the system gets. Without it there is
    no way to compute precision, no way to tell whether a threshold change helped, and
    no way to detect that the model has quietly degraded since the shelves were moved.
    """
    alert = _load_own_alert(session, alert_id, user)

    if alert.status == AlertStatus.RESOLVED.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Alert is already resolved"
        )

    try:
        body.validate_note_requirement()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    alert.status = AlertStatus.RESOLVED.value
    alert.resolved_at = utcnow()
    alert.resolved_by_id = user.id
    alert.disposition = body.disposition
    alert.disposition_note = body.note.strip() or None

    if alert.acknowledged_at is None:
        alert.acknowledged_at = alert.resolved_at
        alert.acknowledged_by_id = user.id

    session.add(alert)

    audit.record(
        session,
        store_id=user.store_id,
        actor_type="user",
        actor_ref=user.username,
        action="alert.resolved",
        target_type="alert",
        target_ref=str(alert.id),
        detail={
            "disposition": body.disposition,
            "had_note": bool(alert.disposition_note),
            "score": round(alert.score, 4),
            "severity": alert.severity,
        },
        source_ip=request.client.host if request.client else None,
    )
    session.commit()
    session.refresh(alert)

    hub.publish(
        user.store_id,
        alert_message(
            kind="alert.resolved",
            payload={
                "id": alert.id,
                "by": user.display_name,
                "disposition": alert.disposition,
            },
        ),
    )
    return _to_out(session, alert)


@router.get("/api/v1/alerts/summary")
def alert_summary(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.ASSISTANT)),
) -> dict:
    """Counts for the dashboard header."""
    alerts = session.execute(
        select(Alert).where(Alert.store_id == user.store_id)
    ).scalars().all()

    open_count = sum(1 for a in alerts if a.status == AlertStatus.OPEN.value)
    ack_count = sum(1 for a in alerts if a.status == AlertStatus.ACKNOWLEDGED.value)
    resolved = [a for a in alerts if a.status == AlertStatus.RESOLVED.value]
    false_positives = sum(
        1 for a in resolved if a.disposition == Disposition.FALSE_POSITIVE.value
    )

    return {
        "open": open_count,
        "acknowledged": ack_count,
        "resolved": len(resolved),
        "total": len(alerts),
        "false_positive_rate": (
            round(false_positives / len(resolved), 3) if resolved else None
        ),
    }


# --------------------------------------------------------------------------------------
# Live feed
# --------------------------------------------------------------------------------------


@router.websocket("/ws/alerts")
async def alert_feed(websocket: WebSocket, session: Session = Depends(get_session)) -> None:
    """Live alert stream for signed-in operational staff.

    Authenticated from the session cookie. The handshake is rejected before ``accept()``
    for anyone unauthenticated, so an unauthorised client never reaches an open socket.
    Auditors are refused here: live operational alerting is not part of an oversight role.
    """
    token = websocket.cookies.get(SESSION_COOKIE)
    claims = decode_session_token(token) if token else None

    if claims is None:
        await websocket.close(code=4401, reason="Authentication required")
        return

    user = session.get(User, claims.user_id)
    if user is None or not user.is_active or user.is_locked:
        await websocket.close(code=4403, reason="Account unavailable")
        return

    if user.role not in {r.value for r in OPERATIONAL_ROLES}:
        await websocket.close(code=4403, reason="Role not permitted on the live feed")
        return

    await websocket.accept()
    subscriber = Subscriber(
        websocket=websocket,
        store_id=user.store_id,
        role=user.role,
        user_ref=user.username,
    )
    await hub.subscribe(subscriber)

    try:
        await websocket.send_json(
            alert_message(kind="hello", payload={"role": user.role, "store_id": user.store_id})
        )
        while True:
            # The client is not permitted to drive any state change over the socket.
            # Inbound frames are read only to detect disconnection and to answer pings;
            # every mutation goes through an authenticated, CSRF-checked HTTP route.
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json(alert_message(kind="pong", payload={}))
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("websocket error for user=%s", user.username)
    finally:
        await hub.unsubscribe(subscriber)
