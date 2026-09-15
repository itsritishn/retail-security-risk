"""Duress activation routes.

``POST /api/v1/duress/fob`` carries no session cookie and no bearer token. That is
deliberate, not an oversight: the caller is a low-power radio gateway, not a browser.
Authentication is the rolling code itself, which is an HMAC over a monotonically
increasing counter under a per-device secret. See :mod:`core.duress` and
docs/05-duress-device-security.md.

The tradeoff is stated plainly because it will be the first thing a reviewer asks about:
this endpoint is reachable by anything that can route to the service, so the rolling code
is the only thing standing in front of it. It is therefore rate limited per device,
every failure is audited, and the deployment guidance places the service on a segmented
VLAN reachable only from the gateway and the dashboard.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from core import audit
from core.alerting import alert_message, hub
from core.config import Settings, get_settings
from core.db import get_session
from core.duress import build_plan, commit_counter, verify_fob_activation
from core.models import DuressActivation, DuressDevice, DuressKind, Role, User, Zone
from core.schemas import DuressFobIn, DuressManualIn, DuressOut
from core.security import (
    duress_throttle,
    get_current_user,
    require_min_role,
    verify_csrf,
)
from core.util import iso, utcnow

logger = logging.getLogger("sentinelfloor.duress")

router = APIRouter(prefix="/api/v1/duress", tags=["duress"])


def _resolve_zone(session: Session, store_id: int, zone_code: str | None) -> Zone | None:
    if not zone_code:
        return None
    return session.execute(
        select(Zone).where(Zone.store_id == store_id, Zone.code == zone_code)
    ).scalar_one_or_none()


def _to_out(activation: DuressActivation, plan_dict: dict | None = None) -> DuressOut:
    plan_dict = plan_dict or {}
    return DuressOut(
        id=activation.id,
        kind=activation.kind,
        silent=activation.silent,
        public_broadcast=activation.public_broadcast,
        zone=activation.zone.name if activation.zone else None,
        source=activation.source,
        created_at=iso(activation.created_at) or "",
        acknowledged_at=iso(activation.acknowledged_at),
        coded_announcement=plan_dict.get("coded_announcement"),
        staff_guidance=plan_dict.get("staff_guidance", []),
        notify_roles=plan_dict.get("notify_roles", []),
    )


def _dispatch(store_id: int, activation: DuressActivation, plan_dict: dict) -> None:
    """Push a duress activation to every connected device for the store.

    Sent with ``notify_roles`` omitted from the envelope filter for threat activations so
    that everyone signed in receives it. A duress alert that reaches only the duty
    manager, who may be the person in trouble, is not a duress alert.
    """
    payload = {
        "id": activation.id,
        "kind": activation.kind,
        "zone": activation.zone.name if activation.zone else None,
        "silent": activation.silent,
        "public_broadcast": activation.public_broadcast,
        "coded_announcement": plan_dict.get("coded_announcement"),
        "staff_guidance": plan_dict.get("staff_guidance", []),
        "source": activation.source,
        "created_at": iso(activation.created_at),
    }
    hub.publish(store_id, alert_message(kind="duress.activated", payload=payload))


@router.post("/fob", response_model=DuressOut)
def fob_activation(
    body: DuressFobIn,
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DuressOut:
    source_ip = request.client.host if request.client else "unknown"

    if not duress_throttle.check(f"duress:{body.serial}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many activations for this device",
        )

    device = session.execute(
        select(DuressDevice).where(DuressDevice.serial == body.serial)
    ).scalar_one_or_none()

    if device is None:
        audit.record(
            session,
            store_id=audit.system_store_id(session),
            actor_type="device",
            actor_ref=body.serial,
            action="duress.rejected",
            outcome="denied",
            detail={"reason": "unknown_device"},
            source_ip=source_ip,
        )
        session.commit()
        # Uniform failure response: a distinct "unknown device" reply would let an
        # attacker enumerate valid fob serials by brute force.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Activation not accepted"
        )

    verification = verify_fob_activation(
        device,
        counter=body.counter,
        kind=body.kind,
        code=body.code,
        window=settings.duress_counter_window,
    )

    if not verification.ok:
        audit.record(
            session,
            store_id=device.store_id,
            actor_type="device",
            actor_ref=device.serial,
            action="duress.rejected",
            outcome="denied",
            detail={
                "reason": verification.reason,
                "presented_counter": body.counter,
                "stored_counter": device.counter,
            },
            source_ip=source_ip,
        )
        session.commit()
        logger.warning(
            "duress rejected device=%s reason=%s", device.serial, verification.reason
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Activation not accepted"
        )

    commit_counter(device, body.counter)
    session.add(device)

    plan = build_plan(body.kind, settings)
    zone = _resolve_zone(session, device.store_id, body.zone_code)

    activation = DuressActivation(
        store_id=device.store_id,
        device_id=device.id,
        kind=body.kind,
        zone_id=zone.id if zone else None,
        silent=plan.silent,
        public_broadcast=plan.public_broadcast,
        counter_value=body.counter,
        source="fob",
    )
    session.add(activation)
    session.flush()

    audit.record(
        session,
        store_id=device.store_id,
        actor_type="device",
        actor_ref=device.serial,
        action="duress.activated",
        target_type="duress_activation",
        target_ref=str(activation.id),
        detail={
            "kind": body.kind,
            "silent": plan.silent,
            "public_broadcast": plan.public_broadcast,
            "counter": body.counter,
            "zone": zone.code if zone else None,
        },
        source_ip=source_ip,
    )
    session.commit()
    session.refresh(activation)

    _dispatch(device.store_id, activation, plan.as_dict())
    return _to_out(activation, plan.as_dict())


@router.post("/manual", response_model=DuressOut)
def manual_activation(
    body: DuressManualIn,
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    user: User = Depends(get_current_user),
    _: None = Depends(verify_csrf),
) -> DuressOut:
    """Raise duress from the dashboard, for when the fob is out of reach."""
    plan = build_plan(
        body.kind, settings, request_public_broadcast=body.request_public_broadcast
    )
    zone = _resolve_zone(session, user.store_id, body.zone_code)

    activation = DuressActivation(
        store_id=user.store_id,
        raised_by_id=user.id,
        kind=body.kind,
        zone_id=zone.id if zone else None,
        silent=plan.silent,
        public_broadcast=plan.public_broadcast,
        source="dashboard",
        outcome_note=body.note.strip() or None,
    )
    session.add(activation)
    session.flush()

    audit.record(
        session,
        store_id=user.store_id,
        actor_type="user",
        actor_ref=user.username,
        action="duress.activated",
        target_type="duress_activation",
        target_ref=str(activation.id),
        detail={
            "kind": body.kind,
            "silent": plan.silent,
            "public_broadcast": plan.public_broadcast,
            "broadcast_requested": body.request_public_broadcast,
            "broadcast_suppressed_reason": plan.suppressed_broadcast_reason,
            "zone": zone.code if zone else None,
        },
        source_ip=request.client.host if request.client else None,
    )
    session.commit()
    session.refresh(activation)

    _dispatch(user.store_id, activation, plan.as_dict())
    return _to_out(activation, plan.as_dict())


@router.get("/active", response_model=list[DuressOut])
def active_activations(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[DuressOut]:
    rows = session.execute(
        select(DuressActivation)
        .where(
            DuressActivation.store_id == user.store_id,
            DuressActivation.resolved_at.is_(None),
        )
        .order_by(DuressActivation.created_at.desc())
        .limit(20)
    ).scalars().all()

    from core.duress import STAFF_GUIDANCE, CODED_ANNOUNCEMENTS

    return [
        _to_out(
            row,
            {
                "coded_announcement": CODED_ANNOUNCEMENTS.get(row.kind) or None,
                "staff_guidance": STAFF_GUIDANCE.get(row.kind, []),
            },
        )
        for row in rows
    ]


@router.post("/{activation_id}/acknowledge", response_model=DuressOut)
def acknowledge(
    activation_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
    _: None = Depends(verify_csrf),
) -> DuressOut:
    activation = session.get(DuressActivation, activation_id)
    if activation is None or activation.store_id != user.store_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if activation.acknowledged_at is None:
        activation.acknowledged_at = utcnow()
        activation.acknowledged_by_id = user.id
        session.add(activation)

        audit.record(
            session,
            store_id=user.store_id,
            actor_type="user",
            actor_ref=user.username,
            action="duress.acknowledged",
            target_type="duress_activation",
            target_ref=str(activation.id),
            source_ip=request.client.host if request.client else None,
        )
        session.commit()
        session.refresh(activation)

        hub.publish(
            user.store_id,
            alert_message(
                kind="duress.acknowledged",
                payload={"id": activation.id, "by": user.display_name},
            ),
        )

    return _to_out(activation)


@router.post("/{activation_id}/resolve", response_model=DuressOut)
def resolve(
    activation_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
    _: None = Depends(verify_csrf),
) -> DuressOut:
    """Stand down an activation.

    Restricted to duty manager and above. An assistant can raise and acknowledge, but
    should not be the one deciding that an incident is over, least of all while still
    standing in it.
    """
    activation = session.get(DuressActivation, activation_id)
    if activation is None or activation.store_id != user.store_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if activation.resolved_at is None:
        activation.resolved_at = utcnow()
        session.add(activation)

        audit.record(
            session,
            store_id=user.store_id,
            actor_type="user",
            actor_ref=user.username,
            action="duress.resolved",
            target_type="duress_activation",
            target_ref=str(activation.id),
            detail={"kind": activation.kind},
            source_ip=request.client.host if request.client else None,
        )
        session.commit()
        session.refresh(activation)

        hub.publish(
            user.store_id,
            alert_message(
                kind="duress.resolved",
                payload={"id": activation.id, "by": user.display_name},
            ),
        )

    return _to_out(activation)


@router.get("/devices")
def list_devices(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
) -> list[dict]:
    """Fob inventory and health.

    The shared secret is never returned. A flat battery or a fob that has not been heard
    from is a silent failure of a life-safety control, so both are surfaced explicitly.
    """
    devices = session.execute(
        select(DuressDevice).where(DuressDevice.store_id == user.store_id)
    ).scalars().all()

    return [
        {
            "serial": device.serial,
            "label": device.label,
            "enabled": device.enabled,
            "counter": device.counter,
            "battery_percent": device.battery_percent,
            "last_seen_at": iso(device.last_seen_at),
            "needs_attention": (
                not device.enabled
                or device.last_seen_at is None
                or (device.battery_percent is not None and device.battery_percent < 20)
            ),
        }
        for device in devices
    ]


@router.get("/kinds")
def list_kinds() -> list[dict]:
    """Activation types with their guidance, for rendering the duress panel."""
    from core.duress import CODED_ANNOUNCEMENTS, STAFF_GUIDANCE

    labels = {
        DuressKind.THREAT.value: "Threat to a person",
        DuressKind.THEFT_IN_PROGRESS.value: "Theft in progress",
        DuressKind.MEDICAL.value: "Medical emergency",
        DuressKind.TEST.value: "Scheduled test",
    }
    return [
        {
            "value": kind.value,
            "label": labels.get(kind.value, kind.value),
            "coded_announcement": CODED_ANNOUNCEMENTS.get(kind.value) or None,
            "staff_guidance": STAFF_GUIDANCE.get(kind.value, []),
        }
        for kind in DuressKind
    ]
