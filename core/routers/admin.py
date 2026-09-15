"""Administration, oversight, and integrity verification.

Note the split between ``require_min_role(Role.ADMIN)`` and
``require_roles(Role.ADMIN, Role.AUDITOR)``. The auditor can *read* the audit chain and
verify its integrity but cannot change policy, rotate keys, or run retention. An oversight
role that can also alter the thing it oversees provides no assurance to anyone.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from core import audit
from core.config import Settings, get_settings
from core.db import get_session
from core.models import AuditRecord, Camera, Event, Role, User
from core.schemas import CameraHealthOut, ChainReportOut
from core.security import require_min_role, require_roles, verify_csrf
from core.util import iso, utcnow

logger = logging.getLogger("sentinelfloor.admin")

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/cameras", response_model=list[CameraHealthOut])
def camera_health(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
) -> list[CameraHealthOut]:
    """Camera liveness.

    A camera that has gone quiet is treated as a finding, not as missing data. From the
    service's point of view a cut cable, a pulled edge box, and a crashed process are
    indistinguishable, and all three mean an aisle is currently uncovered.
    """
    cameras = session.execute(
        select(Camera).where(Camera.store_id == user.store_id).order_by(Camera.code)
    ).scalars().all()

    return [
        CameraHealthOut(
            code=camera.code,
            name=camera.name,
            zone=camera.zone.name if camera.zone else None,
            enabled=camera.enabled,
            stale=camera.is_stale,
            last_seen_at=iso(camera.last_seen_at),
        )
        for camera in cameras
    ]


@router.get("/audit/verify", response_model=ChainReportOut)
def verify_audit_chain(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
) -> ChainReportOut:
    """Recompute the audit hash chain and report any break."""
    report = audit.verify_chain(session, user.store_id)

    if not report.ok:
        logger.error(
            "audit chain verification failed store=%s problems=%s",
            user.store_id,
            report.problems,
        )

    return ChainReportOut(**report.as_dict())


@router.get("/audit")
def list_audit(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None, max_length=64),
) -> list[dict]:
    statement = select(AuditRecord).where(AuditRecord.store_id == user.store_id)
    if action:
        statement = statement.where(AuditRecord.action == action)

    rows = session.execute(
        statement.order_by(AuditRecord.seq.desc()).limit(limit)
    ).scalars().all()

    return [
        {
            "seq": row.seq,
            "created_at": iso(row.created_at),
            "actor_type": row.actor_type,
            "actor_ref": row.actor_ref,
            "action": row.action,
            "target_type": row.target_type,
            "target_ref": row.target_ref,
            "outcome": row.outcome,
            "detail": row.detail,
            "source_ip": row.source_ip,
            "entry_hash": row.entry_hash[:16] + "...",
        }
        for row in rows
    ]


@router.get("/policy")
def current_policy(
    settings: Settings = Depends(get_settings),
    user: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
) -> dict:
    """Effective detection policy.

    Exposed so that an auditor can see the thresholds in force without database access,
    and so that a change of behaviour can be correlated with a change of configuration.
    """
    from core.policy import (
        EVENT_TYPE_WEIGHTS,
        PROHIBITED_FEATURE_KEYS,
        ZONE_ALERT_BUDGET,
        ZONE_BUDGET_WINDOW_MINUTES,
    )

    return {
        "alert_threshold": settings.alert_threshold,
        "escalate_threshold": settings.escalate_threshold,
        "alert_cooldown_seconds": settings.alert_cooldown_seconds,
        "event_retention_hours": settings.event_retention_hours,
        "audit_retention_days": settings.audit_retention_days,
        "zone_alert_budget": ZONE_ALERT_BUDGET,
        "zone_budget_window_minutes": ZONE_BUDGET_WINDOW_MINUTES,
        "event_type_weights": EVENT_TYPE_WEIGHTS,
        "duress": {
            "silent_first": settings.duress_silent_first,
            "public_broadcast_enabled": settings.duress_allow_public_broadcast,
            "counter_window": settings.duress_counter_window,
        },
        "prohibited_feature_keys": sorted(PROHIBITED_FEATURE_KEYS),
        "biometric_processing": "none",
        "facial_recognition": "not implemented and out of scope",
        "automated_decision_making": "none, all alerts require human assessment",
    }


@router.post("/retention/run", status_code=status.HTTP_200_OK)
def run_retention(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    user: User = Depends(require_min_role(Role.ADMIN)),
    _: None = Depends(verify_csrf),
) -> dict:
    """Purge expired behavioural events on demand.

    Retention normally runs on a timer. This route exists so it can be demonstrated and
    so a data subject request can be actioned promptly rather than at the next sweep.
    """
    from core.retention import purge_expired_events

    events_removed = purge_expired_events(session, user.store_id)
    audit_removed = audit.purge_expired(
        session, user.store_id, settings.audit_retention_days
    )

    audit.record(
        session,
        store_id=user.store_id,
        actor_type="user",
        actor_ref=user.username,
        action="retention.manual_run",
        detail={"events_removed": events_removed, "audit_removed": audit_removed},
        source_ip=request.client.host if request.client else None,
    )
    session.commit()

    return {
        "events_removed": events_removed,
        "audit_entries_removed": audit_removed,
        "ran_at": iso(utcnow()),
    }


@router.get("/estate")
def estate_summary(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
) -> dict:
    """Counts for the admin panel."""
    cameras = session.execute(
        select(Camera).where(Camera.store_id == user.store_id)
    ).scalars().all()
    event_count = len(
        session.execute(
            select(Event.id).where(Event.store_id == user.store_id)
        ).scalars().all()
    )

    return {
        "store": user.store.name if user.store else "unknown",
        "cameras_total": len(cameras),
        "cameras_stale": sum(1 for c in cameras if c.is_stale),
        "cameras_disabled": sum(1 for c in cameras if not c.enabled),
        "events_retained": event_count,
        "audit_entries": audit.count_entries(session, user.store_id),
    }
