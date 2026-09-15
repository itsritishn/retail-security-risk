"""Analytics endpoints.

Access is restricted to duty manager and above, plus auditors. An analytics view exposes
aggregate patterns of customer movement, and even without identity that is not something
every account needs to see.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from analytics import metrics, shrink
from core.db import get_session
from core.models import Role, User
from core.security import require_min_role, require_roles

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

OVERSIGHT = (Role.DUTY_MANAGER, Role.ADMIN, Role.AUDITOR)


@router.get("/detection-quality")
def detection_quality(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(*OVERSIGHT)),
    window_days: int = Query(default=14, ge=1, le=180),
) -> dict:
    return metrics.detection_quality(
        session, user.store_id, window_days=window_days
    ).as_dict()


@router.get("/threshold-sweep")
def threshold_sweep(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    window_days: int = Query(default=30, ge=1, le=365),
) -> dict:
    return {
        "window_days": window_days,
        "rows": metrics.threshold_sweep(session, user.store_id, window_days=window_days),
        "caveat": (
            "Shows the effect of raising the threshold only. Events below the current "
            "threshold were never shown to staff and so carry no label, meaning the "
            "effect of lowering it cannot be estimated retrospectively."
        ),
    }


@router.get("/fairness")
def fairness(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(*OVERSIGHT)),
    window_days: int = Query(default=14, ge=1, le=180),
) -> dict:
    return metrics.alert_rate_dispersion(session, user.store_id, window_days=window_days)


@router.get("/review-sample")
def review_sample(
    session: Session = Depends(get_session),
    user: User = Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    size: int = Query(default=20, ge=1, le=100),
    window_days: int = Query(default=14, ge=1, le=180),
) -> dict:
    return {
        "sample": metrics.review_sample(
            session, user.store_id, size=size, window_days=window_days
        ),
        "instructions": (
            "Review each prompt against the recorded rationale without reference to the "
            "outcome, then compare your judgement with the recorded disposition. "
            "Disagreement indicates either an unclear rationale or an unreliable label."
        ),
    }


@router.get("/hotspots")
def hotspots(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
    days: int = Query(default=28, ge=1, le=180),
    top_n: int = Query(default=10, ge=1, le=50),
) -> dict:
    return {
        "days": days,
        "hotspots": shrink.hotspots(session, user.store_id, days=days, top_n=top_n),
    }


@router.get("/zone-hour-matrix")
def zone_hour_matrix(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
    days: int = Query(default=28, ge=1, le=180),
) -> dict:
    return shrink.zone_hour_matrix(session, user.store_id, days=days)


@router.get("/staffing")
def staffing(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
    days: int = Query(default=28, ge=1, le=180),
) -> dict:
    return {
        "days": days,
        "recommendations": shrink.staffing_recommendation(
            session, user.store_id, days=days
        ),
    }


@router.get("/response-coverage")
def response_coverage(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
    days: int = Query(default=28, ge=1, le=180),
) -> dict:
    return shrink.response_coverage(session, user.store_id, days=days)


@router.get("/volume-trend")
def volume_trend(
    session: Session = Depends(get_session),
    user: User = Depends(require_min_role(Role.DUTY_MANAGER)),
    days: int = Query(default=14, ge=1, le=180),
) -> dict:
    return shrink.event_volume_trend(session, user.store_id, days=days)
