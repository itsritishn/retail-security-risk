"""Liveness and readiness endpoints.

``/healthz`` is the only unauthenticated route in the application. It deliberately
reveals nothing beyond liveness and a version string: no store names, no camera counts,
no configuration. An unauthenticated endpoint that enumerates your estate is
reconnaissance for free.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from core import __version__
from core.alerting import hub
from core.db import get_session
from core.schemas import HealthOut
from core.util import iso, utcnow

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthOut)
def healthz() -> HealthOut:
    return HealthOut(status="ok", version=__version__, time=iso(utcnow()) or "")


@router.get("/readyz")
def readyz(response: Response, session: Session = Depends(get_session)) -> dict:
    """Readiness: can we actually reach the database?

    Returns 503 when the dependency is unavailable so an orchestrator stops sending
    traffic instead of letting requests fail deeper in the stack.
    """
    checks: dict[str, str] = {}
    ready = True

    try:
        session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {type(exc).__name__}"
        ready = False

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "ready": ready,
        "checks": checks,
        "alert_hub": hub.stats.as_dict(),
        "time": iso(utcnow()),
    }
