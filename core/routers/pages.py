"""Server-rendered pages."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from core.config import Settings, get_settings
from core.models import Role, User
from core.security import get_current_user
from core.templating import templates

router = APIRouter(tags=["pages"])


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    """Shop-floor dashboard.

    The CSRF token is rendered into a meta tag so the client script can echo it back on
    state-changing requests. It is per-session, not per-form, which is sufficient for a
    single-page interface and avoids a token-fetch round trip before every action.
    """
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "csrf_token": getattr(request.state, "csrf_token", ""),
            "can_resolve_duress": user.role
            in {Role.DUTY_MANAGER.value, Role.ADMIN.value},
            "can_view_analytics": user.role
            in {Role.DUTY_MANAGER.value, Role.ADMIN.value, Role.AUDITOR.value},
            "is_operational": user.role
            in {Role.ASSISTANT.value, Role.DUTY_MANAGER.value, Role.ADMIN.value},
            "public_broadcast_enabled": settings.duress_allow_public_broadcast,
            "alert_threshold": settings.alert_threshold,
        },
    )
