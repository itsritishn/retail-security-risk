"""Sign-in and sign-out.

Cookie choices, and why:

* ``HttpOnly`` on the session cookie so injected script cannot read it.
* ``SameSite=Strict`` because the dashboard is never legitimately reached from a
  third-party context, and Strict removes most of the CSRF surface before the
  double-submit token is even consulted.
* ``Secure`` whenever the service is not in debug, so the cookie never crosses plaintext.
* A short lifetime, because these are shared terminals in a stock room.

The CSRF cookie is intentionally *not* ``HttpOnly``: the browser script has to read it to
echo it back in a header. It is not a secret in the same sense as the session token, and
it is derived from the session identifier so it cannot be transplanted onto another
session.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from core import audit
from core.config import get_settings
from core.db import get_session
from core.models import User
from core.schemas import UserOut
from core.security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    authenticate,
    get_current_user,
    issue_session_token,
    login_throttle,
)
from core.templating import templates

router = APIRouter(tags=["auth"])

#: Shown for every authentication failure regardless of cause. Distinguishing "no such
#: user" from "wrong password" hands an attacker a free account-enumeration oracle.
GENERIC_LOGIN_ERROR = "Those details were not recognised. Please try again."


def _client_ip(request: Request) -> str:
    """Best-effort client address.

    ``X-Forwarded-For`` is honoured only because this service is expected to sit behind
    a reverse proxy that sets it. Treated as untrusted for anything but logging and
    throttling, never for authorisation, since a client can forge it when the proxy is
    misconfigured.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def _set_session_cookies(response: Response, session_token: str, csrf_token: str) -> None:
    settings = get_settings()
    max_age = settings.session_ttl_minutes * 60
    secure = not settings.debug

    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=max_age,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,
        samesite="strict",
        secure=secure,
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
) -> Response:
    source = _client_ip(request)

    if not login_throttle.check(f"login:{source}"):
        # Audited under a synthetic store id of 0 because we have no authenticated store
        # context yet, and dropping the record entirely would hide password spraying.
        audit.record(
            session,
            store_id=audit.system_store_id(session),
            actor_type="system",
            actor_ref=source,
            action="auth.throttled",
            outcome="denied",
            detail={"username_attempted": username[:64]},
            source_ip=source,
        )
        session.commit()
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Too many attempts. Please wait a minute and try again."},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    result = authenticate(session, username, password)

    if not result.ok:
        # Recorded on the system chain: for an unknown username there is no store to
        # attribute it to, and a failed sign-in is exactly what must not go unrecorded.
        audit.record(
            session,
            store_id=audit.system_store_id(session),
            actor_type="user",
            actor_ref=username.strip().lower()[:64],
            action="auth.login",
            outcome="failure",
            detail={"reason": result.reason},
            source_ip=source,
        )
        session.commit()
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": GENERIC_LOGIN_ERROR},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user = result.user
    assert user is not None
    token, csrf_token = issue_session_token(user)

    audit.record(
        session,
        store_id=user.store_id,
        actor_type="user",
        actor_ref=user.username,
        action="auth.login",
        outcome="success",
        detail={"role": user.role},
        source_ip=source,
    )
    session.commit()
    login_throttle.reset(f"login:{source}")

    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookies(response, token, csrf_token)
    return response


@router.post("/logout")
def logout(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user),
) -> Response:
    audit.record(
        session,
        store_id=user.store_id,
        actor_type="user",
        actor_ref=user.username,
        action="auth.logout",
        source_ip=_client_ip(request),
    )
    session.commit()

    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    _clear_session_cookies(response)
    return response


@router.get("/api/v1/me", response_model=UserOut)
def whoami(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        store=user.store.name if user.store else "unknown",
    )


@router.get("/api/v1/csrf")
def csrf_token(request: Request, user: User = Depends(get_current_user)) -> dict:
    """Return the CSRF token bound to the caller's session.

    Present so a client that lost its cookie copy can recover without re-authenticating.
    Requires a valid session, so it hands nothing to an unauthenticated caller.
    """
    token = getattr(request.state, "csrf_token", None)
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active session")
    return {"csrf_token": token}
