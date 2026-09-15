"""Application entry point.

Run with::

    uvicorn core.main:app --host 127.0.0.1 --port 8000

The application binds loopback by default and every route except ``/healthz`` requires
authentication. Before exposing it beyond a single machine, read docs/03-threat-model.md:
in particular, this service expects to sit behind a reverse proxy that terminates TLS,
and to be reachable only from the camera VLAN and the store's staff network.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from core import __version__
from core.alerting import hub
from core.config import get_settings
from core.db import init_db
from core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from core.retention import retention_loop
from core.routers import admin, alerts, analytics, auth, duress, events, health, pages
from core.security import NotAuthenticated
from core.templating import STATIC_DIR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
)
logger = logging.getLogger("sentinelfloor")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()

    # Fails closed on unsafe configuration. A security tool that starts anyway when
    # misconfigured provides false assurance, which is worse than no assurance.
    settings.assert_safe_to_serve()

    init_db()
    await hub.start()

    retention_task = asyncio.create_task(retention_loop(), name="retention-loop")

    if settings.secret_is_placeholder:
        logger.warning(
            "Running with the placeholder SENTINEL_SECRET_KEY. Acceptable for local "
            "development only. Sessions are forgeable by anyone who has read the repo."
        )

    logger.info(
        "SentinelFloor %s ready env=%s alert_threshold=%.2f retention=%sh "
        "duress_public_broadcast=%s",
        __version__,
        settings.env,
        settings.alert_threshold,
        settings.event_retention_hours,
        settings.duress_allow_public_broadcast,
    )

    try:
        yield
    finally:
        retention_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await retention_task
        await hub.stop()
        logger.info("SentinelFloor stopped")


app = FastAPI(
    title="SentinelFloor",
    version=__version__,
    description=(
        "Privacy-first, behaviour-based loss prevention and staff duress platform for "
        "small-format retail. Pose data only: no facial recognition, no identity, no "
        "watchlist, no automated decisions."
    ),
    lifespan=lifespan,
    # Interactive docs are useful in development and are an information disclosure in
    # production, so they follow the debug flag.
    docs_url="/docs" if get_settings().debug else None,
    redoc_url=None,
    openapi_url="/openapi.json" if get_settings().debug else None,
)

app.add_middleware(SecurityHeadersMiddleware, enable_hsts=get_settings().is_production)
app.add_middleware(RequestContextMiddleware)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(pages.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(duress.router)
app.include_router(admin.router)
app.include_router(analytics.router)


@app.exception_handler(NotAuthenticated)
async def not_authenticated_handler(
    request: Request, exc: NotAuthenticated
) -> JSONResponse | RedirectResponse:
    """Redirect page requests to the login screen, answer API clients with JSON.

    Dispatch is on the request path rather than the ``Accept`` header. Header sniffing is
    tempting but unreliable: plenty of clients send ``*/*``, and the resulting behaviour
    changes depending on who is calling, which is miserable to debug. Paths under ``/api/``
    and ``/ws/`` are machine endpoints and get a clean 401; everything else is a page and
    gets a redirect.
    """
    path = request.url.path
    is_machine_endpoint = path.startswith("/api/") or path.startswith("/ws/")

    if not is_machine_endpoint:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": exc.detail}
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return validation errors without echoing the submitted values.

    Pydantic's default handler includes the offending input, which for this service could
    mean a password or a duress rolling code appearing in a client-visible error body and
    in any log that captures responses.
    """
    sanitised = [
        {
            "location": list(error.get("loc", ())),
            "message": error.get("msg", "invalid value"),
            "type": error.get("type", "value_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": sanitised},
    )
