"""Test configuration.

Environment variables are set *before* any project import. ``core.db`` builds its engine at
import time from the settings object, and ``get_settings`` is cached, so configuring after
the first import would silently run the tests against the developer's real database.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TEST_DIR = Path(tempfile.mkdtemp(prefix="sentinelfloor-tests-"))

os.environ["SENTINEL_ENV"] = "test"
os.environ["SENTINEL_DEBUG"] = "true"
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{_TEST_DIR / 'test.db'}"
os.environ["SENTINEL_SECRET_KEY"] = "test-only-secret-not-used-anywhere-real-0123456789"
os.environ["SENTINEL_ALERT_THRESHOLD"] = "0.72"
os.environ["SENTINEL_ESCALATE_THRESHOLD"] = "0.88"
os.environ["SENTINEL_ALERT_COOLDOWN_SECONDS"] = "90"
os.environ["SENTINEL_EVENT_RETENTION_HOURS"] = "72"
os.environ["SENTINEL_DURESS_ALLOW_PUBLIC_BROADCAST"] = "false"

import pytest  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from core.config import get_settings  # noqa: E402
from core.db import Base, SessionFactory, engine  # noqa: E402
from core.models import (  # noqa: E402
    Camera,
    DuressDevice,
    Role,
    Store,
    User,
    Zone,
)
from core.security import hash_password  # noqa: E402

#: Cheap KDF cost for tests. Production cost is 600,000 iterations; using that here would
#: add minutes to the suite for no additional assurance, since the parameterisation itself
#: is covered by a dedicated test.
TEST_KDF_ITERATIONS = 1_000

TEST_PASSWORD = "correct-horse-battery-staple-42"


@pytest.fixture(autouse=True)
def _fresh_schema():
    """Rebuild the schema around every test, so tests cannot leak state into each other."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def settings():
    return get_settings()


@pytest.fixture
def session() -> Session:
    db = SessionFactory()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


@pytest.fixture
def store(session: Session) -> Store:
    record = Store(name="Test Store", reference="TEST-001", timezone="Europe/London")
    session.add(record)
    session.commit()
    return record


@pytest.fixture
def zones(session: Session, store: Store) -> dict[str, Zone]:
    created = {
        "confectionery": Zone(
            store_id=store.id,
            code="confectionery",
            name="Confectionery",
            risk_weight=1.5,
            is_high_value=True,
        ),
        "ambient": Zone(
            store_id=store.id,
            code="ambient",
            name="Ambient grocery",
            risk_weight=0.9,
            is_high_value=False,
        ),
        "neutral": Zone(
            store_id=store.id,
            code="neutral",
            name="Neutral zone",
            risk_weight=1.0,
            is_high_value=False,
        ),
    }
    for zone in created.values():
        session.add(zone)
    session.commit()
    return created


@pytest.fixture
def camera(session: Session, store: Store, zones: dict[str, Zone]) -> Camera:
    record = Camera(
        store_id=store.id,
        zone_id=zones["confectionery"].id,
        code="cam-test-01",
        name="Test camera",
        ingest_key="a" * 64,
    )
    session.add(record)
    session.commit()
    return record


@pytest.fixture
def users(session: Session, store: Store) -> dict[str, User]:
    created: dict[str, User] = {}
    for username, role in (
        ("assistant", Role.ASSISTANT.value),
        ("manager", Role.DUTY_MANAGER.value),
        ("admin", Role.ADMIN.value),
        ("auditor", Role.AUDITOR.value),
    ):
        user = User(
            store_id=store.id,
            username=username,
            display_name=username.title(),
            role=role,
            password_hash=hash_password(TEST_PASSWORD, iterations=TEST_KDF_ITERATIONS),
        )
        session.add(user)
        created[role] = user
    session.commit()
    return created


@pytest.fixture
def duress_device(session: Session, store: Store) -> DuressDevice:
    record = DuressDevice(
        store_id=store.id,
        serial="FOB-TEST-01",
        label="Test fob",
        shared_secret="b" * 64,
        counter=0,
        battery_percent=100,
    )
    session.add(record)
    session.commit()
    return record


@pytest.fixture
def client(store: Store, zones, camera, users, duress_device):
    """Test client with the estate already seeded.

    The fixture depends on the estate fixtures so that the schema is populated before the
    application lifespan runs.
    """
    from fastapi.testclient import TestClient

    from core.main import app

    with TestClient(app) as test_client:
        yield test_client


def login(test_client, username: str = "assistant") -> str:
    """Authenticate the test client and return its CSRF token."""
    response = test_client.post(
        "/login",
        data={"username": username, "password": TEST_PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text

    csrf = test_client.get("/api/v1/csrf")
    assert csrf.status_code == 200, csrf.text
    return csrf.json()["csrf_token"]
