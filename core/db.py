"""Database engine, session management, and schema lifecycle."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for every SentinelFloor table."""


def _build_engine() -> Engine:
    settings = get_settings()
    connect_args: dict[str, object] = {}

    if settings.database_url.startswith("sqlite"):
        # The alert fan-out and retention sweeper touch the session from worker threads.
        connect_args["check_same_thread"] = False

    return create_engine(
        settings.database_url,
        connect_args=connect_args,
        echo=False,
        future=True,
    )


engine = _build_engine()
SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def _configure_sqlite(dbapi_connection, connection_record) -> None:  # noqa: ANN001
    """Apply SQLite pragmas that matter for correctness and integrity.

    ``foreign_keys`` is OFF by default in SQLite, which silently permits orphaned
    rows. For an audit-bearing system that is unacceptable, so it is forced on for
    every connection. WAL improves concurrent read behaviour while the retention
    sweeper holds a write transaction.
    """
    if not get_settings().database_url.startswith("sqlite"):
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()


def init_db() -> None:
    """Create any missing tables.

    Adequate for this project's scope. A multi-store rollout needs Alembic migrations
    so that schema changes are reviewable artefacts rather than side effects.
    """
    from core import models  # noqa: F401  (registers mappers)

    Base.metadata.create_all(bind=engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session = SessionFactory()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for background jobs, scripts, and tests."""
    session = SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
