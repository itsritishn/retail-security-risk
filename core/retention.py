"""Retention enforcement.

Data minimisation is a legal obligation under UK GDPR Article 5(1)(c) and (e), not a
housekeeping task. Behavioural events are minimised at source (no imagery, no identity),
but a record of where an unidentified person stood and what their hands did is still
personal data in context, so it has a defined and short life.

The sweeper is a background task rather than a cron job so that the retention promise
holds even in a single-container deployment where nobody has set up scheduling. It is
idempotent and safe to run concurrently with ingest.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from core import audit
from core.config import get_settings
from core.db import SessionFactory
from core.models import Alert, Event, Store
from core.util import utcnow

logger = logging.getLogger("sentinelfloor.retention")

#: How often the sweeper wakes. Frequent enough that the retention window is meaningful,
#: infrequent enough that it is not a load source.
SWEEP_INTERVAL_SECONDS = 900


def purge_expired_events(session: Session, store_id: int) -> int:
    """Delete events past ``expires_at`` for one store.

    Events still referenced by an unresolved alert are retained until the alert is closed.
    Deleting the evidence behind a prompt a member of staff is currently looking at would
    leave them with a headline and no rationale, and would break the foreign key besides.
    """
    now = utcnow()

    referenced = select(Alert.event_id).where(
        Alert.store_id == store_id, Alert.resolved_at.is_(None)
    )

    doomed = session.execute(
        select(Event.id).where(
            Event.store_id == store_id,
            Event.expires_at < now,
            Event.id.not_in(referenced),
        )
    ).scalars().all()

    if not doomed:
        return 0

    # Alerts are removed alongside their event: the alert is only meaningful with the
    # rationale attached, and keeping a dangling alert would defeat the retention window.
    session.execute(delete(Alert).where(Alert.event_id.in_(doomed)))
    session.execute(delete(Event).where(Event.id.in_(doomed)))
    session.flush()

    logger.info("retention purged %s events for store=%s", len(doomed), store_id)
    return len(doomed)


def run_sweep_once() -> dict[int, int]:
    """Purge expired data for every store. Returns per-store counts."""
    settings = get_settings()
    results: dict[int, int] = {}

    session: Session = SessionFactory()
    try:
        store_ids = session.execute(select(Store.id)).scalars().all()

        for store_id in store_ids:
            removed = purge_expired_events(session, store_id)
            audit_removed = audit.purge_expired(
                session, store_id, settings.audit_retention_days
            )
            results[store_id] = removed

            if removed or audit_removed:
                audit.record(
                    session,
                    store_id=store_id,
                    actor_type="system",
                    actor_ref="retention-sweeper",
                    action="retention.sweep",
                    detail={
                        "events_removed": removed,
                        "audit_entries_removed": audit_removed,
                        "retention_hours": settings.event_retention_hours,
                    },
                )

        session.commit()
    except Exception:
        session.rollback()
        logger.exception("retention sweep failed")
        raise
    finally:
        session.close()

    return results


async def retention_loop(interval_seconds: int = SWEEP_INTERVAL_SECONDS) -> None:
    """Background retention task.

    Wrapped so that a transient database error does not kill the loop permanently. A
    retention sweeper that silently stops is a compliance failure that nobody notices
    until someone asks how long the data is kept.
    """
    while True:
        try:
            await asyncio.to_thread(run_sweep_once)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("retention sweep raised, continuing")
        await asyncio.sleep(interval_seconds)
