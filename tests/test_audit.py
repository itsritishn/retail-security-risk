"""Audit chain integrity.

These tests exist to prove the specific claim the audit log makes: not that tampering is
impossible, but that it cannot happen *silently*. Each test performs the tamper and then
asserts that verification catches it.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from core import audit
from core.models import AuditRecord


def _append(session: Session, store_id: int, count: int) -> None:
    for index in range(count):
        audit.record(
            session,
            store_id=store_id,
            actor_type="user",
            actor_ref=f"user{index}",
            action="alert.acknowledged",
            target_type="alert",
            target_ref=str(index),
            detail={"index": index},
        )
    session.commit()


def test_chain_starts_at_genesis(session: Session, store):
    seq, head = audit.chain_head(session, store.id)
    assert seq == 0
    assert head == audit.GENESIS_HASH


def test_entries_are_sequential_and_linked(session: Session, store):
    _append(session, store.id, 5)

    rows = session.execute(
        select(AuditRecord)
        .where(AuditRecord.store_id == store.id)
        .order_by(AuditRecord.seq)
    ).scalars().all()

    assert [row.seq for row in rows] == [1, 2, 3, 4, 5]
    assert rows[0].prev_hash == audit.GENESIS_HASH

    for previous, current in zip(rows, rows[1:]):
        assert current.prev_hash == previous.entry_hash


def test_verification_passes_for_an_untouched_chain(session: Session, store):
    _append(session, store.id, 8)

    report = audit.verify_chain(session, store.id)

    assert report.ok is True
    assert report.entries_checked == 8
    assert report.problems == []


def test_editing_an_entry_is_detected(session: Session, store):
    """The scenario: someone rewrites a disposition after a complaint."""
    _append(session, store.id, 5)

    target = session.execute(
        select(AuditRecord).where(AuditRecord.store_id == store.id, AuditRecord.seq == 3)
    ).scalar_one()
    target.action = "alert.resolved"
    target.detail = {"disposition": "false_positive", "tampered": True}
    session.add(target)
    session.commit()

    report = audit.verify_chain(session, store.id)

    assert report.ok is False
    issues = [problem.issue for problem in report.problems]
    assert any("hash_mismatch" in issue for issue in issues)


def test_deleting_an_entry_is_detected(session: Session, store):
    """The scenario: someone removes the record of an alert they mishandled."""
    _append(session, store.id, 6)

    doomed = session.execute(
        select(AuditRecord).where(AuditRecord.store_id == store.id, AuditRecord.seq == 4)
    ).scalar_one()
    session.delete(doomed)
    session.commit()

    report = audit.verify_chain(session, store.id)

    assert report.ok is False
    issues = " ".join(problem.issue for problem in report.problems)
    assert "broken_link" in issues or "sequence_gap" in issues


def test_changing_a_timestamp_is_detected(session: Session, store):
    """Back-dating an entry must break verification, since created_at is committed to."""
    from datetime import timedelta

    from core.util import as_utc

    _append(session, store.id, 3)

    target = session.execute(
        select(AuditRecord).where(AuditRecord.store_id == store.id, AuditRecord.seq == 2)
    ).scalar_one()
    target.created_at = as_utc(target.created_at) - timedelta(hours=6)
    session.add(target)
    session.commit()

    report = audit.verify_chain(session, store.id)

    assert report.ok is False
    assert any("hash_mismatch" in problem.issue for problem in report.problems)


def test_chains_are_isolated_per_store(session: Session, store):
    from core.models import Store

    other = Store(name="Other", reference="TEST-002")
    session.add(other)
    session.commit()

    _append(session, store.id, 3)
    _append(session, other.id, 2)

    first = audit.verify_chain(session, store.id)
    second = audit.verify_chain(session, other.id)

    assert first.ok and second.ok
    assert first.entries_checked == 3
    assert second.entries_checked == 2
    # Independent chains: one store's sequence must not depend on another's.
    assert first.head_hash != second.head_hash


def test_truncation_records_its_own_marker(session: Session, store):
    """Retention necessarily breaks the chain at the cut, so the cut is itself recorded."""
    _append(session, store.id, 4)

    removed = audit.purge_expired(session, store.id, retention_days=0)
    session.commit()

    assert removed == 4

    rows = session.execute(
        select(AuditRecord).where(AuditRecord.store_id == store.id)
    ).scalars().all()

    assert len(rows) == 1
    marker = rows[0]
    assert marker.action == "audit.truncate"
    assert marker.detail["removed_count"] == 4
    # The hash of the last removed entry is retained, so the chain stays explainable
    # across the truncation point.
    assert len(marker.detail["last_removed_hash"]) == 64


def test_purge_is_a_no_op_when_nothing_is_old_enough(session: Session, store):
    _append(session, store.id, 3)
    removed = audit.purge_expired(session, store.id, retention_days=365)
    assert removed == 0
    assert audit.count_entries(session, store.id) == 3


def test_concurrent_appends_do_not_collide(session: Session, store):
    """Two sessions racing for the same sequence number must not both win."""
    from core.db import SessionFactory

    other = SessionFactory()
    try:
        audit.record(
            session,
            store_id=store.id,
            actor_type="system",
            actor_ref="a",
            action="test.one",
        )
        session.commit()

        audit.record(
            other,
            store_id=store.id,
            actor_type="system",
            actor_ref="b",
            action="test.two",
        )
        other.commit()

        report = audit.verify_chain(session, store.id)
        assert report.ok is True
        assert report.entries_checked == 2
    finally:
        other.close()
