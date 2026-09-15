"""Append-only, hash-chained audit log.

Threat addressed: a duty manager (or anyone who reaches the database) quietly deleting
the record of an alert they mishandled, or back-dating a disposition after a complaint.

Each entry commits to the previous entry's hash. Removing or editing any row breaks
verification for that row and every row after it. This does not prevent tampering by
someone with write access to the database; it removes the possibility of doing so
*undetectably*, which is the achievable goal when the log shares storage with the data.

For genuine append-only guarantees the chain head should additionally be published to
external, write-once storage on a schedule. That is recorded as future work in
docs/03-threat-model.md (control C-12) and :func:`chain_head` exists to support it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.models import AuditRecord
from core.util import canonical_json, iso, sha256_hex, utcnow

#: ``prev_hash`` of the first entry in a store's chain.
GENESIS_HASH = "0" * 64

#: Reference for the reserved store that owns the system-scope audit chain.
#:
#: Some events must be recorded before any store context exists: a failed sign-in where the
#: username is unknown, an edge event whose signature did not verify, a duress activation
#: from an unrecognised fob serial. Those are precisely the events an attacker would like to
#: go unrecorded, so discarding them is not an option.
#:
#: They cannot be attributed to a real store without guessing, so they go to a dedicated
#: chain. A reserved row keeps the foreign key intact, which matters because referential
#: integrity is switched on specifically to stop orphaned audit rows.
SYSTEM_STORE_REFERENCE = "__system__"
SYSTEM_STORE_NAME = "System (pre-authentication events)"

#: Fields committed to by the entry hash. Adding a field here changes every future
#: hash, so historical entries must be verified against the schema version that wrote
#: them. Kept explicit rather than derived from the model to make that coupling visible.
_HASHED_FIELDS = (
    "seq",
    "store_id",
    "actor_type",
    "actor_ref",
    "action",
    "target_type",
    "target_ref",
    "outcome",
    "detail",
    "source_ip",
    "created_at",
    "prev_hash",
)


def compute_entry_hash(payload: dict) -> str:
    """Hash an audit entry over its canonical JSON representation."""
    subset = {key: payload.get(key) for key in _HASHED_FIELDS}
    return sha256_hex(canonical_json(subset))


def system_store_id(session: Session) -> int:
    """Return the reserved system store id, creating the row if needed.

    Idempotent and safe to call on a hot path: the lookup is a single indexed query, and a
    race between two callers is resolved by the unique constraint on ``reference``.
    """
    from core.models import Store

    store = session.execute(
        select(Store).where(Store.reference == SYSTEM_STORE_REFERENCE)
    ).scalar_one_or_none()

    if store is not None:
        return store.id

    store = Store(name=SYSTEM_STORE_NAME, reference=SYSTEM_STORE_REFERENCE)
    savepoint = session.begin_nested()
    try:
        session.add(store)
        savepoint.commit()
        return store.id
    except IntegrityError:
        savepoint.rollback()
        existing = session.execute(
            select(Store).where(Store.reference == SYSTEM_STORE_REFERENCE)
        ).scalar_one()
        return existing.id


def chain_head(session: Session, store_id: int) -> tuple[int, str]:
    """Return ``(last_seq, last_hash)`` for a store's chain."""
    row = session.execute(
        select(AuditRecord.seq, AuditRecord.entry_hash)
        .where(AuditRecord.store_id == store_id)
        .order_by(AuditRecord.seq.desc())
        .limit(1)
    ).first()
    if row is None:
        return 0, GENESIS_HASH
    return int(row[0]), str(row[1])


def record(
    session: Session,
    *,
    store_id: int,
    actor_type: str,
    actor_ref: str,
    action: str,
    target_type: str | None = None,
    target_ref: str | None = None,
    outcome: str = "success",
    detail: dict | None = None,
    source_ip: str | None = None,
    max_attempts: int = 5,
) -> AuditRecord:
    """Append an entry to a store's audit chain.

    Concurrency is handled optimistically. Two writers can read the same chain head and
    both try to claim the same sequence number; the unique constraint on
    ``(store_id, seq)`` rejects the loser, which then retries against the new head.
    Serialising through a lock would be simpler but would make audit writes a
    throughput ceiling on event ingest.
    """
    detail = detail or {}
    last_error: Exception | None = None

    for _ in range(max_attempts):
        prev_seq, prev_hash = chain_head(session, store_id)
        created_at = utcnow()

        payload = {
            "seq": prev_seq + 1,
            "store_id": store_id,
            "actor_type": actor_type,
            "actor_ref": actor_ref,
            "action": action,
            "target_type": target_type,
            "target_ref": target_ref,
            "outcome": outcome,
            "detail": detail,
            "source_ip": source_ip,
            "created_at": iso(created_at),
            "prev_hash": prev_hash,
        }

        entry = AuditRecord(
            store_id=store_id,
            seq=payload["seq"],
            actor_type=actor_type,
            actor_ref=actor_ref,
            action=action,
            target_type=target_type,
            target_ref=target_ref,
            outcome=outcome,
            detail=detail,
            source_ip=source_ip,
            created_at=created_at,
            prev_hash=prev_hash,
            entry_hash=compute_entry_hash(payload),
        )

        savepoint = session.begin_nested()
        try:
            session.add(entry)
            savepoint.commit()
            return entry
        except IntegrityError as exc:
            savepoint.rollback()
            last_error = exc
            session.expire_all()

    raise RuntimeError(
        f"could not append audit entry after {max_attempts} attempts"
    ) from last_error


# --------------------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------------------


@dataclass
class ChainProblem:
    seq: int
    record_id: int | None
    issue: str

    def as_dict(self) -> dict:
        return {"seq": self.seq, "record_id": self.record_id, "issue": self.issue}


@dataclass
class ChainReport:
    store_id: int
    entries_checked: int = 0
    problems: list[ChainProblem] = field(default_factory=list)
    head_hash: str = GENESIS_HASH

    @property
    def ok(self) -> bool:
        return not self.problems

    def as_dict(self) -> dict:
        return {
            "store_id": self.store_id,
            "ok": self.ok,
            "entries_checked": self.entries_checked,
            "head_hash": self.head_hash,
            "problems": [p.as_dict() for p in self.problems],
        }


def verify_chain(session: Session, store_id: int) -> ChainReport:
    """Recompute the chain and report any break.

    Three distinct failures are detectable and distinguished, because they mean
    different things operationally:

    * ``hash_mismatch`` — the row's contents were edited after it was written.
    * ``broken_link`` — a row's ``prev_hash`` does not match its predecessor, which is
      what a deletion from the middle of the chain looks like.
    * ``sequence_gap`` — sequence numbers skip, indicating removed rows at the tail of
      a transaction or a failed writer.
    """
    report = ChainReport(store_id=store_id)
    expected_prev = GENESIS_HASH
    expected_seq = 1

    rows = session.execute(
        select(AuditRecord)
        .where(AuditRecord.store_id == store_id)
        .order_by(AuditRecord.seq.asc())
    ).scalars()

    for entry in rows:
        report.entries_checked += 1

        if entry.seq != expected_seq:
            report.problems.append(
                ChainProblem(entry.seq, entry.id, f"sequence_gap: expected {expected_seq}")
            )
            expected_seq = entry.seq

        if entry.prev_hash != expected_prev:
            report.problems.append(
                ChainProblem(entry.seq, entry.id, "broken_link: prev_hash does not match")
            )

        recomputed = compute_entry_hash(
            {
                "seq": entry.seq,
                "store_id": entry.store_id,
                "actor_type": entry.actor_type,
                "actor_ref": entry.actor_ref,
                "action": entry.action,
                "target_type": entry.target_type,
                "target_ref": entry.target_ref,
                "outcome": entry.outcome,
                "detail": entry.detail,
                "source_ip": entry.source_ip,
                "created_at": iso(entry.created_at),
                "prev_hash": entry.prev_hash,
            }
        )
        if recomputed != entry.entry_hash:
            report.problems.append(
                ChainProblem(entry.seq, entry.id, "hash_mismatch: contents altered")
            )

        expected_prev = entry.entry_hash
        expected_seq = entry.seq + 1

    report.head_hash = expected_prev
    return report


def purge_expired(session: Session, store_id: int, retention_days: int) -> int:
    """Delete audit entries older than the retention period.

    Note the ordering problem this creates and why it is acceptable: truncating the
    oldest entries necessarily breaks verification of the new earliest entry, whose
    ``prev_hash`` now points at nothing. Rather than pretend otherwise, the truncation
    is itself recorded as an audit entry containing the hash of the last removed row,
    so the chain remains explainable across the cut.

    Retention here is a data-minimisation obligation, not an optional cleanup.
    """
    cutoff = utcnow() - timedelta(days=retention_days)

    doomed = session.execute(
        select(AuditRecord)
        .where(AuditRecord.store_id == store_id, AuditRecord.created_at < cutoff)
        .order_by(AuditRecord.seq.asc())
    ).scalars().all()

    if not doomed:
        return 0

    last_removed = doomed[-1]
    marker = {
        "removed_count": len(doomed),
        "first_seq": doomed[0].seq,
        "last_seq": last_removed.seq,
        "last_removed_hash": last_removed.entry_hash,
        "cutoff": iso(cutoff),
    }

    for entry in doomed:
        session.delete(entry)
    session.flush()

    record(
        session,
        store_id=store_id,
        actor_type="system",
        actor_ref="retention-sweeper",
        action="audit.truncate",
        target_type="audit_chain",
        target_ref=str(store_id),
        detail=marker,
    )
    return len(doomed)


def count_entries(session: Session, store_id: int) -> int:
    return int(
        session.execute(
            select(func.count(AuditRecord.id)).where(AuditRecord.store_id == store_id)
        ).scalar_one()
    )
