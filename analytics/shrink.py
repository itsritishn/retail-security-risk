"""Shrink pattern analysis and staffing guidance.

This is the part of the system that pays for itself even when the detection model is
mediocre. Knowing that concealment signals cluster in the confectionery aisle between
15:30 and 17:00 on weekdays lets a store put a person there, and a visible member of
staff in the right aisle is a stronger deterrent than any camera.

Deliberately built on stdlib only. Pulling in pandas for aggregations over a few thousand
rows adds install weight, a supply-chain surface, and nothing else.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import Alert, Disposition, Event, Store, Zone
from core.util import as_utc, utcnow

#: Confirmed outcomes, used to weight hotspots toward signals that proved real.
CONFIRMED = frozenset(
    {
        Disposition.TRUE_POSITIVE_RECOVERED.value,
        Disposition.TRUE_POSITIVE_LOST.value,
    }
)


def _local_tz(session: Session, store_id: int) -> ZoneInfo:
    """Resolve the store's local timezone.

    Aggregating by hour in UTC would smear the pattern across a one-hour boundary for
    half the year, which is exactly the kind of quiet error that makes an analysis
    plausible and wrong.
    """
    store = session.get(Store, store_id)
    name = store.timezone if store and store.timezone else "Europe/London"
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001
        return ZoneInfo("UTC")


@dataclass
class Hotspot:
    zone: str
    hour: int
    weekday: str
    alerts: int
    confirmed: int
    confirmation_rate: float | None

    def as_dict(self) -> dict:
        return {
            "zone": self.zone,
            "hour": self.hour,
            "weekday": self.weekday,
            "alerts": self.alerts,
            "confirmed": self.confirmed,
            "confirmation_rate": self.confirmation_rate,
        }


WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def zone_hour_matrix(session: Session, store_id: int, *, days: int = 28) -> dict:
    """Alert counts by zone and local hour of day.

    Returns a dense matrix so a heatmap can render zero cells honestly rather than
    leaving gaps that read as missing data.
    """
    tz = _local_tz(session, store_id)
    cutoff = utcnow() - timedelta(days=days)

    alerts = session.execute(
        select(Alert).where(Alert.store_id == store_id, Alert.created_at >= cutoff)
    ).scalars().all()

    zone_names = [
        zone.name
        for zone in session.execute(
            select(Zone).where(Zone.store_id == store_id).order_by(Zone.name)
        ).scalars().all()
    ]
    if "unmapped" not in zone_names:
        zone_names.append("unmapped")

    matrix: dict[str, list[int]] = {name: [0] * 24 for name in zone_names}

    for alert in alerts:
        name = alert.zone.name if alert.zone else "unmapped"
        matrix.setdefault(name, [0] * 24)
        local_hour = as_utc(alert.created_at).astimezone(tz).hour
        matrix[name][local_hour] += 1

    return {
        "window_days": days,
        "timezone": str(tz),
        "hours": list(range(24)),
        "matrix": matrix,
        "total": len(alerts),
    }


def hotspots(
    session: Session, store_id: int, *, days: int = 28, top_n: int = 10
) -> list[dict]:
    """Rank zone/hour/weekday cells by confirmed loss signal.

    Ranked by confirmed outcomes first and raw volume second. A cell with twenty prompts
    and no confirmations is a tuning problem, not a hotspot, and treating it as one sends
    a member of staff to stand in the wrong aisle.
    """
    tz = _local_tz(session, store_id)
    cutoff = utcnow() - timedelta(days=days)

    alerts = session.execute(
        select(Alert).where(Alert.store_id == store_id, Alert.created_at >= cutoff)
    ).scalars().all()

    cells: dict[tuple[str, int, int], Counter] = defaultdict(Counter)

    for alert in alerts:
        local = as_utc(alert.created_at).astimezone(tz)
        key = (
            alert.zone.name if alert.zone else "unmapped",
            local.hour,
            local.weekday(),
        )
        cells[key]["alerts"] += 1
        if alert.disposition in CONFIRMED:
            cells[key]["confirmed"] += 1

    results = [
        Hotspot(
            zone=zone,
            hour=hour,
            weekday=WEEKDAYS[weekday],
            alerts=counts["alerts"],
            confirmed=counts["confirmed"],
            confirmation_rate=(
                round(counts["confirmed"] / counts["alerts"], 3)
                if counts["alerts"]
                else None
            ),
        )
        for (zone, hour, weekday), counts in cells.items()
    ]

    results.sort(key=lambda h: (-h.confirmed, -h.alerts))
    return [hotspot.as_dict() for hotspot in results[:top_n]]


def staffing_recommendation(
    session: Session, store_id: int, *, days: int = 28, slots: int = 5
) -> list[dict]:
    """Suggest where to place a floor-walking assistant.

    Practical output: a small number of zone and time-window pairs, with the evidence
    behind each. This is the recommendation a manager can actually act on when writing
    next week's rota, and it is generated from the store's own history rather than a
    vendor's assumptions about an average supermarket.
    """
    tz = _local_tz(session, store_id)
    cutoff = utcnow() - timedelta(days=days)

    alerts = session.execute(
        select(Alert).where(Alert.store_id == store_id, Alert.created_at >= cutoff)
    ).scalars().all()

    if not alerts:
        return []

    weighted: dict[tuple[str, int], float] = defaultdict(float)
    volume: dict[tuple[str, int], int] = defaultdict(int)

    for alert in alerts:
        local = as_utc(alert.created_at).astimezone(tz)
        key = (alert.zone.name if alert.zone else "unmapped", local.hour)
        volume[key] += 1
        # A confirmed loss weighs far more than an unlabelled prompt; a confirmed false
        # positive actively argues against sending someone there.
        if alert.disposition in CONFIRMED:
            weighted[key] += 3.0
        elif alert.disposition == Disposition.FALSE_POSITIVE.value:
            weighted[key] -= 1.0
        else:
            weighted[key] += 0.5

    ranked = sorted(weighted.items(), key=lambda item: -item[1])

    recommendations: list[dict] = []
    for (zone, hour), score in ranked[:slots]:
        if score <= 0:
            continue
        recommendations.append(
            {
                "zone": zone,
                "window_local": f"{hour:02d}:00-{(hour + 1) % 24:02d}:00",
                "priority_score": round(score, 2),
                "alert_volume": volume[(zone, hour)],
                "rationale": (
                    f"{volume[(zone, hour)]} prompts in this slot over {days} days, "
                    f"weighted by confirmed outcomes."
                ),
                "action": (
                    "Position a visible assistant here. Presence deters; the camera only "
                    "records."
                ),
            }
        )

    return recommendations


def response_coverage(session: Session, store_id: int, *, days: int = 28) -> dict:
    """How well prompts are actually being answered.

    Coverage matters more than model accuracy once the model is adequate. A perfect
    detector whose prompts go unanswered for four minutes prevents nothing, and this is
    the metric that tells a manager whether the tool is being used or ignored.
    """
    cutoff = utcnow() - timedelta(days=days)

    alerts = session.execute(
        select(Alert).where(Alert.store_id == store_id, Alert.created_at >= cutoff)
    ).scalars().all()

    if not alerts:
        return {"window_days": days, "alerts": 0}

    latencies = [
        a.time_to_acknowledge_seconds
        for a in alerts
        if a.time_to_acknowledge_seconds is not None
    ]
    unacknowledged = sum(1 for a in alerts if a.acknowledged_at is None)

    slow_threshold = 120.0
    slow = sum(1 for value in latencies if value > slow_threshold)

    return {
        "window_days": days,
        "alerts": len(alerts),
        "acknowledged": len(latencies),
        "never_acknowledged": unacknowledged,
        "acknowledgement_rate": round(len(latencies) / len(alerts), 3),
        "median_response_seconds": (
            round(statistics.median(latencies), 1) if latencies else None
        ),
        "p90_response_seconds": (
            round(sorted(latencies)[int(len(latencies) * 0.9)], 1)
            if len(latencies) >= 10
            else None
        ),
        "slower_than_2_minutes": slow,
        "interpretation": (
            "A prompt answered after two minutes has usually lost its value: the person "
            "has left the aisle. Sustained slow response means the staffing model, not "
            "the detector, is the constraint."
        ),
    }


def event_volume_trend(session: Session, store_id: int, *, days: int = 14) -> dict:
    """Daily event and alert volume, for spotting drift.

    A sudden change in event volume with no change in trade usually means something
    physical moved: a camera was nudged, a display was relocated, lighting changed. Model
    drift in a retail store is most often a facilities problem.
    """
    tz = _local_tz(session, store_id)
    cutoff = utcnow() - timedelta(days=days)

    events = session.execute(
        select(Event.occurred_at).where(
            Event.store_id == store_id, Event.occurred_at >= cutoff
        )
    ).scalars().all()

    alerts = session.execute(
        select(Alert.created_at).where(
            Alert.store_id == store_id, Alert.created_at >= cutoff
        )
    ).scalars().all()

    event_days: Counter = Counter()
    alert_days: Counter = Counter()

    for value in events:
        event_days[as_utc(value).astimezone(tz).date().isoformat()] += 1
    for value in alerts:
        alert_days[as_utc(value).astimezone(tz).date().isoformat()] += 1

    all_days = sorted(set(event_days) | set(alert_days))

    return {
        "window_days": days,
        "timezone": str(tz),
        "series": [
            {
                "date": day,
                "events": event_days.get(day, 0),
                "alerts": alert_days.get(day, 0),
                "alert_ratio": (
                    round(alert_days.get(day, 0) / event_days[day], 3)
                    if event_days.get(day)
                    else None
                ),
            }
            for day in all_days
        ],
    }
