"""Detection quality measurement.

The single most important thing in this module is what it *refuses* to report.

**Precision is measurable. Recall is not.** Precision comes straight from staff
dispositions: of the prompts we raised, how many were real. Recall would require knowing
about every theft that occurred, including the ones nobody saw, which is precisely the
information a store does not have. Any vendor quoting a recall figure from live
deployment data is quoting something they cannot know.

The honest substitute is an indirect one: correlate alert volume and confirmed recoveries
against measured shrinkage from stocktake over the same period. That gives a directional
signal about coverage without pretending to a number we cannot compute. See
:func:`recall_proxy_note` and docs/06-evaluation-plan.md.

**Demographic fairness cannot be measured here either, and that is by design.** The
system deliberately never collects age, gender, ethnicity, or any proxy for them, so it
is impossible to compute demographic parity. That is the correct tradeoff, but it must be
stated rather than glossed: we have removed the ability to discriminate on those
attributes and simultaneously removed the ability to prove we did not. What remains
measurable is structural: whether alert rates are wildly uneven across zones and hours in
ways the store layout does not explain, and periodic blind human review of a sample of
prompts. Both are implemented below.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import Alert, AlertStatus, Disposition, Event, Zone
from core.util import as_utc, utcnow

#: Dispositions that count as the model having been right.
TRUE_POSITIVE_DISPOSITIONS = frozenset(
    {
        Disposition.TRUE_POSITIVE_RECOVERED.value,
        Disposition.TRUE_POSITIVE_LOST.value,
    }
)

#: Dispositions that carry no signal and must be excluded from precision rather than
#: silently counted as successes. Counting "unclear" as a true positive is the easiest
#: way to make a detection system look better than it is.
UNSCORED_DISPOSITIONS = frozenset(
    {Disposition.UNCLEAR.value, Disposition.NOT_ATTENDED.value}
)


@dataclass
class DetectionQuality:
    window_days: int
    alerts_total: int = 0
    alerts_resolved: int = 0
    true_positives: int = 0
    false_positives: int = 0
    unscored: int = 0
    precision: float | None = None
    mean_time_to_acknowledge_seconds: float | None = None
    median_time_to_acknowledge_seconds: float | None = None
    unattended_rate: float | None = None
    by_event_type: dict[str, dict] = field(default_factory=dict)
    by_zone: dict[str, dict] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "window_days": self.window_days,
            "alerts_total": self.alerts_total,
            "alerts_resolved": self.alerts_resolved,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "unscored": self.unscored,
            "precision": self.precision,
            "recall": None,
            "recall_note": recall_proxy_note(),
            "mean_time_to_acknowledge_seconds": self.mean_time_to_acknowledge_seconds,
            "median_time_to_acknowledge_seconds": self.median_time_to_acknowledge_seconds,
            "unattended_rate": self.unattended_rate,
            "by_event_type": self.by_event_type,
            "by_zone": self.by_zone,
        }


def recall_proxy_note() -> str:
    return (
        "Recall is not computable from deployment data: it would require ground truth on "
        "thefts that were never observed. Use stocktake shrinkage over matched periods as "
        "a directional proxy, and treat any quoted live recall figure as unfounded."
    )


def _precision(true_positives: int, false_positives: int) -> float | None:
    denominator = true_positives + false_positives
    if denominator == 0:
        return None
    return round(true_positives / denominator, 4)


def detection_quality(
    session: Session, store_id: int, *, window_days: int = 14
) -> DetectionQuality:
    """Compute precision and responsiveness over a trailing window."""
    cutoff = utcnow() - timedelta(days=window_days)
    result = DetectionQuality(window_days=window_days)

    alerts = session.execute(
        select(Alert).where(Alert.store_id == store_id, Alert.created_at >= cutoff)
    ).scalars().all()

    result.alerts_total = len(alerts)
    if not alerts:
        return result

    ack_latencies: list[float] = []
    per_type: dict[str, Counter] = defaultdict(Counter)
    per_zone: dict[str, Counter] = defaultdict(Counter)

    for alert in alerts:
        event = session.get(Event, alert.event_id)
        event_type = event.event_type if event else "unknown"
        zone_name = alert.zone.name if alert.zone else "unmapped"

        per_type[event_type]["alerts"] += 1
        per_zone[zone_name]["alerts"] += 1

        latency = alert.time_to_acknowledge_seconds
        if latency is not None:
            ack_latencies.append(latency)

        if alert.status != AlertStatus.RESOLVED.value or alert.disposition is None:
            continue

        result.alerts_resolved += 1

        if alert.disposition in TRUE_POSITIVE_DISPOSITIONS:
            result.true_positives += 1
            per_type[event_type]["true_positives"] += 1
            per_zone[zone_name]["true_positives"] += 1
        elif alert.disposition == Disposition.FALSE_POSITIVE.value:
            result.false_positives += 1
            per_type[event_type]["false_positives"] += 1
            per_zone[zone_name]["false_positives"] += 1
        else:
            result.unscored += 1
            per_type[event_type]["unscored"] += 1
            per_zone[zone_name]["unscored"] += 1

    result.precision = _precision(result.true_positives, result.false_positives)

    if ack_latencies:
        result.mean_time_to_acknowledge_seconds = round(statistics.fmean(ack_latencies), 1)
        result.median_time_to_acknowledge_seconds = round(statistics.median(ack_latencies), 1)

    not_attended = sum(
        1 for a in alerts if a.disposition == Disposition.NOT_ATTENDED.value
    )
    unacknowledged = sum(1 for a in alerts if a.acknowledged_at is None)
    result.unattended_rate = round((not_attended + unacknowledged) / len(alerts), 4)

    result.by_event_type = {
        name: {
            **dict(counts),
            "precision": _precision(counts["true_positives"], counts["false_positives"]),
        }
        for name, counts in per_type.items()
    }
    result.by_zone = {
        name: {
            **dict(counts),
            "precision": _precision(counts["true_positives"], counts["false_positives"]),
        }
        for name, counts in per_zone.items()
    }

    return result


def threshold_sweep(
    session: Session,
    store_id: int,
    *,
    candidates: tuple[float, ...] = (0.55, 0.6, 0.65, 0.7, 0.72, 0.75, 0.8, 0.85, 0.9),
    window_days: int = 30,
) -> list[dict]:
    """Retrospective what-if analysis over the alerting threshold.

    Answers "what would have happened if the threshold had been higher" using the scores
    and dispositions already recorded. This is how the threshold should be tuned: against
    the store's own labelled outcomes, not against a benchmark dataset.

    One important limitation, stated rather than buried: this can only reason about
    alerts that were actually raised, so it shows how raising the threshold would have
    removed prompts. It cannot show what *lowering* it would have surfaced, because
    events below the current threshold were never shown to staff and so were never
    labelled. Lowering a threshold always requires a live trial.
    """
    cutoff = utcnow() - timedelta(days=window_days)

    labelled = session.execute(
        select(Alert).where(
            Alert.store_id == store_id,
            Alert.created_at >= cutoff,
            Alert.disposition.is_not(None),
        )
    ).scalars().all()

    rows: list[dict] = []
    for threshold in candidates:
        retained = [a for a in labelled if a.score >= threshold]
        tp = sum(1 for a in retained if a.disposition in TRUE_POSITIVE_DISPOSITIONS)
        fp = sum(1 for a in retained if a.disposition == Disposition.FALSE_POSITIVE.value)
        missed_tp = sum(
            1
            for a in labelled
            if a.score < threshold and a.disposition in TRUE_POSITIVE_DISPOSITIONS
        )

        rows.append(
            {
                "threshold": threshold,
                "alerts_retained": len(retained),
                "true_positives": tp,
                "false_positives": fp,
                "precision": _precision(tp, fp),
                "true_positives_forgone": missed_tp,
                "alerts_avoided": len(labelled) - len(retained),
            }
        )

    return rows


def alert_rate_dispersion(
    session: Session, store_id: int, *, window_days: int = 14
) -> dict:
    """Structural fairness and drift monitoring.

    Flags zones whose alert rate is a long way from the estate median. A zone firing five
    times more often than its peers is either genuinely a hotspot, or has a camera that
    has been knocked out of alignment, or is producing systematically biased detections.
    All three need a human to look, and the analysis cannot tell them apart, so it
    reports the anomaly rather than a conclusion.
    """
    cutoff = utcnow() - timedelta(days=window_days)

    alerts = session.execute(
        select(Alert).where(Alert.store_id == store_id, Alert.created_at >= cutoff)
    ).scalars().all()

    zones = session.execute(
        select(Zone).where(Zone.store_id == store_id)
    ).scalars().all()

    counts: Counter = Counter()
    for alert in alerts:
        counts[alert.zone.name if alert.zone else "unmapped"] += 1

    for zone in zones:
        counts.setdefault(zone.name, 0)

    values = list(counts.values())
    if not values:
        return {
            "window_days": window_days,
            "zones": {},
            "median": 0,
            "outliers": [],
            "interpretation": "No alerts in window.",
        }

    median = statistics.median(values)
    outliers = [
        {"zone": name, "alerts": count, "ratio_to_median": round(count / median, 2)}
        for name, count in counts.items()
        if median > 0 and (count / median >= 3.0 or (count == 0 and median >= 5))
    ]

    return {
        "window_days": window_days,
        "zones": dict(counts),
        "median": median,
        "mean": round(statistics.fmean(values), 2),
        "stdev": round(statistics.pstdev(values), 2) if len(values) > 1 else 0.0,
        "outliers": sorted(outliers, key=lambda row: -row["ratio_to_median"]),
        "interpretation": (
            "Outliers require human review. A high ratio may indicate a genuine hotspot, "
            "a misaligned camera, or systematically biased detection. This analysis "
            "cannot distinguish between them and does not attempt to."
        ),
        "demographic_fairness": (
            "Not measurable by design: no demographic attribute is collected or inferred. "
            "Substitute control is a periodic blind review of a random sample of prompts."
        ),
    }


def review_sample(
    session: Session, store_id: int, *, size: int = 20, window_days: int = 14
) -> list[dict]:
    """Draw a sample of prompts for blind human review.

    Deliberately sampled across the full score range rather than only the high scores.
    Reviewing only the confident detections tells you nothing about the marginal ones,
    which is where the errors live.
    """
    import random

    cutoff = utcnow() - timedelta(days=window_days)
    alerts = session.execute(
        select(Alert).where(Alert.store_id == store_id, Alert.created_at >= cutoff)
    ).scalars().all()

    if not alerts:
        return []

    buckets: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        band = f"{int(alert.score * 10) / 10:.1f}"
        buckets[band].append(alert)

    rng = random.Random(20260912)
    per_bucket = max(1, size // max(1, len(buckets)))
    picked: list[Alert] = []
    for band in sorted(buckets):
        picked.extend(rng.sample(buckets[band], min(per_bucket, len(buckets[band]))))

    return [
        {
            "alert_id": alert.id,
            "score": round(alert.score, 3),
            "zone": alert.zone.name if alert.zone else None,
            "created_at": as_utc(alert.created_at).isoformat(),
            "recorded_disposition": alert.disposition,
            "rationale": alert.rationale,
        }
        for alert in picked[:size]
    ]
