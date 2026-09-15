# 6. Evaluation plan

The most important section is the first one, because it is about a number this system refuses
to produce.

---

## Why recall cannot be reported

Precision is measurable: of the prompts raised, what fraction were genuine? Staff dispositions
answer that directly.

**Recall is not measurable from deployment data.** Recall requires the denominator "all thefts
that occurred", including every one nobody saw. That is precisely the quantity a store does not
have — if it did, it would not need the system.

So `/api/v1/analytics/detection-quality` returns `recall: null` with an explanation, and the
dashboard states why the field is absent. Any vendor quoting a live-deployment recall figure is
quoting something they cannot know, and recognising that is worth more than any benchmark score.

### The legitimate substitutes

**1. Recall on a labelled dataset**, reported as exactly that. On PoseLift or a held-out
annotated set, recall is computable because the labels exist. It must be reported as
"recall on dataset X", never as system performance.

**2. Shrinkage correlation.** Compare measured stock loss from stocktake against the same period
last year, and against a comparable store without the system. Slow and confounded by trade
patterns, staffing, and layout changes, but it measures the thing that actually matters.

**3. Known-outcome seeding.** During a supervised trial, have a briefed colleague perform
scripted concealment actions at logged times, with the duty manager's knowledge, and measure
what fraction the system flags. This gives a genuine recall estimate for those specific
behaviours. It says nothing about behaviours nobody thought to script, and must be reported
with that caveat.

---

## Metrics that are computed

Implemented in [`analytics/metrics.py`](../analytics/metrics.py) and
[`analytics/shrink.py`](../analytics/shrink.py).

### Detection quality

| Metric | Definition | Target | Why |
|---|---|---|---|
| Precision | TP / (TP + FP) from staff dispositions | **≥ 0.60** for sustained use | Below roughly 0.5 staff stop trusting prompts. This is the number that decides whether the system survives contact with a real shift |
| Unscored rate | Share of resolved alerts marked `unclear` or `not_attended` | < 0.25 | High values mean prompts arrive too late to assess, which is a staffing problem, not a model problem |
| Median time to acknowledge | Seconds from alert to acknowledgement | **< 60 s** | Beyond about two minutes the person has left the aisle and the prompt is worthless |
| p90 time to acknowledge | 90th percentile | < 180 s | Reveals the tail the median hides |
| Unattended rate | Never acknowledged, or explicitly not attended | < 0.20 | Measures whether the tool is used or ignored |
| Precision by event type | Same, split by `concealment` / `shelf_sweep` / `prolonged_dwell` | — | Usually shows dwell is the weakest signal, justifying its low weight |
| Precision by zone | Same, split by zone | — | A single bad zone often means a moved camera, not a model failure |

`unclear` and `not_attended` are excluded from the precision denominator rather than counted as
successes. Counting them as true positives is the easiest way to make a detector look better
than it is.

### Threshold tuning

`threshold_sweep` replays recorded scores and dispositions to answer "what would have happened
at a higher threshold". It reports, per candidate threshold: alerts retained, precision, and
**true positives forgone** — the genuine detections that would have been lost.

The stated limitation matters: it can only reason about alerts that were actually raised.
Events below the current threshold were never shown to staff, so they carry no label, and the
effect of *lowering* the threshold cannot be estimated retrospectively. Lowering always requires
a live trial. That asymmetry is easy to miss and produces overconfident tuning decisions.

### Operational value

`response_coverage` and `staffing_recommendation` exist because coverage matters more than model
accuracy once the model is adequate. A perfect detector whose prompts go unanswered for four
minutes prevents nothing.

The staffing output weights confirmed recoveries at +3.0, unlabelled prompts at +0.5, and
confirmed false positives at **−1.0**, so a zone that generates prompts but never real
recoveries argues against sending someone there. Ranked hotspots are ordered by confirmed
outcomes first and raw volume second, for the same reason.

---

## Fairness: what is measurable and what is not

This is the part that requires the most honesty.

### The tradeoff, stated plainly

The system deliberately collects no age, gender, ethnicity, or any proxy for them.
`PROHIBITED_FEATURE_KEYS` blocks 30 such attributes at both trust boundaries.

That is the right decision, and it has a direct consequence: **demographic parity cannot be
computed.** We have removed the ability to discriminate on those attributes and, in the same
move, removed the ability to prove that we did not.

Pretending otherwise would be the dishonest option. Collecting ethnicity "in order to monitor
fairness" would mean building the exact dataset the design exists to avoid, and creating a
special-category data store that would need its own Article 9 condition.

### What is monitored instead

**1. Structural dispersion.** `alert_rate_dispersion` flags zones whose alert rate is three or
more times the estate median, or that have gone silent while peers are active. It explicitly
reports that it cannot distinguish a genuine hotspot from a misaligned camera from
systematically biased detection, and asks for a human to look.

**2. Blind review sampling.** `review_sample` draws prompts stratified **across the full score
range**, not just the confident ones. Reviewing only high-scoring detections tells you nothing
about the marginal cases, which is where the errors live. A reviewer assesses each against its
recorded rationale without seeing the outcome, then compares. Disagreement indicates either an
unclear rationale or an unreliable label.

**3. Feature audit.** Periodically re-read what the model actually keys on. Every prompt carries
its full contribution breakdown, so this is inspection rather than interpretation. If
`body_shielding` starts dominating, that needs examining: "turned away from the camera" could
correlate with modest dress or with carrying a child.

**4. Independent oversight.** The auditor role can read the audit log, verify chain integrity,
and run all fairness analytics, but cannot acknowledge alerts, change policy, or run retention.
Oversight that can alter what it oversees provides no assurance.

### Recommended external step

Have someone who did not build the system review a sample of prompts against store CCTV under a
documented process, and record whether the flagged behaviour looks like concealment. That
catches systematic error that internal metrics cannot, because internal metrics are computed
from labels produced by the same staff whose judgement is being evaluated.

---

## Model development path

The current scorer is a transparent rule baseline (`rule-baseline-0.1.0`), and the sequencing
matters more than the model choice.

**Stage 1 — rule baseline (implemented).** Needs no training data, fully inspectable, gets a
working system in front of staff. Its real job is to **generate labels from your own store**.

**Stage 2 — supervised temporal model.** ST-GCN or a small transformer over pose sequences,
trained on [PoseLift](https://arxiv.org/abs/2501.06591), with UCF-Crime and DCSASS as secondary
sources. Report precision, recall, and ROC-AUC on held-out data, and be explicit that dataset
performance is not deployment performance.

**Stage 3 — local adaptation.** Fine-tune or recalibrate against the store's own dispositions.
This is where most of the real gain lives, because aisle geometry, camera angles, and lighting
differ per site.

**Stage 4 — monitored retraining.** Threshold sweep and dispersion monitoring as acceptance
gates. A candidate model ships only if it improves precision without a disproportionate loss of
confirmed detections.

Starting at stage 2 is the common mistake. Without stage 1 there are no labels from your own
store, and a model tuned on someone else's aisles will disappoint in yours.

### Drift

Retail environments change constantly: displays move, seasonal stock arrives, lighting is
replaced. `event_volume_trend` reports daily event and alert volume so a step change is visible.
A sudden shift with no change in trade usually means something physical moved, so **model drift
in a retail store is most often a facilities problem**, and that is where to look first.

---

## Acceptance criteria for a live trial

Before recommending sustained use, four weeks minimum:

| Criterion | Threshold | Failure means |
|---|---|---|
| Precision | ≥ 0.60 over the final two weeks | Raise the threshold or improve the model |
| Median acknowledgement | < 60 s | Staffing or notification problem |
| Unattended rate | < 0.20 | The tool is being ignored; find out why |
| Alert volume | < 15 per store per day | Alert fatigue; tighten the budget |
| Zone dispersion outliers | Zero unexplained | Investigate each before proceeding |
| Audit chain | Verifies clean throughout | Integrity failure; stop and investigate |
| Duress test activations | 100% delivered, weekly | Life-safety failure; do not proceed |
| Staff assessment | Majority report it helps rather than distracts | The people using it are the final arbiter |

The last one is not decoration. A loss-prevention tool the staff resent will be worked around,
and no metric will show it.

---

## Reproducing the numbers

```bash
./scripts/dev.sh seed
./scripts/dev.sh serve                              # separate terminal
python -m scripts.demo_replay --with-outcomes
```

Then, signed in as admin or auditor:

```
GET /api/v1/analytics/detection-quality?window_days=14
GET /api/v1/analytics/threshold-sweep
GET /api/v1/analytics/fairness
GET /api/v1/analytics/review-sample
GET /api/v1/analytics/hotspots
GET /api/v1/analytics/staffing
GET /api/v1/analytics/response-coverage
```

A verified run of the synthetic shift produced 253 tracks, 39 published events, and 12 alerts,
with 12 alerts against high-risk zones and zero against the baseline-weighted entrance and till
areas. With synthetic dispositions applied, precision came out at **0.44**.

That figure is deliberately unflattering and the demo generator is weighted to produce it. A
first-pass rule-based detector in a real store does produce a substantial share of false
positives, and a demo showing 95% precision would teach exactly the wrong lesson about what to
expect on day one.
