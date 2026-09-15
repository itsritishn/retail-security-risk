# 1. Problem, evidence, and competitive landscape

## The problem, stated precisely

A small-format convenience store operates with two or three staff on shift, no security
guard on the door, and four to eight cameras feeding a recorder that nobody watches live.
The cameras are used forensically: someone reviews the footage after stock is found
missing. By then the loss has already happened and the recording is only useful for a
police report that, for a £4 chocolate bar, will not be filed.

The gap is not recording. It is **live attention**. Nobody is watching, because everybody
is serving customers.

## The evidence

From the British Retail Consortium's retail crime survey published February 2026, covering
1 September 2024 to 31 August 2025:

| Measure | Figure |
|---|---|
| Detected shoplifting incidents (UK) | 5.5 million |
| Direct cost of theft | approximately £400 million |
| Total cost including prevention spend | £4.2 billion (£2.2bn stock, £1.8bn prevention) |
| Violence and abuse against retail staff | roughly 1,600 incidents per day |

Sources: [Guardian coverage of the BRC survey](https://www.theguardian.com/business/2026/feb/24/criminals-uk-shops-british-retail-consortium-violence-theft),
[Retail Technology Innovation Hub](https://retailtechinnovationhub.com/home/2026/2/23/investment-pays-off-as-progress-is-made-on-tacking-retail-crime-but-job-far-from-done-brc),
[Legatum Institute summary of the cost breakdown](https://www.prosperity.com/media-publications/welcome-to-the-low-trust-economy/).
*Content rephrased for compliance with licensing restrictions.*

Two things in that table shape the entire design.

**£1.8bn is already being spent on prevention.** The market is not "will retailers pay for
this". They are paying, heavily, and much of it goes on measures like locking Cadbury Dairy
Milk into alarmed plastic boxes, which
[has actually happened](https://www.independent.co.uk/news/uk/crime/shoplifting-chocolate-theft-dairy-milk-b2926378.html).
That is a measure that costs sales from honest customers in order to deter dishonest ones.

**1,600 staff abuse incidents a day is the constraint, not a footnote.** It is why this
system alerts silently and why its guidance pushes de-escalation. A tool that makes a
lone 22-year-old assistant more likely to confront somebody is a tool that increases harm
even if it reduces shrinkage. This is the single most important design consequence of the
evidence base.

## What already exists

This is an established commercial category. Pretending otherwise would be dishonest and
would fail the first question any informed person asks.

| Vendor | Approach |
|---|---|
| [Veesion](https://veesion.io/en/) | Gesture-recognition deep learning over existing CCTV, detecting movements that commonly precede theft, pushing clips to a staff app in real time via an on-premises server |
| [Everseen (Evershelf)](https://everseen.com/solutions/evershelf) | Vision AI for aisle loss prevention: product concealment, in-store consumption, unusual shelf-removal patterns, repeated activity near high-value merchandise |

*Content rephrased for compliance with licensing restrictions.*

Both are mature, well-funded, and solve the technical problem competently. **This project
does not claim novelty in detection.**

## Where the actual gap is

Enterprise loss-prevention platforms are sold to estates, priced per store per month, and
deployed by an integrator. A single-site convenience store, a franchise operator with four
shops, or a symbol-group retailer sits below that commercial floor. They get the alarmed
plastic box instead.

Four things are genuinely underserved, and they are what this project addresses:

**1. Privacy-first by construction, not by policy.** The commercial pressure in this sector
runs toward facial recognition and cross-store watchlists, because they are more effective
at catching repeat offenders. That path carries serious legal exposure (see
[`04-dpia-privacy.md`](04-dpia-privacy.md)). SentinelFloor takes pose data only, and enforces
that in code: prohibited features are rejected at the ingest boundary, and imagery cannot
cross the edge/core trust boundary because a runtime check refuses it.

**2. Alert fatigue treated as the primary failure mode.** A tool that interrupts staff
wrongly gets ignored within a week, at which point it is worse than nothing because it
consumes attention while providing no coverage. Cooldowns, per-zone alert budgets, and
mandatory outcome capture are first-class features here rather than tuning parameters.

**3. Staff safety as a co-equal goal.** Loss prevention and staff protection are usually
separate products. In a store with three people on shift they are the same problem, and the
duress subsystem is integrated with the detection system rather than bolted alongside it.

**4. Measurability the operator controls.** Vendors report their own accuracy. This system
computes precision from the store's own staff dispositions, and refuses to report recall at
all because recall is not computable from deployment data (see
[`06-evaluation-plan.md`](06-evaluation-plan.md)).

## Why the small-format constraint changes the engineering

It is not the same system scaled down.

- **No integrator.** It has to install and run without a specialist, which is why the edge
  tier ships a backend that needs no ML dependencies at all.
- **Physically insecure edge.** The compute sits in a stock room that deliveries, agency
  staff, and contractors can reach. That drives per-camera keys, tamper detection, and the
  decision not to spool behavioural data to local disk.
- **Nobody to watch a console.** Alerts go to whoever is on the floor, on the device they
  already have, and must be answerable in under two minutes or they are worthless.
- **No security team.** The controls have to be default-on and fail-closed, because there is
  no one to configure them and no one to notice if they silently stop working.

## Honest limitations of the premise

- Pose-only detection will never match a system that uses appearance and identity. That is
  an accepted, deliberate cost.
- The detector cannot see the item, only the hands. It cannot distinguish concealing a
  chocolate bar from putting away a phone. Human assessment is not a compliance gesture
  here; it is load-bearing.
- Deterrence probably contributes more of the real-world benefit than detection does. A
  visible member of staff in the right aisle at the right time prevents more loss than any
  alert, which is why the analytics tier produces staffing recommendations and treats them
  as a primary output rather than a nice extra.

## Related work worth reading

- [PoseLift (WACV 2025)](https://arxiv.org/abs/2501.06591) — anonymised pose dataset for
  shoplifting detection collected with a real retail store; reports that pose-based methods
  reach high detection accuracy while reducing privacy and bias exposure. This is both the
  academic grounding for the pose-only decision and the dataset to train on.
- [UCF-Crime](https://www.crcv.ucf.edu/papers/anomaly_detection.pdf) — 128 hours of
  real-world surveillance video across 13 anomaly categories; the standard benchmark, though
  its shoplifting subset is small.
- [CNN-BiLSTM shoplifting detection](https://www.mdpi.com/2076-3417/13/14/8341) — purpose-built
  benchmark of 900 clips balanced across five shoplifting methods.

*Content rephrased for compliance with licensing restrictions.*
