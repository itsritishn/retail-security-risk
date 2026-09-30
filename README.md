# SentinelFloor

Privacy-first, behaviour-based loss prevention and staff-duress platform for small-format
retail stores that have no security guard on the door.

SentinelFloor watches **skeletons, not faces**. It never identifies a customer, never keeps a
watchlist, and never makes an accusation. It raises a low-confidence prompt to a human member
of staff, who decides what to do. Every decision is recorded in a tamper-evident audit log.

---

## Why this exists

The British Retail Consortium's 2026 survey recorded 5.5 million detected shoplifting incidents
in the UK over a 12-month period, roughly £400m in direct losses, and £4.2bn once prevention
spend is included. Staff-directed violence and abuse runs at approximately 1,600 incidents per
day. Enterprise loss-prevention suites exist, but they are priced and scoped for large stores.
A single-manager convenience store with four cameras and no door guard is not their market.

SentinelFloor targets that gap, and treats the resulting system as a security engineering
problem rather than only a machine learning one.

## What it is not

- Not facial recognition. There is no face gallery, no embedding store, no identity resolution.
- Not a watchlist or a "known offender" database.
- Not an automated decision system. It cannot detain, ban, charge, or accuse anyone.
- Not a profiling tool. Demographic inference is out of scope by design, and alert-rate
  fairness is actively monitored (see `analytics/`).

These are hard architectural constraints, not settings. See `docs/04-dpia-privacy.md`.

---

## Architecture at a glance

```
   ┌──────────────────────────────┐
   │  EDGE TIER (one per camera)  │   runs on-prem, near the NVR
   │                              │
   │  frame  →  person detect     │
   │         →  pose extract      │   pixels discarded here
   │         →  DROP RGB FRAME    │   ◄── privacy boundary
   │         →  track + features  │
   │         →  concealment score │
   └──────────────┬───────────────┘
                  │  signed event JSON (no imagery)
                  │  HMAC-SHA256 + nonce + timestamp
                  ▼
   ┌──────────────────────────────┐
   │  CORE SERVICE (FastAPI)      │
   │                              │
   │  event ingest → policy       │   thresholds, zone weighting,
   │  engine → alert fan-out      │   cooldown, dedupe
   │                              │
   │  duress subsystem            │   rolling-code auth, silent-first
   │  RBAC + session auth         │   assistant/duty_manager/admin/auditor
   │  hash-chained audit log      │   tamper-evident
   │  retention enforcement       │   auto-purge
   └──────────────┬───────────────┘
                  │  WebSocket
                  ▼
   ┌──────────────────────────────┐
   │  SHOP-FLOOR DASHBOARD        │
   │  alert queue + disposition   │   staff feedback closes the ML loop
   └──────────────────────────────┘
```

Full detail in `docs/02-architecture.md`.

---

## Quick start

Requires Python 3.11+. Tested on 3.13.

```bash
./scripts/dev.sh setup      # venv + core dependencies
./scripts/dev.sh seed       # create demo store, zones, users, devices
./scripts/dev.sh test       # run the test suite
./scripts/dev.sh serve      # start on http://127.0.0.1:8000
```

Then, in a second terminal:

```bash
./scripts/dev.sh demo       # replay a synthetic shift through the pipeline
```

Open http://127.0.0.1:8000 and log in with the credentials printed by `seed`.

### Security note on running this

The service binds to `127.0.0.1` by default and every route except `/healthz` requires
authentication. Do not expose it to a network without reading
`docs/03-threat-model.md` first — in particular the sections on camera-network segmentation
and reverse-proxy TLS termination. `SENTINEL_SECRET_KEY` must be set to a unique random value
before any non-local use; the app refuses to start in non-debug mode with the default value.

### The edge tier without ML dependencies

The edge pipeline ships with a `synthetic` backend that generates realistic pose sequences,
so you can run and test the entire system end to end with no PyTorch, no CUDA, and no video
files. Swap to real inference with:

```bash
pip install -r requirements-edge.txt
# then set backend: yolo_pose in edge/config.yaml
```

---

## Repository layout

| Path         | Contents                                                             |
|--------------|----------------------------------------------------------------------|
| `core/`      | FastAPI service: ingest, policy engine, duress, RBAC, audit, dashboard |
| `edge/`      | Per-camera pipeline: pose extraction, tracking, behaviour features    |
| `analytics/` | Shrink hotspots, detection quality, alert-rate fairness monitoring    |
| `docs/`      | Threat model, DPIA, device security design, evaluation plan, roadmap  |
| `scripts/`   | Dev helper, synthetic shift replay                                    |
| `tests/`     | Policy, audit-chain, API, and feature-extraction tests                |

## Documentation

Read in this order:

1. `docs/01-problem-and-market.md` — the problem, the numbers, the competitive landscape
2. `docs/02-architecture.md` — components, data flow, trust boundaries
3. `docs/03-threat-model.md` — STRIDE analysis and controls
4. `docs/04-dpia-privacy.md` — data protection impact assessment
5. `docs/05-duress-device-security.md` — cryptographic design for the panic button
6. `docs/06-evaluation-plan.md` — how detection quality and fairness are measured
7. `docs/07-roadmap.md` — 12-week delivery plan
8. `docs/12-secrets-incident.md` — incident report: secrets committed via a SQLite WAL sidecar,
   found in a self-audit of this repository, with root cause, rotation, and prevention

`PITCH.md` is the one-page summary for a non-technical audience.

## Licence and status

Portfolio and research project. Not production-certified. Deploying this in a live store
requires a completed DPIA, staff consultation, signage, and sign-off from the data controller.
