# 2. Architecture

## Components and trust boundaries

```
┌─── ZONE 1: CAMERA VLAN (untrusted) ───────────────────────────────────┐
│                                                                       │
│   IP cameras / NVR                                                     │
│   Firmware from 2016, default credentials, no patch path.              │
│   Treated as hostile. No inbound trust whatsoever.                     │
│        │ RTSP                                                          │
│        ▼                                                               │
│   ┌──────────────────────────────────────────┐                         │
│   │  EDGE WORKER  (one process per camera)   │                         │
│   │                                          │                         │
│   │   read frame                             │                         │
│   │   → pose estimation (17 COCO keypoints)  │                         │
│   │   → DISCARD FRAME                        │◄── privacy boundary     │
│   │   → strip head keypoints                 │                         │
│   │   → IoU tracking (ephemeral track_ref)   │                         │
│   │   → behavioural features                 │                         │
│   │   → concealment score                    │                         │
│   │   → privacy assertion (fail closed)      │                         │
│   │   → HMAC-SHA256 sign                     │                         │
│   └──────────────────┬───────────────────────┘                         │
└────────────────────── │ ───────────────────────────────────────────────┘
                        │  HTTPS POST /api/v1/events
                        │  X-SF-Signature, nonce, occurred_at
                        │  ~400 bytes of JSON. No imagery. Ever.
┌────────────────────── ▼ ─── ZONE 2: STORE SERVICE VLAN ───────────────┐
│   ┌──────────────────────────────────────────┐                         │
│   │  CORE SERVICE (FastAPI)                  │                         │
│   │                                          │                         │
│   │   ingest: size cap → HMAC verify →       │                         │
│   │     skew window → nonce uniqueness →     │                         │
│   │     schema → fairness screen → rate cap  │                         │
│   │                                          │                         │
│   │   policy engine: zone weighting,         │                         │
│   │     confidence reducers, cooldown,       │                         │
│   │     per-zone alert budget                │                         │
│   │                                          │                         │
│   │   duress: rolling-code verification      │                         │
│   │   RBAC: 4 roles, oversight separated     │                         │
│   │   audit: hash-chained, append-only       │                         │
│   │   retention: background sweeper          │                         │
│   └────────┬──────────────────────┬──────────┘                         │
│            │ WebSocket            │ rolling code over HTTPS            │
│            ▼                      ▲                                    │
│   ┌─────────────────┐    ┌────────┴─────────┐                          │
│   │  DASHBOARD      │    │  RADIO GATEWAY   │                          │
│   │  staff device   │    │  LoRa / 433MHz   │                          │
│   └─────────────────┘    └────────▲─────────┘                          │
└───────────────────────────────────│────────────────────────────────────┘
                                    │ rolling code, one-way RF
                          ┌─────────┴─────────┐
                          │  DURESS FOBS      │  staff-carried
                          └───────────────────┘
```

Reverse proxy terminating TLS sits in front of the core service. In development the service
binds loopback and runs plaintext.

## The privacy boundary is the central architectural fact

Everything else follows from one decision: **image data never leaves the edge process.**

In [`edge/pipeline.py`](../edge/pipeline.py) the frame is consumed by the pose backend and
released before anything is yielded downstream. In
[`edge/backends/base.py`](../edge/backends/base.py) the `PoseDetection` dataclass has no
field capable of holding pixels, an embedding, or a crop. In
[`edge/privacy.py`](../edge/privacy.py), `assert_no_imagery` walks every outbound payload
immediately before signing and refuses bytes, data URIs, base64 blobs, long numeric arrays,
overlong strings, and any type not on a small allowlist.

That last point matters: the check **fails closed**. An unrecognised type raises rather than
passes. A numpy array or an open file handle cannot slip through by being unanticipated.

## Why the edge/core split at all

It would be simpler to run detection inside the core service. The split earns its complexity
three times over:

1. **It makes the privacy claim structural.** With a network boundary in the middle, "no
   imagery is stored" is enforced by what the protocol can carry, not by remembering not to
   write a file.
2. **It contains a camera-network compromise.** The camera VLAN is the least trustworthy part
   of a retail estate. A compromised edge box holds one camera's key and can forge events for
   one camera, which is detectable and revocable without touching anything else.
3. **It matches the deployment reality.** Cameras are analogue-era infrastructure on a
   separate physical network. The edge worker is the only thing that needs to be near them.

## Request flow: an event from gesture to prompt

1. **Edge** accumulates ~6 seconds of pose history per tracked person, runs the per-arm
   gesture state machine, and scores any concealment pattern found. Below a publish floor of
   0.35, nothing is sent.
2. **Edge** rounds float precision, redacts prohibited keys as defence in depth, asserts the
   privacy boundary, signs the canonical JSON with the camera's key, and POSTs it.
3. **Core** applies the seven ingest controls in order (see
   [`03-threat-model.md`](03-threat-model.md), control C-03).
4. **Core policy engine** adjusts the score for zone risk and observation reliability, then
   applies cooldown and budget checks. Suppression decisions are recorded, not silent.
5. **Core** writes an audit entry and pushes to the WebSocket hub.
6. **Dashboard** renders the prompt with its full score breakdown, so the member of staff can
   see why.
7. **Staff** acknowledge, act, and record an outcome. That outcome is the only ground truth
   the system will ever have.

Step 7 is the one that is usually missing from systems like this, and without it steps 1 to 6
cannot be evaluated or improved.

## Two clocks, deliberately separated

Behavioural reasoning runs on the **frame clock**: how long a hand stayed against the body is
measured in frame timestamps. Replay protection runs on the **wall clock**, because the core's
skew window is defined around real time.

Conflating them produces a genuinely confusing failure. During a compressed replay the frame
clock runs minutes ahead of wall time, every event looks future-dated, and the core correctly
rejects all of them as possible replays. `EdgePipeline._publication_timestamp` keeps the two
apart. In live operation they differ only by inference latency.

## Data model shape

Full detail in [`core/models.py`](../core/models.py). What matters is what is absent:

- **No `Customer` table.** There is nowhere to put a person.
- **No watchlist entity.** There is nowhere to record that someone is barred.
- **No face or embedding column.** Anywhere.
- **`track_ref` is a random 64-bit handle** scoped to one camera and one visit. It exists only
  so the core can suppress duplicate prompts about the same ongoing behaviour. It is not
  correlated across cameras and is meaningless once the person leaves frame.
- **`Event.features` is a flat numeric dictionary.** Explainable to a member of staff and to a
  regulator, which a raw model logit is not.

## Design decisions and their costs

| Decision | Why | What it costs |
|---|---|---|
| Pose only, no appearance | Legal exposure of biometrics; documented bias in retail surveillance AI | Lower ceiling on accuracy; cannot recognise repeat offenders |
| Rule-based baseline scorer | Inspectable, needs no training data, generates the labels a model would need | Weaker than a trained temporal model |
| Alerts advisory, never automated | Detector cannot see the item; automated action on a 70%-confident signal is indefensible | Requires staff availability to have any value |
| Silent-first duress | 1,600 staff abuse incidents a day; loud alarms escalate | Slower mobilisation than a siren |
| Hash-chained audit in the same database | Makes tampering detectable with no extra infrastructure | Does not prevent tampering; needs external anchoring (C-12) |
| SQLite by default | Zero-setup for a single store | Single writer; Postgres required for multi-store |
| Bounded in-memory retry queue | Refuses to create an unmanaged data store on a physically insecure box | Events are lost during a network outage |
| Single-process WebSocket hub | Simple, adequate for one store | Needs a Redis backplane before horizontal scaling |

## Known architectural limits

- **Single-process only.** The alert hub and the login throttle hold state in memory. Two
  workers means subscribers miss events ingested by the other worker (see
  [`07-roadmap.md`](07-roadmap.md)).
- **Camera keys stored in plaintext** in the database. This is risk R-07 and needs a KMS.
- **No zone geometry.** A camera maps to one zone. Real stores need polygon regions within a
  frame to distinguish the confectionery shelf from the aisle in front of it.
- **`tag_removal_motion` is a stub.** Detecting security-tag removal needs fine hand pose,
  which 17-point COCO keypoints cannot provide.
