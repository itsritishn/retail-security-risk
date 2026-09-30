# 7. Roadmap

Sequenced for someone building this around shift work, roughly 8–12 hours a week. The ordering
is deliberate: each phase produces something demonstrable on its own, so the project is
presentable at every point rather than only at the end.

**What exists now** is everything in phase 0. That is already a coherent portfolio piece. Phases
1 to 4 deepen it; phase 5 is only worth attempting with a real employer relationship.

---

## Phase 0 — complete

- Core service: signed ingest, policy engine, RBAC, hash-chained audit, retention sweeper
- Edge tier: pose abstraction, per-arm gesture state machine, tracking, scoring, signed publisher
- Duress subsystem: rolling-code authentication, silent-first escalation, staff guidance
- Dashboard: live alert queue, disposition capture, camera health, duress panel
- Analytics: precision, threshold sweep, dispersion monitoring, hotspots, staffing recommendations
- 180 tests covering the security and behavioural properties
- Threat model, DPIA, device security design, evaluation plan

**Verified working end to end.** 253 tracks → 39 signed events → 12 alerts, audit chain intact,
all three duress attacks rejected.

---

## Phase 1 — weeks 1–2: real inference

Replace the synthetic backend with actual pose estimation so the pipeline runs on video.

- `pip install -r requirements-edge.txt`, switch `backend: yolo_pose`
- Record your own test footage: you and a friend, in a room, acting out concealment and
  replacement. Ten minutes of clips is enough. Written consent from everyone in frame.
- **Do not use your employer's CCTV.** The backend refuses live sources without an
  `authorisation_reference` for exactly this reason.
- Measure and record throughput on your hardware: frames per second at 640px on CPU versus MPS.
  A realistic figure for what a £150 box can do is genuinely useful information.
- Tune `REACH_THRESHOLD`, `BODY_THRESHOLD`, and `MEDIAL_THRESHOLD` against real pose data. The
  synthetic values will not transfer exactly.

**Deliverable:** a 60-second screen recording of a real clip producing a real alert on the
dashboard. This is the single most valuable artefact for a job application, because it proves
the thing works rather than describing it.

---

## Phase 2 — weeks 3–5: the security work that makes this a cyber project

This phase is the reason the project exists. Do not skip it to build more features.

**Pen test your own deployment** following the plan in
[`03-threat-model.md`](03-threat-model.md#pen-test-plan-for-this-system). Write it up as a proper
report: scope, methodology, findings with CVSS-style severity, evidence, remediation, retest.
Ten well-evidenced findings including "no issue found" results is a stronger artefact than
fifty automated scanner hits.

Tooling worth using and citing: `ffuf` or Burp for the ingest boundary, `sqlmap` against the
query paths (expect nothing, SQLAlchemy is parameterised, and a clean negative result is a
finding), `nuclei` for the headers, and a manual role matrix walk for authorisation.

**Fix R-07: get camera keys out of plaintext.** Options in increasing realism: OS keyring for a
single box, HashiCorp Vault in dev mode, or AWS KMS with envelope encryption. Implement per-camera
rotation with an overlap window so rotation does not drop events. This is the highest-value
remaining technical fix.

**Implement C-12: anchor the audit chain externally.** A scheduled job publishing
`chain_head()` to append-only storage — an S3 bucket with object lock, or simply a signed daily
email. Then write the verification procedure. This closes the "someone with database access
could rewrite the whole chain" gap.

**Add detection engineering.** Ship logs to a SIEM (Wazuh or the Elastic free tier, both run on
a laptop) and write rules for: repeated `event.rejected` from one camera, any
`event.rejected_prohibited_feature`, `duress.rejected` bursts, `alert.suppressed` storms,
authentication spraying, and audit chain verification failure. **Detection content you wrote
yourself, mapped to your own threat model, is exactly what a SOC interview asks about.**

**Deliverable:** `docs/09-pentest-report.md` and `docs/10-detection-rules.md`. These two documents
will do more for a security application than any additional feature.

---

## Phase 3 — weeks 6–8: model work

Now the data analytics MSc earns its place.

- Obtain [PoseLift](https://github.com/TeCSAR-UNCC/PoseLift) and reproduce the paper's baseline.
  Reproducing published results is an underrated skill and a good talking point.
- Train an ST-GCN or small transformer over pose sequences. Report precision, recall, and ROC-AUC
  on held-out data, clearly labelled as dataset performance rather than deployment performance.
- Compare against the rule baseline **on the same data**. Report honestly if the rules win on
  precision; on small data they sometimes do, and saying so demonstrates judgement.
- Implement adversarial evasion testing: loose clothing, deliberate occlusion, turning away.
  Quantify the degradation. This is the most interesting result you will produce and almost
  nobody publishes it.
- Add model versioning so `model_version` on each event ties a prompt to the model that raised it.

**Deliverable:** `docs/11-model-evaluation.md` with a threshold curve, a confusion matrix, and an
evasion analysis.

---

## Phase 4 — weeks 9–12: production hardening

- **Redis backplane** for the WebSocket hub and the rate limiters, removing the single-process
  constraint (R-05).
- **PostgreSQL** with Alembic migrations, so schema changes are reviewable artefacts.
- **Zone polygons** rather than one-zone-per-camera. Define regions within a frame so the
  confectionery shelf is distinguishable from the aisle in front of it. This is probably the
  largest single accuracy improvement available.
- **Containerise** with a non-root user, read-only root filesystem, and dropped capabilities.
  Compose file for the whole stack.
- **CI pipeline:** ruff, pytest, `pip-audit` for dependency CVEs, Trivy for the image, and
  Semgrep or CodeQL for SAST. A green pipeline with security gates is a credible signal.
- **Mobile-first alert view.** Staff carry phones, not laptops. The current dashboard is
  responsive but not designed phone-first.

---

## Phase 5 — only with a real employer relationship

Everything here needs written authorisation and is not a solo activity.

- Approach the store manager with [`PITCH.md`](../PITCH.md). Ask about a supervised trial on one
  camera in one aisle, outside trading hours to begin with.
- The manager will escalate. A symbol group owned by a large grocer has central information security,
  data protection, and loss prevention functions, and all three would need to be involved. Expect
  a long process, and treat that as the point rather than an obstacle: **navigating an approval
  process is itself the experience worth having.**
- Requirements before any live data: completed DPIA signed by the controller, staff consultation,
  signage, and a documented retention configuration.
- If the answer is no, that is a perfectly good outcome. "I proposed it, went through the DPIA
  process, and it was declined at information security review on these grounds" is a stronger
  interview story than most approved projects.

---

## Deliberately out of scope

Recorded so the boundaries are visible as choices rather than omissions.

| Not doing | Why |
|---|---|
| Facial recognition, watchlists, re-identification | The core design constraint. See [`04-dpia-privacy.md`](04-dpia-privacy.md) section 6 |
| Cross-store data sharing | Would create a de facto offender database with no due process |
| Automated intervention: till locks, door locks, tannoy triggers | Detector cannot see the item. Automated action on a 70%-confident signal is indefensible |
| Emotion or intent inference | Scientifically weak and carries specific EU AI Act duties |
| Staff productivity monitoring | Purpose limitation. Would also destroy staff trust and with it the disposition data everything depends on |
| Mobile app | A responsive web dashboard is sufficient and avoids app store distribution |

---

## Where the effort is best spent

If time is limited, the ranking is: **phase 2 first, then phase 1.**

Phase 1 makes the project more impressive to look at. Phase 2 makes it a cybersecurity project
rather than a computer vision project, which is the actual goal. A pen test report and a set of
detection rules written against your own threat model will get more interviews than a better
detector will.
