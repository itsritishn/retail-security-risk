# 3. Threat model

Method: STRIDE per component across the trust boundaries in
[`02-architecture.md`](02-architecture.md), followed by a risk register with control mappings
and an explicit statement of what is **not** mitigated.

Scope: the SentinelFloor system itself. Store physical security, EPOS, and the retailer's
corporate network are out of scope except where they interact.

---

## Assets, ranked by what their loss actually costs

| Asset | Why it matters | Worst realistic outcome |
|---|---|---|
| Customer dignity and privacy | The whole system operates on non-consenting members of the public | Wrongful accusation; regulatory action; a person is humiliated in a shop |
| Staff physical safety | Duress is a life-safety function | An assistant is assaulted because the alarm did not reach anyone |
| Audit trail integrity | The only evidence that the system was operated properly | A complaint cannot be investigated; accountability collapses |
| Camera ingest keys | Authenticate all detection input | Attacker forges or suppresses alerts at will |
| Duress fob secrets | Authenticate life-safety signalling | Attacker triggers or disables the panic button |
| Behavioural event data | Personal data under UK GDPR | Unlawful processing; excessive retention |
| Staff credentials | Access to the alert queue and analytics | Insider misuse under someone else's name |

Note the ordering. In most threat models the operator's data sits at the top. Here the people
being watched come first, because they did not choose to participate and cannot opt out.

---

## STRIDE by component

### Cameras and NVR (Zone 1, untrusted)

| Threat | Scenario | Response |
|---|---|---|
| **S**poofing | Attacker on the camera VLAN impersonates a camera to the recorder | Out of scope: the recorder is the retailer's existing kit. SentinelFloor never trusts it. C-01 |
| **T**ampering | Firmware modification, stream injection | Assumed possible. The edge worker treats all input as untrusted data; a manipulated stream can only cause bad detections, never code execution |
| **I**nformation disclosure | Default credentials expose the live feed | Pre-existing risk, not introduced by this system. Documented for the operator (R-01) |
| **D**enial of service | Cameras taken offline | Detected as staleness, surfaced as a finding rather than absence of data. C-13 |

The honest position: cameras in small retail are frequently indefensible. The architecture
assumes they are compromised and limits what that buys an attacker.

### Edge worker

| Threat | Scenario | Response |
|---|---|---|
| **S**poofing | Rogue process posts events as a legitimate camera | Requires that camera's HMAC key. Per-camera scope limits blast radius. C-02 |
| **T**ampering | Attacker modifies the scorer to suppress real detections | Detectable only statistically, via alert-rate dispersion monitoring. Partially mitigated (R-16) |
| **R**epudiation | Edge denies having sent an event | Every event is signed and nonce-bound; audit records the camera code |
| **I**nformation disclosure | Frames or crops written to disk | Structurally prevented: no code path writes imagery, and `assert_no_imagery` fails closed. C-14. Retry queue is memory-only and bounded |
| **D**enial of service | Edge process killed | Heartbeat gap surfaces within 180 seconds. C-13 |
| **E**levation | Malicious video exploits the decoder | Real risk in OpenCV/FFmpeg. Mitigation is patching plus running the worker unprivileged in a container (R-16) |

### Core service

| Threat | Scenario | Response |
|---|---|---|
| **S**poofing | Forged events; session forgery; fob impersonation | C-02, C-03, C-05, C-08; duress rolling code (see [`05`](05-duress-device-security.md)) |
| **T**ampering | Audit rows edited or deleted to hide mishandling | Hash chain makes it detectable. C-10. Not preventable without external anchoring (C-12) |
| **R**epudiation | "I never acknowledged that alert" | Every state change audited with actor, timestamp, and source IP. C-10 |
| **I**nformation disclosure | Cross-store data leak; secrets in error bodies; enumeration | Store scope taken from session not parameters; validation errors sanitised; uniform auth failures. C-07, C-09 |
| **D**enial of service | Event flood; alert storm; unbounded queue growth | Body size cap, per-camera rate limit, bounded hub outbox with counted drops. C-06 |
| **E**levation | Assistant reaches admin functions; auditor gains operational power | Explicit role sets per route; auditor scores zero operational privilege by design. C-09 |

### Dashboard

| Threat | Scenario | Response |
|---|---|---|
| **S**poofing | Session reuse on a shared terminal | Short TTL (45 min default, 12 h hard cap), no-store caching. C-08 |
| **T**ampering | CSRF from a malicious page | SameSite=Strict plus session-bound double-submit token. C-08 |
| **I**nformation disclosure | Alert data cached on a shared device | `Cache-Control: no-store` on all non-static responses |
| **E**levation | Stored XSS in a disposition note escalates to a manager session | Jinja autoescaping, `textContent` only in JS, strict CSP with no inline script. C-15 (R-13) |

### Duress subsystem

Covered in detail in [`05-duress-device-security.md`](05-duress-device-security.md).
Summary: rolling-code HMAC with a bounded forward window, per-device secrets, tight rate
limiting, uniform failure responses, and specific causes recorded only in the audit log.

---

## Risk register

Rating is qualitative: likelihood × impact, judged for a single-site convenience store.

| ID | Risk | L | I | Rating | Controls | Residual |
|---|---|---|---|---|---|---|
| **R-01** | Camera/NVR compromise via default credentials or unpatched firmware | High | Med | **High** | C-01 | Accepted, pre-existing. Documented for operator: segment the VLAN, change defaults |
| **R-02** | Forged events injected from the camera network, causing false prompts | Med | Med | **Med** | C-02, C-03 | Low. Requires a stolen per-camera key |
| **R-03** | Replay of captured legitimate events | Med | Low | **Low** | C-04, C-05 | Low. Nonce uniqueness enforced by DB constraint; two-sided skew window |
| **R-04** | Event flooding to exhaust storage or bury staff in prompts | Med | Med | **Med** | C-06, plus zone alert budget | Low. Suppression is audited so going quiet is visible |
| **R-05** | Password spraying against the dashboard | Med | High | **High** | C-07 | **Medium.** The per-source throttle is in-memory: it resets on restart and does not span replicas. Per-account lockout in the database is the durable control. Needs Redis or reverse-proxy rate limiting before multi-instance deployment |
| **R-06** | Session hijack on a shared shop-floor terminal | Med | Med | **Med** | C-08 | Low-medium. Short sessions help; a physically accessible unlocked terminal remains exposed |
| **R-07** | Camera ingest keys stored in plaintext in the database | Med | High | **High** | C-02 (scope limiting only) | **Medium-high, accepted for this build.** Database read access yields all camera keys. Correct fix is a KMS or HSM-backed secret store with per-camera rotation. This is the most significant unmitigated technical risk and is deliberately not hidden |
| **R-08** | Duress fob replay, forgery, or counter desynchronisation | Med | High | **High** | Rolling code, bounded window, C-06 | Low. All three attack paths are tested in `tests/test_duress.py` and demonstrable via `scripts/duress_fob_sim.py` |
| **R-09** | Duress unavailable when needed: flat battery, gateway offline, RF jamming | Med | High | **High** | C-13, device health surfacing | **Medium.** One-way RF cannot be made jam-proof. Mitigation is a second channel: the dashboard duress button is independent of the fob path |
| **R-10** | Insider misuse: staff use the system to target an individual, or delete records | Low | High | **Med** | C-09, C-10, C-14 | Low-medium. Detectable after the fact, not preventable. Oversight separation means an auditor can see what a manager did |
| **R-11** | Camera tampering: lens covered, sprayed, or knocked out of alignment | Med | Med | **Med** | C-13 | Low. Obstruction bypasses the score threshold entirely and always escalates |
| **R-12** | Adversarial evasion: loose clothing, deliberate body shielding, exploiting occlusion | High | Med | **Med** | Confidence reducers | **Medium, accepted.** Evasion is straightforward for a determined offender. The system targets opportunistic loss, which is the bulk of it. Claiming otherwise would be dishonest |
| **R-13** | Stored XSS via a disposition note, escalating to a manager session | Low | High | **Med** | C-15 | Low. Three independent layers |
| **R-14** | Scope creep: an operator adds facial recognition or a cross-store watchlist | **Med** | **Very high** | **High** | C-14, C-16, governance | **Medium.** This is the largest overall risk to the project and it is not a technical one. Code-level constraints make it harder, but a determined operator can fork the repo. Only governance addresses it: DPIA sign-off, staff consultation, published policy |
| **R-15** | Discriminatory alerting: prompts concentrate on a particular group | Med | **Very high** | **High** | C-14, dispersion monitoring, blind review | **Medium.** Structurally constrained by refusing demographic input, but that same refusal removes the ability to *prove* absence of bias. See [`06`](06-evaluation-plan.md) |
| **R-16** | Physical theft of the edge box, or decoder exploit via crafted video | Low | Med | **Low-med** | Memory-only retry queue | Medium. A stolen box yields one camera key and no stored footage. Run unprivileged and containerised |

---

## Controls

| ID | Control | Where |
|---|---|---|
| **C-01** | Network segmentation: cameras on their own VLAN, core reachable only from the edge subnet and the staff network, TLS terminated at a reverse proxy | Deployment, not code |
| **C-02** | Per-camera HMAC-SHA256 ingest keys, individually revocable | [`core/models.py`](../core/models.py) `Camera.ingest_key`, [`core/security.py`](../core/security.py) `verify_edge_event` |
| **C-03** | Layered ingest validation in fixed order: body size cap → HMAC verification over canonical JSON → clock-skew window → nonce uniqueness → schema with `extra="forbid"` → fairness screen → per-camera rate limit | [`core/routers/events.py`](../core/routers/events.py) |
| **C-04** | Nonce uniqueness enforced by a database constraint on `(camera_id, nonce)`, the only place the check is atomic under concurrency | [`core/models.py`](../core/models.py) |
| **C-05** | Two-sided clock-skew window: a future-dated event is as suspicious as a stale one | [`core/util.py`](../core/util.py) `within_skew` |
| **C-06** | Sliding-window rate limits: authentication per source, ingest per camera, duress per device | [`core/security.py`](../core/security.py) `SlidingWindowThrottle` |
| **C-07** | PBKDF2-HMAC-SHA256 at 600,000 iterations with self-describing cost factor and transparent upgrade on login; per-account lockout; uniform failure responses; timing equalisation for unknown usernames | [`core/security.py`](../core/security.py) |
| **C-08** | Short sessions; `HttpOnly` + `SameSite=Strict` + `Secure`; session-bound double-submit CSRF token; pinned JWT algorithm; role re-read from database on every request so demotion is immediate | [`core/security.py`](../core/security.py) |
| **C-09** | RBAC with oversight separation: the auditor can verify the audit chain and read analytics but cannot acknowledge, resolve, change policy, or run retention | [`core/models.py`](../core/models.py) `privilege_of`, route dependencies |
| **C-10** | Hash-chained append-only audit log with three distinguishable failure modes (`hash_mismatch`, `broken_link`, `sequence_gap`); no application code path updates or deletes an entry | [`core/audit.py`](../core/audit.py) |
| **C-11** | Retention enforcement as a background sweeper, plus an on-demand route for data subject requests; truncation records its own marker containing the hash of the last removed entry | [`core/retention.py`](../core/retention.py), [`core/audit.py`](../core/audit.py) `purge_expired` |
| **C-12** | *(Not implemented — planned.)* Publish the audit chain head to external write-once storage on a schedule, so tampering is detectable even by someone with full database write access. `chain_head()` exists to support this | [`07-roadmap.md`](07-roadmap.md) |
| **C-13** | Absence-of-signal treated as signal: camera staleness after 180 s; obstruction detection bypasses the score threshold and always escalates; duress device battery and last-seen surfaced | [`core/models.py`](../core/models.py) `Camera.is_stale`, [`edge/pipeline.py`](../edge/pipeline.py) `_IntegrityMonitor` |
| **C-14** | Prohibited-feature rejection on **both** sides of the trust boundary: the edge redacts and logs an error, the core rejects the event with 422 and audits it. Recursive, so nesting does not evade it | [`core/policy.py`](../core/policy.py), [`edge/privacy.py`](../edge/privacy.py) |
| **C-15** | Layered XSS defence: Jinja autoescaping with no `\| safe` anywhere, `textContent` only in JavaScript, CSP with `script-src 'self'` and no `unsafe-inline` | [`core/middleware.py`](../core/middleware.py), [`core/static/app.js`](../core/static/app.js) |
| **C-16** | Fail-closed configuration: the application refuses to start with a placeholder secret outside debug, with debug enabled in production, bound to `0.0.0.0`, or on SQLite in production | [`core/config.py`](../core/config.py) `assert_safe_to_serve` |

---

## What is deliberately not mitigated

Stating this plainly is more useful than a document implying everything is handled.

1. **A determined offender can evade the detector** (R-12). Loose clothing and turning away
   defeat pose-based detection. The system targets opportunistic loss.
2. **Camera keys are recoverable from a database read** (R-07). Needs a KMS.
3. **The audit chain is not externally anchored** (C-12). Someone with database write access
   could rewrite the whole chain consistently. Detectable only with an off-box copy of the head.
4. **RF jamming defeats the fob** (R-09). Physics. Mitigated only by the independent dashboard path.
5. **Single-process throttle state** (R-05). Needs Redis before horizontal scaling.
6. **Demographic fairness cannot be proven** (R-15). The system refuses demographic input,
   which is correct, and that same refusal removes the ability to compute demographic parity.
   The substitute is structural monitoring plus blind human review.
7. **The largest risk is governance, not code** (R-14). Nothing in this repository stops an
   operator bolting facial recognition on. Only a DPIA, staff consultation, and published
   policy do that.

---

## Testing the controls

Every control above with a code home has a test. Notable ones:

| Control | Test |
|---|---|
| C-02, C-03, C-05 | `test_api.py::test_event_with_wrong_signature_is_rejected`, `test_stale_event_is_rejected`, `test_future_dated_event_is_rejected` |
| C-04 | `test_api.py::test_replayed_nonce_is_rejected` |
| C-07 | `test_security.py::test_repeated_failures_lock_the_account`, `test_unknown_user_and_bad_password_both_fail` |
| C-08 | `test_security.py::test_unsigned_alg_none_token_is_rejected`, `test_api.py::test_acknowledge_requires_csrf_token` |
| C-09 | `test_api.py::test_auditor_cannot_acknowledge_alerts`, `test_assistant_cannot_resolve_duress` |
| C-10 | `test_audit.py::test_editing_an_entry_is_detected`, `test_deleting_an_entry_is_detected`, `test_changing_a_timestamp_is_detected` |
| C-14 | `test_policy.py::test_prohibited_features_are_rejected_when_nested`, `test_privacy.py` (whole module) |
| Duress (R-08) | `test_duress.py::test_replayed_counter_is_rejected`, `test_forged_code_is_rejected`, `test_counter_far_ahead_is_rejected` |

Attack demonstrations that run against a live instance:

```bash
python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test --replay   # counter_replay
python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test --forge    # code_mismatch
python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test --desync   # counter_out_of_window
```

All three return HTTP 401 with an identical generic message. The specific cause appears only
in the audit log at `/api/v1/admin/audit?action=duress.rejected`, which is the separation an
attacker should not get to see.

## Pen test plan for this system

Work to do against your own deployment, in rough priority order:

1. **Ingest boundary.** Fuzz `/api/v1/events` with malformed JSON, deep nesting, huge arrays,
   duplicate keys, and unicode edge cases. Try signature verification bypasses: whitespace
   changes to canonical form, key reordering, type juggling on `raw_score`.
2. **Authentication.** Confirm no user enumeration through timing or response differences.
   Attempt JWT `alg` confusion and `kid` injection. Check lockout cannot be used to
   deliberately lock out a colleague mid-shift (a real availability concern).
3. **Authorisation.** Walk every route as each of the four roles. Attempt IDOR on alert and
   duress IDs across stores. Confirm 404 rather than 403 for foreign objects.
4. **Duress.** Beyond the three scripted attacks, try counter values at exactly the window
   boundary, negative counters, and kind substitution on a captured code.
5. **XSS.** Payloads in disposition notes, then verify CSP blocks execution even if escaping
   were bypassed.
6. **Adversarial ML.** Physically test evasion: loose coat, turning away, working at the
   occlusion boundary. Record the detection rate honestly. This is the most interesting
   section to write up and the one most people skip.
