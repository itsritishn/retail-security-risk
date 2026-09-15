# 5. Duress device security design

The panic button is the only life-safety function in this system. If detection fails, stock
goes missing. If duress fails, somebody gets hurt. It is therefore specified in more detail
than anything else here.

---

## The design change, and why

The original concept was a remote that, when pressed, sounded an alarm through the store's
public address system so that "everyone gets activated".

**That was reversed.** The reasoning is the most defensible decision in the project.

UK retailers recorded roughly 1,600 incidents of violence and abuse against staff per day in
the BRC's February 2026 survey, close to four times the pre-pandemic rate
([BRC via Retail Technology Innovation Hub](https://retailtechinnovationhub.com/home/2026/2/23/investment-pays-off-as-progress-is-made-on-tacking-retail-crime-but-job-far-from-done-brc)).
*Content rephrased for compliance with licensing restrictions.*

A loud public alarm does four harmful things at once:

1. **It tells the offender they have been detected**, converting a quiet theft into a
   confrontation, and the person nearest that confrontation is a member of staff.
2. **It draws staff toward the incident** rather than away from it, which is the opposite of
   what safety guidance advises.
3. **It puts the decision to escalate in the hands of whoever pressed the button**, usually the
   most junior person present and the one under most stress.
4. **It desensitises everyone.** After the third false alarm nobody moves.

Established retail practice runs the other way: silent alerts to a mobile device, plus coded
verbal announcements that mean something to briefed staff and nothing to a customer. The
"Would Mr Sands please come to the front of store" convention exists precisely because it
communicates without escalating.

So the default is: **silent alert to every signed-in device, plus an optional coded
announcement.** The public broadcast path still exists, because there are situations where
clearing a store loudly is correct, but it is off by default, must be explicitly enabled in
configuration, and is restricted to threat-to-person activations only.

```python
PUBLIC_BROADCAST_ELIGIBLE = frozenset({DuressKind.THREAT.value})
```

A suspected theft can never trigger a store-wide alarm, no matter what an operator configures.
Tested in `test_duress.py::test_public_broadcast_is_restricted_to_threat_events`.

---

## Threat model for the fob

| Threat | Attack | Consequence | Control |
|---|---|---|---|
| **Replay** | Capture the RF transmission with an SDR, retransmit later | Attacker summons staff to a chosen location, or fabricates incidents to desensitise them | Monotonic counter; a used counter is rejected |
| **Forgery** | Craft a transmission without the secret | Same as replay, at will | HMAC-SHA256 under a per-device secret |
| **Kind substitution** | Replay a captured "medical" press as "threat" | Wrong response mobilised | Activation kind is bound into the MAC |
| **Counter desynchronisation** | Send a counter far ahead of the real fob | **Silently disables the fob.** The real device's counters now all appear used | Bounded forward window (32 steps) |
| **Cross-device replay** | Use one fob's code on another serial | Impersonation | Per-device secrets; a code is bound to its serial |
| **Serial enumeration** | Probe serials to find valid ones | Reconnaissance for targeted attack | Uniform 401 for unknown device and bad code alike |
| **Flooding** | Repeated activations | Alert fatigue on a life-safety channel | Rate limit: 6 per device per minute |
| **Jamming** | Block the RF band | Fob unavailable | **Not solvable.** Mitigated by an independent dashboard path |
| **Battery exhaustion** | Passive failure | Fob silently dead | Battery level and last-seen surfaced; `needs_attention` flag |

Desynchronisation deserves emphasis. It is the most damaging attack because it is *quiet*.
Replay and forgery create noise that someone notices. Desync leaves a member of staff pressing
a button that does nothing, with no indication of failure, in exactly the situation the button
exists for. That is why the forward window is bounded rather than open-ended.

---

## Protocol

### Fob to gateway (RF, one-way)

```
serial ‖ counter ‖ kind ‖ MAC
where MAC = HMAC-SHA256(device_secret, "serial:counter:kind")  truncated to 128 bits
```

The counter increments on every press and is held in non-volatile memory on the device.
Truncating the MAC to 128 bits keeps the payload inside a typical low-power radio frame while
leaving a security margin far beyond what a brute-force attacker could exploit within the
lifetime of a fob.

### Gateway to core (HTTPS)

```http
POST /api/v1/duress/fob
Content-Type: application/json

{ "serial": "FOB-TILL-01", "counter": 42, "kind": "threat", "code": "<32 hex chars>" }
```

The gateway is a relay. It holds no secrets and makes no decisions, so compromising it yields
nothing beyond the ability to forward frames it could already hear.

### Verification, in order

From [`core/duress.py`](../core/duress.py):

```python
if not device.enabled:                          reject "device_disabled"
if counter <= device.counter:                   reject "counter_replay"
if counter >  device.counter + window:          reject "counter_out_of_window"
if not constant_time_equals(code, expected):    reject "code_mismatch"
```

Order matters. The cheap integer comparisons come before the HMAC computation, so an attacker
flooding the endpoint cannot force expensive work per request. Comparison of the MAC is
timing-safe.

### Why the counter must move strictly forward

Accepting `counter == device.counter` permits straightforward replay. Accepting an unbounded
jump permits desynchronisation. The window is the compromise: 32 steps tolerates a fob whose
button was pressed while out of range, or a gateway that was offline, without allowing an
attacker to burn the counter space.

---

## Escalation policy

Activation kinds and what each does:

| Kind | Notifies | Coded announcement | Public broadcast |
|---|---|---|---|
| `threat` | Assistants, duty manager, admin | "Would Mr Sands please come to the front of store." | Eligible, disabled by default |
| `theft_in_progress` | Assistants, duty manager | "Customer service assistance required, aisle team." | Never |
| `medical` | Assistants, duty manager, admin | "First aider to the shop floor, please." | Never |
| `test` | Duty manager only | None | Never |

**A threat activation notifies assistants, not just management.** A duress alert that reaches
only the duty manager fails when the duty manager is the person in trouble. Tested in
`test_duress.py::test_threat_notifies_everyone_including_assistants`.

Coded announcements are checked in tests to contain none of the words "theft", "shoplift",
"steal", "police", "threat", or "attack", so a customer overhearing one learns nothing.

---

## Staff guidance, delivered with the alert

An alarm that tells someone something is wrong but not what to do is close to useless when
adrenaline is up. Every activation carries guidance written to be read in about three seconds.

For a threat to a person:

> - Do not confront. Put a counter or shelving between you and the person.
> - Keep the exit clear. Never block a doorway or follow anyone outside.
> - Call 999 if anyone is in immediate danger. Say the store name and address first.
> - Note clothing and direction of travel only when it is safe to do so.
> - Move colleagues and customers away from the area rather than toward it.

For a theft in progress:

> - Approach only if you feel safe, and only in pairs.
> - Open with a service line: offer a basket or ask if they need help finding anything.
> - Do not touch the person, their bag, or their trolley.
> - Never pursue beyond the door. Stock is replaceable and you are not.
> - Log the outcome afterwards so the detection can be tuned.

Every line pushes toward de-escalation. Tests assert that the threat guidance contains "do not
confront" and a 999 reference, and that the theft guidance contains "never pursue". These are
safety requirements, so they are enforced like any other requirement.

---

## Authorisation model

| Action | Assistant | Duty manager | Admin | Auditor |
|---|---|---|---|---|
| Raise duress | Yes | Yes | Yes | No |
| Acknowledge | Yes | Yes | Yes | No |
| **Resolve (stand down)** | **No** | Yes | Yes | No |
| View device health | No | Yes | Yes | No |

An assistant can raise and acknowledge but cannot declare the incident over. Someone standing
inside an incident is not well placed to judge that it has ended, and the person who called for
help should not be the one under pressure to say everything is fine. Tested in
`test_api.py::test_assistant_cannot_resolve_duress`.

---

## Hardware notes for a real build

Not implemented here; the simulator stands in for the radio path. What a real build needs:

| Component | Choice | Reasoning |
|---|---|---|
| Radio | LoRa 868 MHz (EU) or 433 MHz | Range through a steel-shelved building; low power |
| Fob MCU | Any with secure key storage, e.g. ATECC608 or an nRF52 with APPROTECT | The secret must not be readable over a debug interface, which is how most cheap fobs fail |
| Counter storage | Internal flash with wear levelling | Losing the counter bricks the fob |
| Battery | CR2032 with voltage reporting on each transmission | Silent battery death is a life-safety failure |
| Provisioning | Secret generated on-device, public half registered; or injected in a controlled environment and never stored elsewhere | Currently the seeder generates it, which is why R-07 applies here too |
| Test schedule | Weekly `test` activation, logged | An untested life-safety control is not a control |

### Known gaps in the current implementation

1. **Device secrets stored in plaintext** in the database, same as camera keys (R-07). Needs a
   KMS or an HSM.
2. **No RF layer.** The simulator posts directly to the endpoint. A real gateway needs its own
   authenticated channel to the core so it cannot be impersonated on the LAN.
3. **No dead-man detection.** A fob that stops transmitting entirely is only visible through
   `last_seen_at`. Periodic keep-alives would let the system flag a dead fob proactively.
4. **Rate limit is in-memory** (R-05), so it resets on restart.

---

## Demonstrating it

```bash
# Legitimate activation: accepted, silent, with guidance
python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind threat --zone confectionery

# Three attacks, all rejected with an identical generic 401
python -m scripts.duress_fob_sim --serial FOB-TILL-01 --kind test --replay
python -m scripts.duress_fob_sim --serial FOB-FLOOR-01 --kind test --forge
python -m scripts.duress_fob_sim --serial FOB-FLOOR-01 --kind test --desync
```

Verified output from a live run:

| Scenario | HTTP | Audited reason |
|---|---|---|
| Legitimate | 200 | `duress.activated`, silent, coded announcement issued |
| Replay | 401 | `counter_replay` (presented 1, stored 1) |
| Forged code | 401 | `code_mismatch` |
| Desync | 401 | `counter_out_of_window` (presented 5000, stored 0) |

The API response is identical in all three failure cases. The specific cause is available only
to an admin or auditor at `/api/v1/admin/audit?action=duress.rejected`. That separation between
what an attacker learns and what an operator learns is the point.
