# 8. How to talk about this work

You have an MSc in Advanced Computer Science with a data analytics specialism, and you want to
move into cybersecurity. This document is about closing that specific gap.

---

## The problem this project solves for you

A shoplifting detector, described as a shoplifting detector, reads as a computer vision project.
A security hiring manager sees "he built an ML model" and files you under data science. That is
the trap, and it is why the framing below leads with the security engineering and treats the
detection as the context it runs in.

The genuine asset is not the detector. It is that you designed a system that processes personal
data about non-consenting members of the public, in a physically insecure environment, with a
life-safety function attached, and you can talk about the threat model, the legal basis, and the
tradeoffs you accepted. That combination is uncommon at entry level.

---

## The one-sentence version

> I built a privacy-first retail loss-prevention and staff-duress platform, and treated it as a
> security engineering problem: STRIDE threat model, DPIA under UK GDPR, cryptographic design for
> the panic button, tamper-evident audit logging, and fairness constraints enforced in code rather
> than in a policy document.

Note that the detector is not mentioned. It comes up in the second sentence, as the thing being
secured.

---

## CV bullets

Pick four or five. Every one is verifiable in the repository.

**Security engineering**
- Threat modelled a physical-security convergence system using STRIDE across four trust
  boundaries; produced a 16-item risk register with mapped controls and explicitly documented
  residual risk
- Designed and implemented rolling-code authentication (HMAC-SHA256 over a monotonic counter with
  a bounded forward window) for a life-safety duress device, defeating replay, forgery, and
  counter-desynchronisation attacks; all three demonstrable and covered by tests
- Built a tamper-evident hash-chained audit log distinguishing content alteration, record
  deletion, and sequence gaps; verification exposed to a segregated auditor role that holds no
  operational privilege
- Implemented layered ingest authentication for untrusted edge devices: per-device HMAC keys,
  canonical-form signing, two-sided clock-skew windows, and database-enforced nonce uniqueness
- Hardened a web application against OWASP Top 10: PBKDF2 at 600k iterations, per-account
  lockout, session-bound CSRF tokens, pinned JWT algorithms, strict CSP, and uniform
  authentication failure responses to prevent user enumeration

**Privacy and compliance engineering**
- Completed a DPIA to UK GDPR Article 35, including a documented legitimate-interests balancing
  test and a reasoned rejection of facial recognition on ICO and EU AI Act grounds
- Enforced privacy constraints in code rather than policy: a fail-closed runtime assertion
  prevents any image or biometric data crossing the network boundary, and a recursive screen
  rejects 30 protected-characteristic attributes at both trust boundaries

**Data and evaluation**
- Built a detection-quality pipeline computing precision from operator feedback, and documented
  why recall is not computable from deployment data rather than reporting a misleading figure
- Implemented retrospective threshold-sweep analysis and structural fairness monitoring, with
  the limitations of each stated in the output

Keep one non-security bullet so the CV does not look like it is hiding the ML work:
- Implemented pose-based behavioural detection distinguishing item concealment from item
  replacement using a per-arm gesture state machine over skeletal keypoints

---

## Interview answers

### "Walk me through the project."

> I work weekends as a customer service assistant in a One Stop, which is a Tesco symbol brand.
> There is no guard on the door and the cameras are only ever reviewed after stock goes missing.
> The BRC put UK shoplifting at 5.5 million detected incidents last year, and chocolate is now
> being sold from alarmed plastic boxes, so this is not a hypothetical problem.
>
> I built a system that runs pose estimation on the existing cameras, detects the specific
> movement pattern where someone reaches to a shelf and then tucks their hand inside their body
> outline without putting anything back, and prompts whoever is on the floor.
>
> But the detection is the easy part, and Veesion and Everseen already sell it. What I actually
> spent my time on was the security and privacy engineering, because that is what makes it
> deployable rather than just functional.

Then stop and let them pick a thread. Do not deliver a monologue.

### "Why not facial recognition? It would work better."

The best question you will get. Answer it as a tradeoff, not a rule.

> It would work better, particularly against repeat offenders, who are most of the loss. I
> rejected it for four reasons.
>
> Legally, the ICO investigated Facewatch and found breaches on a considerable number of points,
> and biometric data used for identification is special category data needing an Article 9
> condition. Under the EU AI Act, biometric high-risk duties land in December 2027.
>
> Proportionality is the one that actually decides it. Legitimate interests requires a necessity
> test, and if a less intrusive method achieves the purpose then the more intrusive one is
> disproportionate by definition. Pose-only achieves the purpose.
>
> The harm profile is asymmetric. A false positive on a facial recognition watchlist means an
> innocent person is refused entry, possibly repeatedly across multiple stores. A false positive
> in mine means a colleague walks down an aisle and offers someone a basket.
>
> And it is architecturally enforced rather than promised. There is no face column, no embedding
> store, and a runtime assertion that fails closed if anything image-shaped tries to cross the
> network boundary.

### "What went wrong?"

Have real answers. Fabricated smooth projects are obvious.

> Seven substantive bugs during verification. Three are worth describing.
>
> The gesture detector silently did nothing, and the cause was that I was taking the maximum wrist
> extension across both arms. People conceal with one hand while the other stays at rest, so the
> maximum always reported the resting arm. I rewrote it as a per-arm state machine.
>
> Then it flagged everybody, because distance from the torso cannot distinguish a hand tucked at
> the waistband from an arm hanging at rest. I added a medial test: whether the wrist is inside
> the hip line. That is what actually separates concealment from a dropped arm.
>
> The one I liked most was self-inflicted. I strip facial keypoints for privacy, which zeroes five
> of seventeen points, and my occlusion estimate counted them as missing. So the privacy control
> was masquerading as a 29% occlusion penalty on every observation, quietly suppressing every
> alert in the system. A privacy control silently degrading detection quality is a nice example of
> why you verify end to end rather than trusting unit tests.

That last answer does more for you than any feature, because it demonstrates debugging under
uncertainty and an eye for second-order effects.

### "How do you know it works?"

> Precision, from staff dispositions, currently 0.44 on synthetic outcomes. And I deliberately do
> not report recall, because recall needs the count of thefts nobody saw, which is exactly what a
> store does not have. Any vendor quoting live recall is quoting a number they cannot know.
>
> For a real trial I would use three substitutes: recall on a labelled dataset reported as such,
> shrinkage correlation against stocktake, and seeded known-outcome events with the manager's
> knowledge.

### "Fairness?"

Do not claim to have solved it.

> Retail surveillance AI has a documented history of disproportionate impact, and the usual cause
> is a feature set that proxies for appearance. So I refuse those inputs architecturally: 30
> attribute names are blocked at both trust boundaries, recursively so nesting does not evade it.
>
> That has a consequence I have to be straight about. By not collecting ethnicity I have removed
> the ability to discriminate on it and also the ability to prove I did not. Demographic parity is
> not computable. Collecting it "for fairness monitoring" would mean building the exact dataset
> the design exists to avoid.
>
> What I do instead is structural: alert-rate dispersion across zones, and blind review sampling
> stratified across the whole score range rather than just the confident detections.

### "What would you do differently with more time?"

> Camera ingest keys are stored in plaintext in the database. It is risk R-07 in my register and
> the most significant unmitigated technical issue. Database read access yields every camera key.
> The fix is a KMS with per-camera rotation and an overlap window.
>
> Second, the audit chain is not externally anchored. Right now someone with database write access
> could rewrite the entire chain consistently. That is control C-12: publish the chain head to
> write-once storage on a schedule.

Naming your own worst finding, unprompted, with the remediation, is the strongest available signal
of security maturity.

---

## Roles this actually maps to

Ordered by how well the project supports the application.

| Role | Why it fits | Lead with |
|---|---|---|
| **Security engineer / AppSec (junior)** | Threat model plus hardened implementation plus tests | Ingest authentication design, OWASP controls |
| **GRC / privacy engineer** | The DPIA is a genuine differentiator; most candidates have never written one | DPIA, legitimate-interests test, EU AI Act analysis |
| **SOC analyst (L1/L2)** | Weaker until you finish phase 2 | The detection rules and SIEM work from phase 2 |
| **Detection engineering** | Once phase 2 is done, you have rules written against your own threat model | Rules mapped to your own risk IDs |
| **OT / IoT security** | The duress device is a real embedded security design | Rolling-code protocol, desync attack |
| **Retail / physical security convergence** | Unusual and directly relevant; retail, logistics, and CNI all hire for it | The whole project |
| **AI governance / responsible AI** | Growing fast, and you can speak to both the model and the regulation | Fairness enforcement, AI Act positioning |

Your data analytics MSc is an advantage in the last two, not a liability. Very few security
candidates can evaluate a model properly, and very few data scientists can threat model.

---

## What to build next, and in what order

From [`07-roadmap.md`](07-roadmap.md), the ranking for employability is:

1. **Pen test report against your own system** (phase 2). Highest value single artefact.
2. **Detection rules in a SIEM** (phase 2). Turns this into a SOC-credible project.
3. **Fix R-07 with a KMS** (phase 2). Shows you close your own findings.
4. **Real inference on consented footage** (phase 1). Makes the demo tangible.
5. **The trained model** (phase 3). Nice, but the least differentiating, because plenty of
   candidates can train a model.

Note that four of the top five are security work. That is the point.

---

## Certifications that pair with this

The project already demonstrates the practical side, so pick certifications that supply the
vocabulary and the credential filter.

- **CompTIA Security+** — clears HR filters, and much of it you can already evidence
- **ISC2 CC** — free exam, quick, useful signal
- **BCS Foundation Certificate in Data Protection** or IAPP CIPP/E — directly extends the DPIA
  work and is genuinely rare among technical candidates
- **PortSwigger Web Security Academy** — free, and complements the AppSec side of phase 2
- Skip OSCP for now. It is expensive and points at a different career track than this project.

---

## Things not to claim

Overclaiming is the fastest way to lose credibility with a technical interviewer.

- Do not call this production-ready. It is a portfolio and research build; the README says so.
- Do not claim it prevents theft. It has never run in a live store.
- Do not quote a recall figure. You will be asked how you computed it.
- Do not claim it is unbiased. Claim you constrained the inputs and monitor structurally.
- Do not imply Tesco or One Stop endorsed, reviewed, or deployed it. Say "I work in a One Stop and
  this came from a problem I saw on shift", which is true and stronger.
- Do not say you tested it on store CCTV. If you did, that is a data protection breach and saying
  so in an interview would end it.
