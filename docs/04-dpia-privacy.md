# 4. Data Protection Impact Assessment

Structured to UK GDPR Article 35 and the ICO's DPIA guidance.

**Status: template completed as a worked example for a demonstration deployment.** A live
deployment requires this to be completed by the actual data controller, with genuine staff
consultation, and signed off before a single camera is connected. A DPIA written by the person
who built the system is a starting point, not an approval.

---

## 1. Is a DPIA required?

Yes, and not marginally. Article 35(3)(c) requires one for systematic monitoring of a publicly
accessible area on a large scale. The ICO also lists as triggers: innovative technology,
processing of biometric data, tracking behaviour, and processing that could lead to denial of
a service.

This system involves systematic monitoring of a publicly accessible area and behavioural
analysis using novel technology. A DPIA is mandatory.

---

## 2. Describe the processing

### Nature

Existing store CCTV streams are processed on-premises. For each person in frame, a pose
estimator extracts 17 skeletal keypoints. **The video frame is then discarded.** Facial
keypoints are zeroed. Skeletal geometry over a rolling ~6-second window is analysed for a
specific movement pattern: an outward reach toward shelving followed by the hand moving inside
the body silhouette and remaining there without returning to the shelf.

When that pattern scores above a threshold, a prompt is shown to a member of staff on a
dashboard, together with a numeric breakdown of why. A human then decides whether to do
anything. The system takes no action of its own.

### Scope

| | |
|---|---|
| Data subjects | Customers and staff in camera view; staff as system users |
| Categories of data | Skeletal keypoint coordinates (transient, edge-only); derived numeric behavioural features; zone; timestamp; ephemeral per-camera track reference |
| **Explicitly not processed** | Images, video, crops or thumbnails of any kind; facial or biometric templates; names or identities; age, gender, ethnicity, or any proxy; emotion or affect; payment or loyalty data |
| Volume | One store, six cameras, roughly 250 tracked people per camera per day in the demonstration configuration |
| Retention | Behavioural events 72 hours (configurable, enforced automatically). Audit records 365 days. Frames: zero, never stored |
| Geography | On-premises. No cloud processing, no third-party transfer, no international transfer |

### Context

Data subjects are members of the public going about ordinary shopping. They have not consented
and cannot meaningfully opt out, since the alternative is not entering the shop. This
asymmetry is the reason the design is as constrained as it is.

Retail surveillance carries a documented history of disproportionate impact on particular
groups, which is why demographic input is refused at the architectural level rather than being
addressed by policy.

### Purposes

Reduce stock loss; improve staff safety by enabling earlier, calmer intervention; produce
staffing insight so that a visible member of staff can be placed where loss actually occurs.
The deterrent value of staff presence is expected to exceed the value of detection.

---

## 3. Consultation

| Group | Requirement | Status here |
|---|---|---|
| Shop-floor staff | Must be consulted before deployment. They are both users and data subjects, and a system that changes how they respond to confrontation directly affects their safety | **Not done.** Mandatory before live use |
| Data controller / DPO | Sign-off required | **Not done** |
| Customers | Informed via clear signage at entrance and in monitored aisles, stating behavioural analysis is in use and that facial recognition is not | Signage wording drafted below |
| Union representative | Where recognised (for example Usdaw in UK grocery) | Recommended |

### Draft signage

> **CCTV and behavioural monitoring in use**
> This store uses automated analysis of body movement to help staff spot potential theft.
> **We do not use facial recognition. We do not identify you. We keep no images from this
> system.** Alerts are reviewed by a member of staff, who decides what to do. No decision
> about you is made automatically.
> Data protection enquiries: [contact]. Retention: 72 hours.

---

## 4. Lawful basis

**Article 6(1)(f), legitimate interests.** Three-part test:

**Purpose test.** Preventing crime against the business and protecting staff from violence
are legitimate interests. Evidenced: 5.5 million detected shoplifting incidents and roughly
1,600 staff abuse incidents per day across UK retail (BRC, February 2026).

**Necessity test.** Passive CCTV is already present and demonstrably insufficient, since it
supports after-the-fact review rather than live intervention. Alternatives were considered:

| Alternative | Why not sufficient |
|---|---|
| Human security guard | Cost is prohibitive for a single-site convenience store. This is precisely the gap |
| Locking stock in cases | Already used; suppresses legitimate sales and degrades the shopping experience for everyone |
| Electronic article surveillance gates | Alarms only after the fact and is routinely defeated with lined bags |
| Passive CCTV only | The status quo; provides no live coverage |
| Facial recognition | Would be more effective and is **rejected** — see section 6 |

The processing is necessary, and the pose-only form is the least intrusive means that achieves
the purpose.

**Balancing test.** Weighed against the rights of data subjects:

*Reducing the impact:* no imagery retained; no identity; no biometric template; facial
keypoints discarded; 72-hour retention; no automated decision; no watchlist; no sharing with
third parties; no cross-store correlation; on-premises only.

*Residual impact:* people are subject to automated behavioural inference without consent, and
a false positive can result in being approached by staff. That is a real intrusion on dignity
and it is the reason the system biases hard toward precision, requires human assessment, and
instructs staff to open with a service line rather than an accusation.

**Conclusion:** legitimate interests is an appropriate basis for the pose-only implementation.
It would **not** support the facial recognition variant, which would require an Article 9
condition for special category biometric data.

### Article 9: not engaged

Biometric data becomes special category data when processed *for the purpose of uniquely
identifying a natural person*. This system extracts no facial template, no gait signature, and
performs no identification or matching. It cannot recognise the same person twice, by design.
Article 9 is therefore not engaged, and this is a structural property rather than a policy
commitment.

---

## 5. Necessity and proportionality measures

| Principle | How it is met | Enforced by |
|---|---|---|
| Lawfulness, fairness, transparency | Legitimate interests assessed above; signage; no covert operation; every prompt carries a human-readable rationale | `Alert.rationale` |
| Purpose limitation | Loss prevention and staff safety only. No marketing, no dwell-time analytics for merchandising, no staff productivity monitoring | Data model has nowhere to put it |
| **Data minimisation** | Frame discarded immediately after pose extraction; facial keypoints zeroed; float precision reduced before publication; only derived scalars transmitted | `edge/privacy.py`, `strip_head_keypoints`, `round_features` |
| Accuracy | Precision measured from staff outcomes; confidence reducers lower the score for occluded or fragmented observations; unreliable observations are discounted rather than ignored | `analytics/metrics.py`, `FEATURE_PENALTIES` |
| Storage limitation | 72-hour automatic purge with a background sweeper plus an on-demand route | `core/retention.py` |
| Integrity and confidentiality | Per-camera HMAC keys; TLS; RBAC; hash-chained audit; strict security headers | See [`03-threat-model.md`](03-threat-model.md) |
| Accountability | Tamper-evident audit log; independent auditor role that cannot act operationally; effective policy exposed at `/api/v1/admin/policy` | `core/audit.py`, `core/routers/admin.py` |

### Article 22: no automated decision-making

Article 22 applies to decisions based solely on automated processing with legal or similarly
significant effects. This system produces a **prompt for a human**, not a decision. It cannot
ban, detain, charge, refuse service, or record anyone as an offender. There is no code path to
any of those things.

That is why `Alert.rationale` always contains `human_review_required: true`, and why the
dashboard labels every prompt "a behavioural signal, not an accusation".

---

## 6. Facial recognition: considered and rejected

The most important decision in this document, recorded with reasons.

Facial recognition with a cross-store watchlist would materially improve effectiveness against
repeat offenders, who account for a large share of retail loss. It was rejected because:

**Legal exposure.** The ICO investigated Facewatch, a retail facial recognition provider, and
correspondence obtained under FOI showed the company had
[breached data protection law on a considerable number of points](https://bigbrotherwatch.org.uk/blog/update-big-brother-watchs-complaint-to-the-ico-on-retailer-facial-recognition/).
The ICO's own position is that there is
[a high bar for lawful use of facial recognition in public places](https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2026/07/how-data-protection-law-can-help-protect-businesses-from-crime/),
given the nature of the data and the risk of misidentification. Biometric data used for unique
identification is
[special category data requiring an Article 9 condition](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/cctv-and-video-surveillance/guidance-on-video-surveillance-including-cctv/how-can-we-comply-with-the-data-protection-principles-when-using-surveillance-systems/).

**Regulatory trajectory.** Under the EU AI Act, prohibitions and transparency duties are in
force, with high-risk obligations covering biometrics applying from
[2 December 2027 for standalone systems and 2 August 2028 for embedded ones](https://digital-strategy.ec.europa.eu/en/policies/guidelines-ai-high-risk-systems).
Emotion recognition and biometric categorisation carry specific disclosure duties. Building
pose-only keeps the system outside that regime entirely.

**Misidentification harm is asymmetric.** A false positive in a facial recognition watchlist
means an innocent person is refused entry or approached as a known thief, potentially
repeatedly and across multiple stores. The harm from a false positive here is that a member of
staff walks down an aisle and offers help.

**It is not necessary.** The necessity test above is satisfied by the less intrusive option.
Where a less intrusive means achieves the purpose, the more intrusive one is by definition
disproportionate.

**Peer-reviewed support for the alternative.** [PoseLift (WACV 2025)](https://arxiv.org/abs/2501.06591)
reports that pose-based shoplifting detection achieves high accuracy while addressing the
privacy and bias concerns inherent in appearance-based methods.

*Content rephrased for compliance with licensing restrictions.*

### Enforced in code, not just promised

`PROHIBITED_FEATURE_KEYS` in [`core/policy.py`](../core/policy.py) and
[`edge/privacy.py`](../edge/privacy.py) blocks 30 attribute names covering demographics,
biometric templates, identity, emotion, and appearance proxies. The check is recursive, so
burying `{"demographics": {"age": 31}}` one level down does not evade it. An event carrying any
of them is rejected with HTTP 422 and the attempt is audited as
`event.rejected_prohibited_feature`.

Tested in `test_policy.py` and `test_privacy.py`. If those tests ever regress, the project's
central claim is void.

---

## 7. Risks to data subjects

| Risk to individuals | Likelihood | Severity | Measures | Residual |
|---|---|---|---|---|
| Wrongly suspected of theft | Med | High | Precision-biased threshold (0.72, not 0.5); mandatory human assessment; de-escalation guidance; false positives require a written note so causes get reviewed | **Medium.** Cannot be eliminated. A visible member of staff offering a basket is the least harmful form of intervention |
| Disproportionate targeting of a group | Med | Very high | Demographic input refused architecturally; alert-rate dispersion monitoring; blind review sampling | **Medium.** Constrained but not provable — see [`06`](06-evaluation-plan.md) |
| Behavioural data retained too long | Low | Med | 72-hour automatic purge; on-demand purge route | Low |
| Re-identification by combining event data with till or loyalty records | Low | High | No customer identifier exists to join on; float precision reduced; track references are random and per-camera | Low |
| Function creep into staff performance monitoring | Med | Med | Purpose limitation; no productivity metric in the data model; response coverage is reported per store, not per person | **Medium.** Governance risk. Staff consultation should address it explicitly |
| Scope creep into facial recognition | Med | Very high | Section 6; code-level prohibition; DPIA re-run required for any change | **Medium.** Governance, not technical |
| Excessive intrusion on non-shoplifting behaviour | Med | Low-med | Prolonged dwell weighted to 0.55 and cannot alert alone; ambient grocery zone weighted *below* baseline to keep prompts off browsing shoppers | Low |

---

## 8. Data subject rights

| Right | Position |
|---|---|
| Access (Art. 15) | Honoured where the subject can be located in the data, which is usually **impossible by design**: there is no identifier to search on. The controller must explain this rather than claim compliance. Any images relevant to a request come from the retailer's existing CCTV, not from this system |
| Erasure (Art. 17) | The on-demand retention route at `/api/v1/admin/retention/run` supports prompt action. Automatic purge at 72 hours means most data self-erases |
| Objection (Art. 21) | Available since the basis is legitimate interests. The controller must have a documented process |
| Rectification (Art. 16) | Alerts carry a disposition. A subject who says a prompt was wrong should result in a `false_positive` disposition with a note, which feeds evaluation |
| Not to be subject to automated decisions (Art. 22) | Not engaged: no automated decision is made. See section 5 |

The honest position on access requests: pseudonymisation this strong means the controller
genuinely cannot identify a data subject in the behavioural record. Article 11 covers this, but
it must be explained truthfully rather than used as a shield.

---

## 9. Sign-off

| Item | Owner | Status |
|---|---|---|
| DPIA completed and reviewed | Data controller | **Outstanding** |
| DPO opinion recorded | DPO | **Outstanding** |
| Staff consultation completed | Store management | **Outstanding** |
| Signage installed | Store management | **Outstanding** |
| Retention configured and verified | System administrator | Implemented, verify per site |
| Audit chain verification scheduled | Independent auditor | Implemented, schedule per site |
| Residual risks accepted | Data controller | **Outstanding** |

**Review triggers:** any change to the feature set; any change to thresholds; any new camera
or zone; any proposal involving identity, biometrics, or cross-store data; annually regardless.

---

## Legal and regulatory sources

- [ICO guidance on video surveillance including CCTV](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/cctv-and-video-surveillance/guidance-on-video-surveillance-including-cctv)
- [ICO: complying with data protection principles when using surveillance systems](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/cctv-and-video-surveillance/guidance-on-video-surveillance-including-cctv/how-can-we-comply-with-the-data-protection-principles-when-using-surveillance-systems/)
- [ICO: how data protection law can help protect businesses from crime (2026)](https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2026/07/how-data-protection-law-can-help-protect-businesses-from-crime/)
- [ICO letter concluding the Facewatch investigation](https://ico.org.uk/media2/migrated/4031293/ic-331345-y5n0-facewatch-letter-redacted.pdf)
- [EU AI Act Article 5: prohibited practices](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-5)
- [European Commission guidelines on high-risk AI classification and timelines](https://digital-strategy.ec.europa.eu/en/policies/guidelines-ai-high-risk-systems)

*Content rephrased for compliance with licensing restrictions.*
