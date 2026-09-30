# SentinelFloor

**Helping shop-floor staff spot theft earlier, without watching customers.**

---

## The situation

A convenience store runs with two or three people on shift and no guard on the door. There are
cameras, but nobody watches them live, because everybody is serving customers. The footage gets
reviewed after the stock has already gone, which is useful for a report and useless for stopping
the loss.

The gap is not recording. It is that **nobody is watching while it happens.**

Across UK retail last year: 5.5 million detected shoplifting incidents, around £400m in stock,
and £4.2bn once you count what retailers spend trying to prevent it. Some supermarkets are now
selling Dairy Milk out of alarmed plastic boxes, which costs sales from honest customers in order
to slow down dishonest ones.

---

## What SentinelFloor does

It watches the existing cameras for one specific movement: someone reaches to a shelf, brings
their hand inside their body outline, and keeps it there instead of putting anything back.

When it sees that, it puts a short prompt on the shop-floor screen or a staff phone:

> **Possible concealment in Confectionery** — camera 2, 14:32, confidence 78%
> *Why: reached out, hand came to the body and stayed there, no item returned to the shelf*

A member of staff looks, decides, and acts. Usually that means walking over and offering a
basket, which is the single most effective and least confrontational thing anyone can do.

It also has a **staff alert button**. Press it and the whole team and the duty manager know
immediately what is happening and where, with a coded announcement if needed. Nobody is told to
confront anybody.

**This does not replace your monitored alarm.** The existing hold-up button that reaches the
alarm centre and the police stays exactly as it is, pressed and verified by people. This system
never contacts the emergency services. What it adds is the part the existing alarm cannot do:
making sure your colleagues on the other side of the shop know what is going on, and keeping a
record you can review afterwards.

---

## What it does not do

This matters as much as what it does.

| | |
|---|---|
| **No facial recognition** | It cannot recognise a face. There is no face data in the system at all |
| **No customer identities** | It does not know who anyone is and cannot tell if the same person comes back |
| **No images kept** | Video is analysed and discarded in the same instant. Nothing is stored. Ever |
| **No banned list** | It cannot record anyone as a shoplifter |
| **No automatic action** | It cannot stop a till, lock a door, or accuse anyone. A person always decides |
| **No judgement on appearance** | Age, gender, and ethnicity are not just unused — the software refuses to accept them |

It watches **movement**, not people. Think of it as a colleague who only ever says "you might
want to look over there."

---

## Why staff safety comes first

UK retail sees roughly 1,600 incidents of violence and abuse against staff every day, close to
four times pre-pandemic levels.

So the alarm is **silent by default**. The original idea was a loud alarm over the store speakers,
and that was dropped deliberately: a loud alarm tells the offender they have been spotted, turns a
quiet theft into a confrontation, and pulls staff towards it. The person standing closest is
usually the youngest colleague on shift.

Instead the alert goes quietly to the team, and every alert arrives with plain guidance:

> Approach only if you feel safe, and only in pairs. Open with a service line. Never pursue beyond
> the door. Stock is replaceable and you are not.

---

## What a store gets out of it

1. **Earlier, calmer intervention.** Offering help at the right moment prevents loss without
   confrontation.
2. **Knowing where and when loss actually happens.** The system builds a picture from your own
   store: which aisle, which hours, which days. Not an industry average.
3. **A staffing recommendation you can put on a rota.** For example: "confectionery, 15:00–17:00,
   weekdays." A visible colleague in the right aisle deters more than any camera records.
4. **A silent panic button** that reaches everyone at once.
5. **A record you can stand behind.** Every prompt and every decision is logged in a form that
   cannot be quietly altered, so a complaint can actually be investigated.

---

## Being straight about the limits

- It will sometimes be wrong. It cannot see the item, only the hands, so it cannot tell
  concealing a chocolate bar from putting a phone in a pocket. That is why a person always decides.
- Someone determined can defeat it with a loose coat or by turning away. It is aimed at
  opportunistic loss, which is most of it.
- It has never run in a live store. This is a working system, not a proven one.
- It needs someone free to look. If everyone is on the till, a prompt achieves nothing.

---

## What would be needed to try it

Nothing is connected to a real camera without permission. Before any trial:

1. **Written approval** from whoever is responsible for data protection
2. **A completed impact assessment**, drafted and ready for review
3. **Staff consulted** — they are affected more than anyone and should have a say
4. **Signage** telling customers behavioural monitoring is in use and facial recognition is not
5. **One camera, one aisle, supervised**, to see whether it helps or just gets in the way

The honest test is not whether the technology works. It is whether the staff using it find it
helpful rather than annoying. If they do not, it should not be deployed.

---

## Status

Working system: detection pipeline, alerting, staff dashboard, panic button, and analytics, with
180 automated tests and full security and data protection documentation.

Built by Ritish N., who works as a customer service assistant and noticed the problem on shift.

Technical documentation in [`docs/`](docs/). Start with
[`docs/01-problem-and-market.md`](docs/01-problem-and-market.md).
