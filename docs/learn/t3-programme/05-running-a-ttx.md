# Running an OT tabletop exercise (TTX)

> **Tier 3 / Lesson 5 — 60 minutes.**

## Why TTX is the hardest deliverable

A policy document survives as long as the printer ink. A TTX exposes whether your people, processes, and tools actually work together when stressed. It is also the artefact most likely to be requested in a NACSA s23 audit.

## The shape of an OT TTX

Different from an IT TTX in three ways:

1. **Engineering injects.** Mid-exercise, the facilitator introduces a *physical* anomaly — "the HMI says valve is closed, but the pressure gauge shows it is building". Forces the IT/OT collaboration question to surface.
2. **The IT/OT severance question is the test.** When (not if) someone proposes severing IT from OT, who has authority? How long does it take? What breaks? If the answer is fuzzy, the exercise has done its job.
3. **Plant operators must be in the room.** Not represented by IT — actually present. The IR plan is for them as much as the SOC.

## Scenario design

Pick one of the canonical incidents from [Threats](#threats/incidents) and adapt it to your sector. For example:

| Source incident | Your sector | TTX scenario |
|---|---|---|
| Ukraine 2015 | Power gen | Phishing → OT network → opening of two breakers from HMI; do operators trust HMI vs SCADA reading? |
| TRITON | Petrochemical | Engineer reports "PLC fault" — was it a routine fault, or a SIS controller probe? |
| Oldsmar | Water | HMI logs show setpoint change at 02:14 from a vendor remote session — investigate while continuing operations |
| Colonial Pipeline | Oil & gas | IT ransomware with no confirmed OT compromise — do you preventively shut down OT? Who decides? |

A scenario that isn't sector-relevant is worse than no scenario — it teaches the wrong lessons.

## Facilitation pattern (90-minute TTX)

| Time | Activity |
|---|---|
| 0–10 min | Brief participants. Establish rules of engagement (no real systems touched). State the goal explicitly: "today we test our IT/OT severance procedure". |
| 10–30 min | Initial scenario. Watch how teams *form*. Observe whether plant operations is consulted within the first 5 minutes. |
| 30–45 min | Engineering inject. Drop a physical anomaly into the scenario. Watch how teams reconcile contradictory signals. |
| 45–60 min | Decision point. Force a containment vs continuity decision. Time it. |
| 60–75 min | s26 notification rehearsal. The clock starts at detection. Walk through the actual notification template. |
| 75–90 min | Hot-wash. What worked, what didn't, what action items. |

## After-Action Review (AAR)

The TTX is worthless without the AAR. The deliverable:

| Field | Content |
|---|---|
| Scenario summary | One paragraph, no jargon |
| Decisions taken | Each decision, by whom, at what time, against what authority |
| Things that worked | Be specific |
| Things that broke | Be specific. Don't blame; describe |
| Action items | Each with owner + 90-day deadline + acceptance criteria |
| Date of next exercise | Quarterly is the published cadence target in [Pillar I](#basic-start/pillar-incident-response-planning) |

If your AAR has more than 8 action items, the scenario was too ambitious. If fewer than 3, it was too easy.

## Map to repo

- Pillar source: [B.A.S.I.C. Pillar 4 — Incident Response Planning](#basic-start/pillar-incident-response-planning)
- Threat library: [Known incidents](#threats/incidents) — pick your scenario base from here
- NACSA: s26 (notification clock practised in the scenario)

## What's next

[Checkpoint](#learn/lesson:t3-programme:06-checkpoint) — programme readiness review.
