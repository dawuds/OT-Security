# Pillar I — Incident Response (with TTX + NACSA s26 timing)

> **Tier 3 / Lesson 4 — 2 hours.** Apply the 4-phase pattern. The pillar with a regulatory clock — and the only pillar where the artefact (the IR plan) is meaningless without rehearsal (the TTX).

> **Caveat (regulatory):** NACSA Act 854 timings cited in this lesson are illustrative based on the published Act. Verify against the official Federal Gazette and your sector's Code of Practice before relying on any specific clock.

## Why this pillar matters now

Two reasons:

1. **The triage order is reversed.** The IR plan must put physical safety first, process availability second, data confidentiality third. An IT-flavoured IR plan applied in OT will optimise for the wrong outcome at the worst time.
2. **The s26 clock starts at detection.** For NACSA-designated NCII operators in Malaysia, incident notifications have a documented timeline. You cannot meet a clock you haven't rehearsed.

## Discover

- **Sector** — drives historical threat intelligence (which TTPs to model).
- **Current IR maturity** — no formal plan, an IT plan reused for OT, or a dedicated and tested OT plan.
- **Stakeholder engagement** — do plant managers and safety engineers participate in cyber planning?
- **Containment authority** — can you physically or logically sever IT-OT without halting production? Who has the authority?
- **Reporting audience** — Plant Manager, Board, Regulators (NACSA s26).

## Plan — SANS Top 5 + OT-specific extensions

The plan structure:

1. **Sector-specific threat intelligence** — top 3–4 historical OT incidents in your sector, with kill chains. Map to MITRE ATT&CK for ICS techniques.
2. **The OT IR plan** — ICS-specific triage (safety > availability > integrity > confidentiality); IT/OT severance protocol with explicit authority; passive PCAP investigation procedures (no active scanning of PLCs); secure remote access lockdown playbook.
3. **NACSA s26 notification flow** — initial / supplementary / final notification timing (per published Act; verify against sector COP for sector-specific overlays).
4. **TTX programme** — cyber-physical scenarios with engineering injects.

## Produce — the artefacts

| Artefact | Owner | Audience |
|---|---|---|
| Cyber Incident Response Plan (CIRP) | OT Security Lead + Plant Manager | All operators, IT, Legal, NACSA |
| s26 notification runbook (with template messages) | OT Security Lead | NACSA, Sector Lead |
| IT/OT severance procedure (with named authority) | Plant Manager | Operators, IT, Vendors |
| TTX scenario library (sector-specific) | OT Security Lead | TTX participants |
| AAR template (after-action review) | OT Security Lead | Steering Committee |

The starting point template: [`04-cyber-incident-response-plan`](#templates/view:04-cyber-incident-response-plan).

## KPI

| Type | KPI | Target |
|---|---|---|
| Leading | % of plant operators participated in OT TTX in last 12 months | 100% |
| Leading | IT/OT severance execution time during quarterly drill (minutes) | published target per sector COP |
| Lagging | Mean Time to Detect (MTTD) anomaly in OT environment | trending down |
| Lagging | Time from detection → NACSA notification during drill | within published Act 854 s26 clock |
| Lagging | TTX action items closed within 90 days | >80% |

## The thing IT analysts get wrong

In an IT incident, you preserve evidence, then contain. In an OT incident, you stabilise the process first — even if that destroys forensic evidence. A live process that's about to over-pressurise doesn't wait for chain-of-custody. The plan must say this out loud.

---

## Running the TTX (the rehearsal that proves the plan exists)

A policy document survives as long as the printer ink. A TTX exposes whether your people, processes, and tools actually work together when stressed. It is also the artefact most likely to be requested in a NACSA s23 audit.

### What makes an OT TTX different

Three differences from an IT-flavoured TTX:

1. **Engineering injects.** Mid-exercise, the facilitator introduces a *physical* anomaly — "the HMI says valve is closed, but the pressure gauge shows it is building". Forces the IT/OT collaboration question to surface.
2. **The IT/OT severance question is the test.** When (not if) someone proposes severing IT from OT, who has authority? How long does it take? What breaks? If the answer is fuzzy, the exercise has done its job.
3. **Plant operators must be in the room.** Not represented by IT — actually present. The IR plan is for them as much as the SOC.

### Scenario design — pick from real incidents

Pick a canonical incident from [Threats](#threats/incidents) and adapt it to your sector. Examples:

| Source incident | Your sector | TTX scenario |
|---|---|---|
| Ukraine 2015 | Power gen | Phishing → OT network → opening of two breakers from HMI; do operators trust HMI vs SCADA reading? |
| TRITON | Petrochemical | Engineer reports "PLC fault" — was it a routine fault, or a SIS controller probe? |
| Oldsmar | Water | HMI logs show setpoint change at 02:14 from a vendor remote session — investigate while continuing operations |
| Colonial Pipeline | Oil & gas | IT ransomware with no confirmed OT compromise — do you preventively shut down OT? Who decides? |
| **Monterrey 2026** | Water | IT SOC detects two rounds of failed password-spray against the vNode SCADA management interface from an internal IT host. Authentication held. (a) How did the SCADA interface become reachable from IT? (b) What would have happened if the password had been weaker? (c) AI-augmented recon means the attacker did not need OT expertise — does your IT-side telemetry catch unprompted SCADA enumeration? |

A scenario that isn't sector-relevant is worse than no scenario — it teaches the wrong lessons.

### Facilitation — the 90-minute shape

| Time | Activity |
|---|---|
| 0–10 min | Brief participants. State the goal explicitly: "today we test our IT/OT severance procedure". |
| 10–30 min | Initial scenario. Watch how teams *form*. Observe whether plant operations is consulted within the first 5 minutes. |
| 30–45 min | Engineering inject. Drop a physical anomaly into the scenario. Watch how teams reconcile contradictory signals. |
| 45–60 min | Decision point. Force a containment vs continuity decision. Time it. |
| 60–75 min | s26 notification rehearsal. The clock starts at detection. Walk through the actual notification template. |
| 75–90 min | Hot-wash. What worked, what didn't, what action items. |

### After-Action Review (AAR) — the deliverable

The TTX is worthless without the AAR:

| Field | Content |
|---|---|
| Scenario summary | One paragraph, no jargon |
| Decisions taken | Each decision, by whom, at what time, against what authority |
| Things that worked | Be specific |
| Things that broke | Be specific. Don't blame; describe |
| Action items | Each with owner + 90-day deadline + acceptance criteria |
| Date of next exercise | Quarterly cadence |

If your AAR has more than 8 action items, the scenario was too ambitious. If fewer than 3, it was too easy.

## Map to repo

- Pillar source: [B.A.S.I.C. Pillar 4 — Incident Response Planning](#basic-start/pillar-incident-response-planning)
- Domain detail: [Incident Detection and Response](#framework/domain:incident-detection-response)
- Threat library for scenarios: [Known incidents](#threats/incidents)
- IEC 62443: SR-6.1, SR-6.2, SR-3.1
- NACSA: s26 (notification), s22 (code of practice), s23 (audit — TTX evidence)

## What's next

[Checkpoint](#learn/lesson:t3-programme:06-checkpoint) — programme readiness review.
