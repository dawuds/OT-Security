# Pillar I — Incident Response (with NACSA s26 timing)

> **Tier 3 / Lesson 4 — 90 minutes.** Apply the 4-phase pattern. The pillar with a regulatory clock.

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

## Map to repo

- Pillar source: [B.A.S.I.C. Pillar 4 — Incident Response Planning](#basic-start/pillar-incident-response-planning)
- Domain detail: [Incident Detection and Response](#framework/domain:incident-detection-response)
- IEC 62443: SR-6.1, SR-6.2, SR-3.1
- NACSA: s26 (notification), s22 (code of practice)

## What's next

[Lesson 5 — Running an OT tabletop exercise](#learn/lesson:t3-programme:05-running-a-ttx).
