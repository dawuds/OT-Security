# Pillar B — Backup & Recovery (3-2-1-1-0 for OT)

> **Tier 3 / Lesson 3 — 90 minutes.** Apply the 4-phase pattern.

## Why this pillar is first

Two reasons:

1. **Ransomware exposure today.** Most plants are one phishing email away from a ransomware event. A clean, tested backup means you recover. No backup means you negotiate.
2. **Recovery sequencing matters in OT.** A PLC restored to the wrong state into a running process is more dangerous than the original attack. Standard IT backup playbooks don't say this. Yours must.

## Discover

Your discovery profile (one page, written before any plan):

- **Sector & site** — Power gen, water treatment, oil refinery, manufacturing? What's the worst-case physical consequence?
- **Asset classes in scope** — PLCs (logic + setpoints), HMIs (full OS), SCADA servers, historians, engineering workstations, SIS controllers.
- **Tolerance for downtime** — minutes (continuous process), hours (batch), days (manual fallback exists).
- **Current state** — no OT backups, ad-hoc backups on local USB, scheduled backups but never tested.
- **Threats of concern** — ransomware (most common), insider, hardware failure, natural disaster.
- **Reporting audience** — Plant Manager (uptime), Board (ransomware resilience), NACSA Auditor (s23 evidence).

## Plan — the OT 3-2-1-1-0 architecture

Adapt the IT 3-2-1 to OT with two extra digits:

| Number | What it means in OT |
|---|---|
| **3** copies | Primary (HMI/EWS), backup (IDMZ server), archive (offline media) |
| **2** media types | OT-rated NAS for warm; tape or write-once optical for cold |
| **1** off-site | Via data diode or IDMZ-hosted SFTP — never direct from OT |
| **1** immutable / offline | Air-gapped or write-once. Ransomware cannot reach it |
| **0** errors (verification) | Automated hash verification + scheduled restore test in isolated testbed |

Plan sections (each becomes a chapter in the deliverable):

1. **Architecture** — the 3-2-1-1-0 layout with explicit Purdue-level placement.
2. **IT/OT delineation** — where shared IT backup infrastructure can be leveraged; where OT must remain isolated.
3. **System-specific playbooks** — separate playbook per asset class (PLC, HMI, SCADA, historian).
4. **Recovery workflow** — the sequence (network → SCADA/DCS → PLCs → historian) and the decision tree (restore vs rebuild).
5. **Metrics** — leading + lagging KPIs.

## Produce — the artefacts

| Artefact | Owner | Audience |
|---|---|---|
| Backup standard SOP | OT Security Engineer | Plant Operations, IT, Auditor |
| Recovery runbook (per asset class) | OT Engineer | Plant operators (used during incident) |
| Restoration test logbook | OT Security Engineer | Plant Manager, Auditor |
| Vendor / supply chain register for backup tooling | Procurement + OT Security | Auditor |

For the SOP, start from a template — the IT-side template won't cover the OT specifics, but it gives you the document structure.

## KPI

| Type | KPI | Target |
|---|---|---|
| Leading | % of Level 1 PLCs with verified logic backups in the last 30 days | 95% |
| Leading | % of SCADA server backups with successful automated hash verification this month | 100% |
| Lagging | MTTR for critical HMIs during testbed simulations | <4h |
| Lagging | Number of failed restoration tests requiring plan update | trending down quarter-on-quarter |

## Map to repo

- Pillar source: [B.A.S.I.C. Pillar 1 — Backup & Recovery](#basic-start/pillar-backup-recovery)
- Domain detail: [Backup and Recovery domain](#framework/domain:backup-recovery)
- IEC 62443: SR-7.3, SR-7.6, SR-7.7
- NACSA: s21 (risk assessment), s22 (code of practice)

## What's next

[Lesson 3a — Pillar A (Asset Management)](#learn/lesson:t3-programme:03a-pillar-a-asset-management). With Backup in place, build the inventory that unblocks Network Architecture, Vulnerability Management, and everything that follows.
