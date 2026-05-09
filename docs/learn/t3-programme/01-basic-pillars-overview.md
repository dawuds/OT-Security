# The 10 pillars — sequencing and dependencies

> **Tier 3 / Lesson 1 — 30 minutes.**

## The acronym, decoded

**B.A.S.I.C.** is the foundation phase. **S.T.A.R.T.** is the maturity phase. The order is not alphabetical — it is causal.

| # | Letter | Pillar | Why this position |
|---|---|---|---|
| 1 | B | Backup & Recovery | If ransomware hits tomorrow, you need to recover. Everything else is moot if you can't. |
| 2 | A | Asset Management | You cannot protect what you cannot see. Discovery precedes every other initiative. |
| 3 | S | Secure Network Architecture | The IDMZ + zones-and-conduits is the architectural foundation for the rest. |
| 4 | I | Incident Response Planning | Before you have detection, you need a plan for when detection happens. |
| 5 | C | Continuous Vulnerability Management | OT-specific: compensating controls, not patch-everything. |
| 6 | S | Secure Remote Access | The most-exploited attack vector after 2020. |
| 7 | T | Training & Awareness | Operators are the last line. Phishing tests don't translate to OT. |
| 8 | A | Risk Assessments | Consequence-driven, integrated with HAZOP/PHA. |
| 9 | R | Real-Time Network Monitoring | Passive-only DPI of OT protocols. |
| 10 | T | Teamwork — IT/OT Partnership | Binds the rest. Without it, the other nine collapse. |

## Dependencies

Visualise as a graph:

- **Pillar 2 (Asset Management)** is the prerequisite for almost everything. If you don't know what you have, you can't backup it (1), segment it (3), monitor it (9), or assess its risk (8).
- **Pillar 3 (Secure Network Architecture)** is the prerequisite for monitoring (9) and remote access (6) — both depend on the IDMZ.
- **Pillar 4 (IR Planning)** is the prerequisite for the s26 notification flow under NACSA Act 854 — you cannot meet the clock with no plan.
- **Pillar 10 (Teamwork)** is the cross-cutting binder. Every other pillar dies in execution without it.

## Sequencing in practice

Most organisations attempt these in parallel and fail. The realistic phasing:

| Month | Focus |
|---|---|
| 1–2 | **B + A** — backup hygiene, asset inventory (passive). Get the immediate ransomware exposure down. |
| 3–4 | **S + S** — IDMZ implementation, segregate remote access through it. Architectural debt repaid. |
| 5–6 | **I** — IR plan with NACSA s26 timings; first TTX. Audit-defensible incident posture. |
| 7–9 | **C + R** — vulnerability management on the inventory; passive monitoring on the architecture. |
| 10–12 | **T + A + T** — risk assessment programme, training programme, IT/OT steering committee. The programme that survives the founder leaving. |

## Map every pillar to data in this repo

Each pillar surfaces in [B.A.S.I.C. S.T.A.R.T.](#basic-start). The pillar pages now have clickable IEC 62443 / NACSA / NIST CSF references — use them to drill into the underlying requirement, control, or cross-reference detail.

## What's next

[Lesson 2 — How to use a pillar workbook](#learn/lesson:t3-programme:02-pillar-workbook-pattern). One pattern, applied 10 times.
