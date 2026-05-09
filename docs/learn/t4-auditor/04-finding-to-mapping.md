# Writing a finding that maps to SR + NACSA

> **Tier 4 / Lesson 4 — 45 minutes.**

## What separates a finding from a complaint

A complaint says "this is bad". A finding says **"this fails criterion X, the cause is Y, the effect is Z, and the recommendation is W"** — with citations.

The structured form (the **finding template** in the audit package) enforces this:

| Field | Content |
|---|---|
| **Observation** | What you saw, factually. No opinion, no jargon. "On 2026-04-15, sample firewall rule ID 4421 permits any-source TCP/502 to the Level 1 PLC subnet 10.20.30.0/24." |
| **Criteria** | The standard / regulation it fails against, *cited*. "IEC 62443-3-3 SR-5.1; NACSA Act 854 s18; internal Network Segmentation Policy v1.2 cl. 4.3." |
| **Cause** | Why the gap exists. "Rule was created during 2023 commissioning by vendor; no documented review since." |
| **Effect** | The consequence — physical, regulatory, financial. "Any IT-side compromise can write Modbus function codes to the PLC, including coil writes that affect process state. Worst case: process upset analogous to Oldsmar 2021." |
| **Recommendation** | What to do, specifically. "Restrict source to IDMZ jump server IP only; add OT-aware DPI to permit only function codes 1-4 (read); enter into firewall rule review cycle with 90-day cadence." |
| **Rating** | Per the rating methodology. "Major — direct exploitable path to control system, no compensating control." |
| **Owner & deadline** | "OT Security Engineer; remediation by 2026-06-30; verification by re-test." |

## Why the citations are non-negotiable

Three reasons:

1. **The auditee can argue an opinion. They cannot argue a citation.** "Your firewall rule violates SR-5.1" is a different conversation from "your firewall rule looks risky".
2. **The citation tells the auditee what they're *complying with*, not just what they're failing.** That is what makes the recommendation actionable.
3. **The citation enables roll-up.** Every finding citing SR-5.1 means SR-5.1 is a programme-wide weakness — not 20 unrelated incidents.

## The bidirectional citation

Every finding must cite at least:

- **One IEC 62443 SR** (the engineering standard).
- **One NACSA Act 854 section** (the legal basis — for Malaysian NCII).

Optional, but valued:

- **NIST CSF 2.0 subcategory** (for organisations using CSF as their reference).
- **MITRE ATT&CK for ICS technique** (for findings that explicitly enable an adversary technique).
- **Sector COP clause** (where the sector COP elaborates on the Act).

The repo's [cross-reference layer](#reference) gives you the join — every IEC 62443 SR is mapped to NACSA, NIST CSF, and NIST 800-82, so the citations write themselves once you've identified the SR.

## Self-check

Before you submit a finding, check:

- [ ] Observation is factual (no "we believe", "we suspect", "appears to be").
- [ ] Criteria cite at least one SR + one NACSA section.
- [ ] Cause is actionable (not "the system is bad").
- [ ] Effect references a physical or regulatory consequence, not just a CVSS score.
- [ ] Recommendation is implementable in <90 days OR documents a compensating control.
- [ ] Rating is justified by the methodology.
- [ ] Owner is named (a role, ideally a person).
- [ ] Re-test method is specified.

If any box is unchecked, the finding is not done.

## Map to repo

- The finding template lives in the Tech-Audit repo (path published in `audit-integration.json`).
- The cross-reference data: [`cross-references/`](#reference) — five files joining SRs to NACSA, NIST CSF, NIST 800-82, MITRE, and sector COPs.

## What's next

[Checkpoint](#learn/lesson:t4-auditor:05-checkpoint) — produce a complete audit package.
