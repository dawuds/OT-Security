# Evidence-gathering by domain

> **Tier 4 / Lesson 2 — 60 minutes.**

## The 30-minute-per-domain target

Across the 13 domains, you have ~6.5 hours of audit time. That's 30 minutes per domain. To hit it, you need a structured approach that doesn't waste time on rabbit holes.

The repo's [`evidence/index.json`](../../../evidence/index.json) lists 36 evidence items across 13 domains, each with three fields you exploit:

| Field | What it does for you |
|---|---|
| `whatGoodLooksLike` | The acceptance criteria — if the artefact matches, log "satisfied" and move on |
| `commonGaps` | The likely failure modes — check these first; they're where most findings come from |
| `howToVerify` | The procedure — what to actually do (review document / observe / test / interview) |

## The pattern, applied per domain

For each domain, in 30 minutes:

1. **5 min — request the artefact.** Already on the PBC list; just confirm receipt.
2. **10 min — check against `whatGoodLooksLike`.** If it matches, log evidence ID, mark satisfied, move to the next item in the domain.
3. **10 min — probe the `commonGaps`.** Specifically test the failure modes the field flags.
4. **5 min — log finding (if any).** Use the finding template; cite the SR + NACSA section.

## A worked example — Network Segmentation

Domain: [Network Segmentation](#framework/domain:network-segmentation). Evidence items (from `evidence/index.json`): network topology diagram, firewall rule register, IDMZ architecture diagram, firewall rule review records.

| Time | Action |
|---|---|
| 0–5 min | Confirm the four artefacts are in PBC return |
| 5–15 min | Topology diagram: IDMZ present? OT-side & IT-side firewalls clearly separate? Zones labelled with SL-T? — `whatGoodLooksLike` |
| 15–25 min | Sample 5 firewall rules at random. For each: business justification documented? Last reviewed in last 90 days? Any "any/any" rules? — `commonGaps` |
| 25–30 min | Log finding (if any), with citation: NS-R2 / SR-5.1 / NACSA s18 |

Repeat for the other 12 domains. By end of Day 3 you have a populated finding draft.

## What "good evidence" actually looks like

For each domain, the auditor's mental model:

- **Network segmentation** — diagram + firewall rules + 90-day review records.
- **Remote access** — JIT provisioning logs + session recording samples + vendor onboarding form.
- **Patch / vuln management** — vulnerability ledger with compensating controls; not "patch list".
- **IAM** — privileged-account inventory + MFA enforcement evidence + dormant-account report.
- **Incident response** — CIRP signed; TTX AAR with closed actions; s26 notification template.
- **Supply chain** — vendor risk assessments; software hash verification logs; component register.
- **Physical security** — visitor logs + camera retention policy + tamper-detection records.
- **SIS** — SIS isolation evidence (network diagram + physical inspection); program checksum verification logs.
- **Asset inventory** — passive discovery tool reports; asset register reconciled monthly.
- **Configuration management** — baseline configs + change records + drift detection alerts.
- **Backup & recovery** — restoration test logbook (the *test*, not the backup); RTO/RPO compliance.
- **Monitoring & logging** — log retention vs s26 timing; SIEM use-case catalogue; FP/TP ratio.
- **Data protection** — data classification register; encryption inventory; secure disposal records.

## Map to repo

- Evidence schema: [`evidence/index.json`](../../../evidence/index.json)
- Domain-by-domain detail: [Framework → Domain Requirements](#framework/domains)
- The 36-item index: surfaced inline on each [control detail](#controls) under "Audit Package"

## What's next

[Lesson 3 — Walking the FAT/SAT checklist](#learn/lesson:t4-auditor:03-fat-sat-walkthrough).
