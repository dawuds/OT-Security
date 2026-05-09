# How to use a pillar workbook

> **Tier 3 / Lesson 2 — 20 minutes.** Read once, apply ten times.

## The four-phase pattern

Every pillar in this programme follows the same shape. Learn it once, apply it to all ten.

### 1. Discover

Answer the discovery questions for *your* environment. The pillar JSON for each one (e.g., [`basic-start/framework.json`](#basic-start)) lists 4–6 environment-specific questions. Examples: "what sector?", "what's your current maturity?", "what's your tolerance for downtime?", "who is the reporting audience?".

Output: a one-page environment profile for the pillar.

### 2. Plan

Use the discovery output to draft a plan structured around the pillar's plan sections. Each plan section addresses a specific dimension (architecture, IT/OT delineation, system-specific playbooks, metrics, etc.).

This is where AI-assisted drafting earns its keep. Feed your environment profile + the pillar's plan section list into an LLM and iterate. The output is *not* final — it is a working draft you customise.

Output: a draft plan document, 4–8 pages.

### 3. Produce

Convert the plan into the **artefact** that an auditor wants to see. For most pillars this is one of:

- A policy document (e.g., backup policy, remote access policy, IAM policy).
- A standard / SOP (e.g., backup recovery sequence runbook, incident severance procedure).
- A runbook / playbook (e.g., NACSA s26 notification sequence).
- A signed register (e.g., risk register, vulnerability ledger).

The repo's [Templates](#templates) section gives you starting points for the common ones.

Output: the signed artefact in your document management system.

### 4. KPI

Each pillar has **leading** and **lagging** indicators. Leading indicators predict; lagging confirm. Pick at most 2 of each — too many KPIs becomes a reporting cult, and the data quality drops.

Output: KPIs in your dashboard, with a baseline measurement and a target.

## A worked snippet

For Pillar 1 (Backup & Recovery):

| Phase | Output |
|---|---|
| Discover | Environment profile: "Power generation plant, currently no OT backups, RPO target 24h, RTO target 4h, primary threat ransomware" |
| Plan | Backup architecture document covering 3-2-1-1-0 with OT adaptations (immutable copy in IDMZ, restoration test cadence, recovery sequencing per Purdue level) |
| Produce | (1) Backup standard SOP, signed by Plant Manager (2) Restoration test logbook, populated quarterly |
| KPI | Leading: % of Level 1 PLCs with verified backups <30 days old (target: 95%). Lagging: MTTR for critical HMIs in test (target: <4h) |

## What this pattern guarantees

Audit-readiness. By construction, each pillar produces:

- A traceable artefact (signed, dated, owned).
- A measurable indicator (with baseline + target).
- A mapping to standards (the pillar JSON cites IEC 62443 SRs, NACSA sections, and NIST CSF subcategories).

The next three lessons walk through Pillar B (Backup), Pillar I (Incident Response), and the TTX execution. After those, you can apply the pattern to the remaining seven on your own.

## What's next

[Lesson 3 — Pillar B (Backup & Recovery)](#learn/lesson:t3-programme:03-pillar-b-backup-recovery).
