# Anatomy of an OT audit package

> **Tier 4 / Lesson 1 — 30 minutes.**

> **Caveat (regulatory):** The audit pattern here is illustrative — based on common practice and the published NACSA Act 854 s23 obligation. Verify against your sector's Code of Practice and NACSA-issued audit guidance before relying on any specific procedural detail.

## What an audit package contains

A defensible OT audit package has four tightly-coupled documents. None of them stands alone.

| Document | What it is | Maintained by |
|---|---|---|
| **Work Programme** | The numbered audit procedures, organised by domain. Each procedure has objective, evidence to obtain, test steps, expected result. | Audit team |
| **PBC List** ("Provided By Client") | The artefacts the audit team requests from the auditee, by domain. The auditee's job is to produce these on schedule. | Audit team, in consultation with the auditee |
| **Finding Template** | The structured form for each finding: observation, criteria, cause, effect, recommendation, plus citation to SR + NACSA section. | Audit team |
| **Rating & Conclusion Methodology** | How findings are rated (e.g., Critical / Major / Minor) and how those roll up to a domain conclusion. | Audit team |

In this repo, the join from the framework to those documents lives in [`audit-integration.json`](../../../audit-integration.json) — open any [control detail](#controls) to see the procedure refs and file paths surfaced inline.

## Why "tightly coupled"

The four documents reference each other:

- The **work programme** procedure cites the **PBC list** items it depends on.
- The **finding template** cites the **work programme** procedure that produced the observation.
- The **rating methodology** cites the **finding template** fields it scores against.

If your finding doesn't cite the procedure, the procedure doesn't cite the PBC, or the rating doesn't cite the finding fields — you have an audit, not an audit *package*. The first time scope creeps or the team turns over, an audit without the package collapses.

## The five-day audit shape

For a single-site OT audit, the typical shape:

| Day | Activity |
|---|---|
| **Day 0 (pre)** | Issue PBC list. Get artefacts in advance. Schedule walk-throughs |
| **Day 1** | Opening meeting. Architecture walk-through (the IDMZ question). Asset inventory verification |
| **Day 2** | Network segmentation testing. Remote access review. Sample firewall rules |
| **Day 3** | Backup recovery test (in testbed only). IR plan walk-through. TTX evidence review |
| **Day 4** | Sample of controls per domain. Operator interviews. Vendor access review |
| **Day 5** | Findings drafting. Closing meeting (preliminary). Action plan review with auditee |

If you need more than 5 days, scope was wrong or the auditee is unprepared.

## The IDMZ question

Every OT audit starts with the same question: **"show me the IDMZ"**. The answer determines everything that follows. If there is no IDMZ, the entire compensating-control story changes — most other findings get rolled into the architectural one.

## Map to repo

- The audit assets are housed in the Tech-Audit repo (path published in `audit-integration.json`)
- The control-to-procedure map is in [`audit-integration.json`](../../../audit-integration.json)
- The starting templates are in [Templates](#templates)

## What's next

[Lesson 2 — Evidence-gathering by domain](#learn/lesson:t4-auditor:02-evidence-by-domain).
