# Checkpoint — Produce an audit package

> **Tier 4 / Lesson 5 — 2 hours.** The capstone exercise.

## The exercise — pick one of two paths

### Path A — your own sector

Pick a sector you have not yet worked in. Open that sector's profile in [Sectors](#framework/sectors). Your job: produce a *complete*, end-to-end audit package — as if you were preparing to audit a fictional NCII operator in that sector tomorrow.

### Path B — the broken plant (recommended for first attempt)

Use the [SABESB TP4 broken-plant bundle](../samples/00-README.md). The bundle gives you the asset list, network diagram, remote-access policy, and a fake auditor's draft report. Your job: produce **your own audit package** for SABESB TP4 — and grade the fake report's findings (correct / miscited / wrong / missing).

The advantage of Path B: there's an answer key. You can calibrate your finding-writing against a known-good baseline before you do this on a real engagement.

## Required deliverables

| Deliverable | Source / template |
|---|---|
| **PBC List** — sector-customised, by domain | Use the Tech-Audit PBC template + the [13 domains](#framework/domains) |
| **Work Programme excerpt** — pick 3 domains, write 5 procedures per domain | Use the procedure refs in [`audit-integration.json`](../../../audit-integration.json) as a starting point |
| **5 worked findings** — one per domain you chose, plus 2 cross-cutting | Use the finding template; cite SR + NACSA section per finding |
| **Rating roll-up** — domain conclusions + overall opinion | Use the rating methodology |
| **Cover memo** — 1 page, executive-grade | Plain English; risk-based language |

## Self-grading rubric

| | Pass | Fail |
|---|---|---|
| PBC list | Sector-specific items present (e.g., NACSA sector COP clauses, sector-specific OT protocols) | Generic PBC indistinguishable from any sector |
| Work programme | Each procedure has objective, evidence sought, test step, expected result | Procedures are aspirational rather than testable |
| Findings | Each cites SR + NACSA section; observation is factual | "Risk of …" findings (= speculation) |
| Rating | Roll-up is consistent with methodology | Inflated ratings to look thorough |
| Cover memo | Exec can read in 5 minutes and act on it | More than 1 page, jargon-heavy |

If 4 of 5 pass, you have completed the learning path.

## What you can now do

- Run a 5-day OT audit start to finish.
- Produce findings that survive an auditee disagreement meeting.
- Map every finding to its IEC 62443 SR and its NACSA section.
- Hand over an audit package that the next auditor can pick up cold.

## Beyond this

The path forward is *engagement-driven*. Each new sector, each new asset class, each new vendor will sharpen the rubric. The data layers in this repo are the substrate; what you do on top of them is the craft.

## Map to repo (full circle)

- [Framework](#framework) for the standards
- [Controls](#controls) for the implementations
- [Domains](#framework/domains) for the requirements
- [Threats](#threats) for the consequences
- [Templates](#templates) for the policy starting points
- [Risk Management](#risk) for the residual risk register
- [Reference](#reference) for the cross-mappings
- [B.A.S.I.C. S.T.A.R.T.](#basic-start) for the AI-assisted programme building

You started in T1 not knowing the Purdue model. You finish T4 able to audit a Purdue-segmented plant, write findings that cite the standard and the law, and produce a deliverable an executive will sign.

That is the journey this repo was built for.
