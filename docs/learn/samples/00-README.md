# The "Broken Plant" — canonical worked example

> A deliberately-flawed reference environment used as the worked substrate across **T2 (Practitioner)**, **T3 (Programme Builder)**, and **T4 (Auditor)**. One artefact, three tiers of leverage. Every flaw in this bundle is *intentional* and is exactly the kind of thing an auditor will find on a real plant.

## The fictional plant

**SABESB Treatment Plant 4** — a fictional water treatment facility in a fictional Malaysian state, used purely as illustration. ~50,000 customers served. Mid-size. The kind of plant a junior auditor would visit on day three of a five-day engagement.

> **No real organisation.** "SABESB" is a play on the name pattern of Malaysian water concessionaires (SABESB ≠ SAB ≠ JBA ≠ SPAN). Names of people in the policies are fictional. None of this is a real plant or real plan.

## What's in the bundle

| File | What it is | Used in |
|---|---|---|
| [`01-asset-list.csv`](01-asset-list.csv) | A 12-row asset inventory from "passive scan" — with three deliberate Purdue / segmentation issues | T2 Lessons 1, 3 + T3 Pillar A checkpoint + T4 Lesson 2 |
| [`02-network-diagram.md`](02-network-diagram.md) | ASCII-art network diagram showing the IDMZ design (or lack thereof) — with three deliberate IDMZ violations | T2 Lesson 4 + T3 Pillar S checkpoint + T4 Lesson 1 |
| [`03-bad-remote-access-policy.md`](03-bad-remote-access-policy.md) | A remote-access policy that *looks* compliant but fails on six specific OT criteria | T2 Lesson 5 + T4 Lesson 3 |
| [`04-fake-audit-report.md`](04-fake-audit-report.md) | A draft audit report with five findings — two correct, two miscited, one missing | T4 Lessons 2, 4 + T4 checkpoint |
| [`05-answer-key.md`](05-answer-key.md) | The complete answer key. **Don't read until you've worked through the others.** | After learner attempts |

## How to use it

### As a T2 (Practitioner) learner

Use it for **calibration**. After Lessons 1, 3, 4, and 5, compare what you produced (your own asset list, Purdue diagram, IDMZ gap analysis, remote-access policy) against the corresponding sample. The samples are *deliberately worse* than what you should produce — if your output looks like the sample, you missed the lesson.

### As a T3 (Programme Builder) learner

Use it as **input data** for the Pillar A and Pillar S Discover phases. Treat the bundle as the existing state of your fictional client; produce the pillar plans that fix what's broken.

### As a T4 (Auditor) learner

Use it as the **substrate for an audit walkthrough**. Apply the FAT/SAT checklist. Write the five findings yourself. Compare against the fake audit report — note where the real auditor (the answer key) found things the fake auditor missed, and where the fake auditor cited the wrong SR.

## Calibration philosophy

**A learner with no comparison anchor cannot self-grade.** Every prior version of this curriculum told learners to "produce a Purdue diagram for your environment" — which only works if you have a real plant. The well-prepared learner accelerated; everyone else stalled. The broken-plant bundle removes that asymmetry: every learner has the same plant, and the answer key tells them what good looks like.

## Sanitisation note

This bundle is intentionally publishable. No real plant data, no real personnel names, no real client work. The flaws baked into it are pedagogically chosen — common, realistic, and discriminating between novice and expert response.
