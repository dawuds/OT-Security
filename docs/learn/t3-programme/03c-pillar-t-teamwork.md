# Pillar T — IT/OT Teamwork (the binding pillar)

> **Tier 3 / Lesson 3c — 75 minutes.** Apply the 4-phase pattern. The pillar where every other pillar collapses if you skip it.

## Why this pillar comes here (not last)

The B.A.S.I.C. S.T.A.R.T. acronym puts T (Teamwork) at position 10. That sequencing is for *delivery* — you put governance scaffolding on top of working operational practice, not under it.

But for *learning*, you need this pillar early in T3 because:

1. **Every prior pillar has an IT/OT collaboration question baked into it.** Backup decides what IT infrastructure can be leveraged. Asset Management decides who owns the inventory. Network Architecture decides who controls the firewall ruleset. Without an answer to the teamwork question, every prior pillar produces an artefact and a fight.
2. **It's the only pillar that's *not* a deliverable.** The output is governance — RACI matrices, steering committees, joint authority. Easy to skip; impossible to recover from.
3. **The next pillar (Continuous Vulnerability Management) cannot be assigned without it.** Patching authority in OT is contested by definition.

## Discover

- **Current IT/OT relationship** — actively combative, passively cooperative, integrated, or already unified under one CISO?
- **Risk ownership** — does the enterprise CISO own OT cyber risk, or the Plant / Site Manager?
- **Resource model** — dedicated OT security engineers, or IT engineers doubling up?
- **Cultural distance** — measured: do IT analysts know what LOTO means? Do OT engineers know what "least privilege" means?
- **Trigger event** — most IT/OT teamwork programmes start after a near-miss. Has yours had one?

## Plan — Steering Committee + Cross-Pollination + RACI

The plan structure:

1. **The Steering Committee (Centre of Excellence)**
   - Joint charter: explicit balance between IT security mandates and OT safety + reliability mandates.
   - Voting members: CISO + Plant Director + Engineering Lead + OT Security Architect (minimum). Plus rotating ops-shift representation.
   - **Tie-breaker workflow**: when IT demands a patch and OT refuses (production schedule, validation cycle), who decides, and how is residual risk formally accepted? Document this *before* the disagreement, not during.
   - Meeting cadence: monthly minimum, with ad-hoc convening authority for incident response.

2. **Cross-pollination programme**
   - **IT in the Plant**: every IT security analyst walks the plant floor, witnesses LOTO procedures, sits in on a shift handover. Annual minimum.
   - **OT in the SOC**: control engineers shadow SOC L1 + L2 to understand network telemetry and the IT incident queue. Annual minimum.
   - Mandatory cross-training hours, tracked, reported in the metric.

3. **Hybrid roles definition**
   - **OT Security Architect** — translates enterprise security policy into Purdue-compliant architectures. Must read both firewall rules and ladder logic.
   - **Process Security Analyst** — plant-side engineer; primary IR liaison; holds the "physical wrench" while IT holds the "keyboard".
   - **OT SOC Liaison** — IT-side analyst dedicated to OT alert triage; has authority to call the plant during off-hours.

4. **RACI matrix for the contested decisions**
   - Firewall rule changes (R: OT Network Engineer; A: OT Security Architect; C: IT Network; I: Plant Manager)
   - Vulnerability scanning prohibition (R/A: OT Security Lead; C: IT VM team; I: Plant Manager + Engineering)
   - Incident containment (R: SOC L2; A: Plant Manager during business hours / OT Security Lead OOH; C: IT Sec; I: Steering Committee)
   - MOC approvals (R: Engineering; A: Plant Manager; C: OT Security; I: IT Sec)
   - Patch deployment to OT (R: OT Engineer; A: Plant Manager; C: Vendor + OT Security; I: IT VM team)
   - **Each row of the RACI is a documented escalation path, signed by the named role-holders.**

5. **No-blame incident culture**
   - Joint post-incident debriefs structured to prevent IT/OT finger-pointing.
   - Psychological safety: plant operators must report suspected anomalies (unusual HMI cursor movement, unexpected valve activation, "the screen looked weird") without fear of reprimand.
   - Integrate cyber near-miss reporting into the existing plant safety near-miss programme — same form, same channel, same anonymity.

## Produce — the artefacts

| Artefact | Owner | Audience |
|---|---|---|
| IT/OT Steering Committee Charter (signed by CEO or COO) | OT Security Lead + CISO | Board, all members |
| Steering Committee Minutes (last 12 months) | Committee Secretary | Auditor |
| RACI Matrix for the 5+ contested decision categories | OT Security Lead | All affected roles |
| Cross-Training Log (IT-in-Plant + OT-in-SOC hours per person) | HR + OT Security | Compliance, Auditor |
| Hybrid Role JDs (OT Security Architect, Process Security Analyst, OT SOC Liaison) | HR + OT Security Lead | Recruitment, Auditor |
| Joint Incident AAR Template (ensures both sides debrief together) | OT Security Lead + SOC Lead | All incident participants |

The starting point template: [`01-master-isp`](#templates/view:01-master-isp) for the governance backbone; create the RACI as a separate signed document.

## KPI

| Type | KPI | Target |
|---|---|---|
| Leading | % of IT security staff with completed plant-floor familiarisation hours in last 12 months | ≥ 80% |
| Leading | % of control engineers with SOC shadow hours in last 12 months | ≥ 80% |
| Leading | Number of jointly-authored MOC tickets (signed by both IT Sec and Engineering) | trending up |
| Lagging | Number of escalations to Steering Committee for IT/OT dispute resolution | trending down (after baseline) |
| Lagging | % of post-incident action items with joint IT and OT ownership | ≥ 70% |
| Lagging | Time-to-resolution for IT/OT-flagged conflicts (vs IT-only or OT-only conflicts) | parity or better |

## The three pitfalls

1. **The Steering Committee that meets quarterly but doesn't decide anything.** If decisions still escalate to the CEO, the committee has failed. The tie-breaker workflow must work without escalation in 80%+ of cases.
2. **Cross-training hours that are never measured.** Without a metric, the programme dies inside six months — both sides revert to their silos.
3. **Treating safety-culture incident reporting as a model.** It is the model. Don't reinvent it; integrate. The plant already has a near-miss programme; adding a "cyber" form is one form, not one programme.

## Map to repo

- Pillar source: [B.A.S.I.C. Pillar 10 — Teamwork (IT/OT Partnership)](#basic-start/pillar-teamwork-it-ot-partnership)
- Related domain: spans every domain — most relevant are [Incident Detection and Response](#framework/domain:incident-detection-response) and [Configuration Management](#framework/domain:configuration-management)
- IEC 62443: SR-2.1 (Authorisation enforcement), SR-2.4 (Mobile code), IEC 62443-2-1 (Programme requirements)
- NACSA: s17 (NCII designation — drives ownership), s19 (training and programme)
- NIST CSF 2.0: GV.OC, GV.RR (governance and roles)

## What's next

[Lesson 4 — Pillar I (Incident Response with TTX + NACSA s26)](#learn/lesson:t3-programme:04-pillar-i-incident-response). With the team and the architecture in place, build the response that uses both.
