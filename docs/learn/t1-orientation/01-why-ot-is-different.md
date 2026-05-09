# Why OT is different from IT

> **Tier 1 / Lesson 1 — 10 minutes.** Read this before anything else.

## The triage order is reversed

In IT security, the priority is **C-I-A**: Confidentiality first, Integrity second, Availability third. Lose data → bad. Lose service → annoying.

In OT, the priority is **S-A-I-C**: **Safety** first, **Availability** second, **Integrity** third, **Confidentiality** last.

Why the reversal: a control system runs a physical process. If the process fails unsafely — over-pressurised vessel, runaway turbine, contaminated water — people die. Stolen plant data is a problem. A dead operator is an end-of-career incident.

The triage question during an OT incident is **not** "what data was stolen?" — it's **"is the process still safe?"** An IR plan that doesn't centre this will fail at the worst moment.

## "Just patch it" doesn't apply

| | IT | OT |
|---|---|---|
| Patch cadence | Weekly / monthly | Annual shutdown windows; some assets never |
| Reboot tolerance | Minutes | Zero — reboot can crash the process |
| Vendor support | Active for current versions | Often expired; supplier is gone |
| Active scanning | Yes — it's the job | No — Nessus has crashed PLCs |

A 20-year-old PLC running a coal handling line is not getting patched. The mitigation is **compensating controls**: network segmentation, virtual patching at the boundary, strict access control. CVSS scores fail in OT because they ignore process criticality — a CVSS-5 on a chlorination dosing PLC is more dangerous than a CVSS-9.8 on an offline workstation.

## Why active scanning is forbidden

Tools like Nessus actively probe ports. OT devices were designed in the 1990s to talk to two specific peers, predictably. An unexpected packet sequence — a port scan, a malformed Modbus request — can hang the device or crash the process it controls. The 2003 Davis-Besse nuclear plant incident is the canonical example: the SQL Slammer worm, scanning aggressively, took down the safety parameter display system.

OT discovery is **passive only**: tap a SPAN port, read the traffic, infer what's there. Tools like Dragos, Claroty, Nozomi do this commercially; the included [pcap-analyzer.py](../../../tools/pcap-analyzer.py) does it manually for small captures.

## What makes a good OT security professional

Three things, in order:

1. **Respect the process.** You are a guest in the plant. The plant existed before you and will exist after you. Don't break it.
2. **Bridge two cultures.** IT speaks confidentiality; OT speaks reliability. Your job is to make them collaborate, not pick a winner. The B.A.S.I.C. S.T.A.R.T. pillar [Teamwork — IT/OT Partnership](#basic-start/pillar-teamwork-it-ot-partnership) is the explicit programme for this.
3. **Cite the consequence, not the CVE.** "If this PLC is compromised, the chlorine dosing setpoint can be raised — that contaminates drinking water for 50,000 people." That sentence gets budget. "There's a CVSS 7.5 vulnerability on Schneider M340" does not.

## What's next

Move on to [Lesson 2 — The Purdue Model in 10 minutes](#learn/lesson:t1-orientation:02-purdue-tour). Once you know where things live, the rest of the orientation makes sense.
