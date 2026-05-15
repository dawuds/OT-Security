# Pillar S — Secure Network Architecture (IDMZ + Zones & Conduits)

> **Tier 3 / Lesson 3b — 90 minutes.** Apply the 4-phase pattern. The pillar where physical reality and security policy collide.

## Why this pillar comes third

Two reasons:

1. **The IDMZ is the single most impactful architectural control in OT.** Every public OT incident from Ukraine 2015 onward exploited the absence — or hollowness — of an Industrial DMZ.
2. **You cannot segment what you don't know exists.** That's why Pillar A (Asset Management) precedes this one. With the asset register in hand, you have the *map*. This pillar produces the *boundaries* on the map.

If T2 produced your "find the IDMZ gap" worksheet, this pillar is where you industrialise the answer.

## Discover

- **Sector and process** — continuous (oil & gas, power) vs batch (manufacturing) drives latency tolerance for inter-zone traffic.
- **Current network state** — flat network, basic VLAN separation, partial IDMZ, or full Purdue with IDMZ and DPI.
- **Vendor / OEM relationships** — who needs remote access, on what schedule, to which zones?
- **Existing firewall vendor** — Fortinet, Palo Alto, Cisco, Tofino — drives whether OT-aware DPI is feasible without procurement.
- **Safety system constraints** — IEC 61511 SIS isolation requirements (the cardinal rule from T1).

## Plan — IDMZ + Zones & Conduits + ACL lifecycle

The plan structure:

1. **The IDMZ design** (the central architectural element)
   - Two-firewall pattern: OT-side NGFW + IT-side NGFW with IDMZ-hosted services between them.
   - **Required IDMZ services**: jump server (vendor remote access), historian replica (data egress), patch server (controlled software ingress), AV update relay, time source.
   - **Forbidden in IDMZ**: any direct routing path between IT and OT. The IDMZ is a *broker*, not a *bridge*.
   - **Data diodes** for highest-criticality unidirectional flows (e.g., historian → corporate analytics). One-way flow, hardware-enforced.

2. **Internal segmentation per IEC 62443-3-2**
   - Zone definition for every Purdue level group: enterprise (4+), IDMZ (3.5), operations (3), supervisory (2), control (1), process (0), **safety (separate)**.
   - Sub-zones inside production for process isolation: e.g., Reactor A zone vs Reactor B zone, packaging zone vs mixing zone.
   - Conduit definition for each inter-zone communication: name, source zone, destination zone, allowed protocols, allowed function codes (read vs write — see [OT protocols primer](#learn/lesson:t1-orientation:04b-ot-protocols)), required SL.
   - **SIS isolated absolutely.** Physical and logical separation from BPCS. Different power, different network, different engineering tools where possible.

3. **OT-aware filtering at every conduit**
   - DPI signatures for protocols in use (Modbus, DNP3, EtherNet-IP, S7, IEC-104, BACnet).
   - **Default-deny on writes.** Permit reads where needed; permit specific write function codes (FC05, FC06, FC15, FC16) only on explicitly justified conduits with signed change records.
   - Logging of every policy violation; alerting on patterns.

4. **ACL lifecycle**
   - Documented business justification for every permit rule.
   - **90-day review cycle** for OT firewall rules. Rules without recent review get an expiry date.
   - Deny-all baseline for new conduits; permit-by-exception with named owner.
   - Out-of-band management network for the firewalls themselves — usable during an active cyber event.

5. **Resilience**
   - HA pairs on critical firewalls. Failure must not cause loss-of-view or loss-of-control for plant operators.
   - Wireless treated as conduit, not exception: separate WiFi controller, WPA3-Enterprise auth, per-VLAN.

## Produce — the artefacts

| Artefact | Owner | Audience |
|---|---|---|
| OT Network Architecture Diagram (zones, conduits, IDMZ services, SIS isolation) | OT Security Architect + Plant Manager | All; primary auditor evidence |
| Zone Register (every zone, with SL-T and rationale) | OT Security Architect | Auditor (required by IEC 62443-3-2) |
| Conduit Catalogue (every conduit, with allowed protocols + function codes + owner) | OT Security Architect | Network team, auditor |
| Firewall Rule Standard (review cadence, justification template, expiry policy) | OT Network Engineer | Network team |
| IDMZ Services Inventory (each service: purpose, owner, ingress/egress, audit trail) | OT Security Engineer | Auditor |
| ACL Review Log (last 12 months of reviews) | OT Network Engineer | Auditor |

The starting point template: the architecture sections of [`02-statement-of-applicability`](#templates/view:02-statement-of-applicability).

## KPI

| Type | KPI | Target |
|---|---|---|
| Leading | % of firewall rules with explicit business justification documented | 100% |
| Leading | % of remote-access sessions transiting IDMZ jump host vs direct VPN | 100% |
| Leading | % of firewall rules permitting Modbus/DNP3/S7 writes with named owner | 100% |
| Lagging | Number of "any/any" rules in OT firewall rulesets | 0 |
| Lagging | Number of firewall rules past their 90-day review date | 0 |
| Lagging | Number of unauthorised cross-zone traffic attempts blocked per week | trending stable / down |

## The three pitfalls

1. **Calling a VLAN-only separation an IDMZ.** A VLAN does not make a DMZ. Two firewalls with a service zone between them does. Auditors who ask "show me the IDMZ" are asking to see the two firewalls.
2. **Allowing port-only firewall rules in OT.** "Permit tcp/502" is not a control — it's a hole. Without DPI on protocol function codes, the rule is decorative. Re-read the [OT protocols primer](#learn/lesson:t1-orientation:04b-ot-protocols).
3. **Joining engineering workstations to the corporate AD.** It collapses the architectural status of the workstation from Level 3 to Level 4+, exposing OT to any IT identity-system compromise. Use a separate OT directory or a one-way trust.

## Map to repo

- Pillar source: [B.A.S.I.C. Pillar 3 — Secure Network Architecture](#basic-start/pillar-secure-network-architecture)
- Domain detail: [Network Segmentation and Zone Architecture](#framework/domain:network-segmentation)
- Architecture reference: [Purdue Model](#framework/purdue-interactive)
- IEC 62443: SR-5.1, SR-5.2, SR-5.3, SR-5.4, IEC 62443-3-2 (zones & conduits)
- NACSA: s18 (security measures), s20 (incident management capability)

## What's next

[Lesson 3c — Pillar T (IT/OT Teamwork)](#learn/lesson:t3-programme:03c-pillar-t-teamwork). The architectural and asset work means nothing without the IT/OT human bridge.
