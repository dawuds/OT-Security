# Pillar A — Asset Management (passive-only, audience-specific)

> **Tier 3 / Lesson 3a — 75 minutes.** Apply the 4-phase pattern. The pillar that unblocks every other one.

## Why this pillar comes second

A blunt sentence: **you cannot protect, segment, monitor, back up, patch, or audit what you cannot see.** Every other pillar in this programme presumes a current asset inventory. Without it, the programme is theatre.

Two further reasons:

1. **Active scanning kills PLCs.** OT discovery is *always* passive. The asset programme that imports IT discovery practice unchanged is dangerous.
2. **OT inventory is sector-mandatory.** NACSA s17 (NCII designation) and s18 (security measures) cannot be defended without a current asset register that distinguishes critical from non-critical assets.

## Discover

- **Sector** — drives which protocols you'll see and which assets are NCII-designated.
- **Current visibility** — completely blind below Level 3, partial via switch logs, or full passive coverage via Dragos / Claroty / Nozomi.
- **Tooling constraints** — commercial passive sensors, open-source (Zeek + custom dissectors), or fully manual.
- **Audience for the metric** — Board (risk burndown), Plant Manager (per-site coverage), OT SecOps (anomaly volume).
- **Integration with B (Backup)** — does Backup have an asset list, and is it the *same* list?

## Plan — passive-only architecture + audience-specific dashboards

The plan structure:

1. **Discovery method**
   - Network TAP at every conduit boundary — physical preferred, SPAN port acceptable.
   - Passive DPI sensor inferring asset type from protocol traffic, MAC OUI, and vendor signatures.
   - **Zero active scanning** of Levels 0–3. No `nmap -sV`, no Nessus, no SNMP polling without explicit per-asset sign-off from the asset owner.

2. **Asset register schema** — minimum fields per asset:
   - IP address, MAC address, MAC OUI vendor.
   - Purdue level (assigned, with documented justification).
   - Asset type (PLC / HMI / SCADA server / engineering workstation / SIS controller / sensor).
   - Protocols seen.
   - Communicating peers.
   - Criticality classification (NCII / non-NCII; safety-instrumented or not).
   - SL-T (Target Security Level) for the zone the asset sits in.
   - Owner (named role, ideally a person).
   - Last seen (timestamp).

3. **Audience-specific dashboards** — three dashboards, three numerators:
   - **Board / Executive** — % of NCII-designated assets in active passive monitoring; financial exposure of unmanaged-but-discovered devices.
   - **Plant / Site Manager** — days since last passive scan refresh; count of unmanaged devices per site; backup coverage per asset.
   - **OT SecOps** — anomalous protocol pairs detected per asset; firewall rule violations per zone; MTTD for unauthorised devices.

4. **Reconciliation cadence** — monthly comparison of the passive-discovered list vs the engineering-of-record list. Deltas are findings.

## Produce — the artefacts

| Artefact | Owner | Audience |
|---|---|---|
| OT Asset Register (signed, dated, versioned) | OT Security Engineer | Plant Manager, Auditor |
| Discovery Architecture diagram (TAP / SPAN placement, sensor coverage) | OT Network Architect | Auditor |
| Reconciliation Procedure (monthly cadence, deltas, action thresholds) | OT Security Engineer | Plant Manager |
| NCII Asset Classification (per s17) | OT Security Lead + Plant Manager | NACSA |
| Active-Scanning Prohibition Standard (with named exceptions and approval workflow) | OT Security Engineer | All IT, OT, vendor staff |

The starting point templates: [`02-statement-of-applicability`](#templates/view:02-statement-of-applicability) for the SoA structure, plus the asset-register schema embedded in the [Asset Inventory domain](#framework/domain:asset-inventory).

## KPI

| Type | KPI | Target |
|---|---|---|
| Leading | % of Level 1–3 assets in active passive monitoring vs estimated total | ≥ 95% |
| Leading | % of NCII-designated assets with verified ownership in the register | 100% |
| Lagging | Number of unmanaged / unknown devices discovered on the OT network this month | trending down |
| Lagging | Age of oldest unreviewed asset entry in the register | ≤ 30 days |
| Lagging | Number of active-scan attempts blocked or rejected by network policy | ≥ 0 (any > 0 is a finding) |

## The three pitfalls

1. **Buying a passive-monitoring tool before defining the register schema.** The vendor will define it for you, in their data model. Your auditor will then be auditing against the vendor, not your sector. Define the register first.
2. **Treating "unmanaged device discovered" as a one-time finding.** It's a *recurring* metric. Each month's number tells you whether IT/OT teamwork (Pillar T) is improving or degrading.
3. **Skipping the criticality classification.** A register without NCII / safety / SL-T per asset is a list of devices. With them, it's a defensible inventory under Act 854 s17.

## Map to repo

- Pillar source: [B.A.S.I.C. Pillar 2 — Asset Management](#basic-start/pillar-asset-management)
- Domain detail: [Asset Inventory and Management](#framework/domain:asset-inventory)
- IEC 62443: SR-7.8 (Asset inventory), SR-2.2 (Use control)
- NACSA: s17 (NCII designation), s18 (security measures), s19 (programme)

## What's next

[Lesson 3b — Pillar S (Secure Network Architecture)](#learn/lesson:t3-programme:03b-pillar-s-network-architecture). With the inventory in hand, segment what you've found.
