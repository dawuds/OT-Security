# OT Security Framework

> **Disclaimer:** Educational and indicative resource. Not legal, regulatory, or technical advice. Content marked `sourceType: "constructed-indicative"` is not verified against official sources. Refer to authoritative standards bodies and seek professional counsel for compliance decisions.

A structured, open-access knowledge base for Operational Technology (OT) cybersecurity — international standards, compliance requirements, frameworks, audit evidence, and a graduated learning path.

**Primary Standard:** IEC 62443 (paraphrased)
**Malaysia Focus:** NACSA Act 854 cross-referenced throughout
**Audience:** OT security engineers, GRC practitioners, auditors, NCII-designated operators

---

## Quick Start

- Open [`index.html`](index.html) in a browser — the SPA loads everything below.
- New here? Start with the [Learn](docs/learn/index.json) tier-1 orientation in the **Learn** nav (≈ 1 hour).
- Need a reference quickly? Browse [Controls](controls/library.json), [Domain Requirements](requirements/index.json), or [Threats](threats/known-incidents.json).
- Validating the data layer? `node validate.js`.

---

## Important Notice

> Educational and indicative purposes only. Not legal or technical advice. IEC 62443 content is paraphrased from the standard — obtain normative text from [iec.ch](https://iec.ch). NACSA Act 854 references are indicative — verify against official Gazette text. Content marked `sourceType: "constructed-indicative"` is not verified against official sources.

---

## What This Repository Covers

| Layer | Content | Source |
|---|---|---|
| **Learn** | 4-tier graduated learning path: Orientation → Practitioner → Programme → Auditor (22 lessons, 5 checkpoints) | [`docs/learn/index.json`](docs/learn/index.json) |
| **Standards** | IEC 62443 series, 7 FRs, all SRs with SL 1-4 descriptions, NIST SP 800-82, MITRE ATT&CK for ICS | [`standards/`](standards/) |
| **Architecture** | Purdue model, zones and conduits, IDMZ pattern, asset types | [`architecture/`](architecture/) |
| **Requirements** | 13 security domains, each with detailed legal/technical/governance requirements, SL mapping, MITRE ATT&CK ICS | [`requirements/by-domain/`](requirements/by-domain/) |
| **Controls** | 25 controls with maturity levels, audit procedures, defended incidents, and cross-linked NACSA/NIST CSF/MITRE mappings | [`controls/library.json`](controls/library.json) |
| **Evidence** | 36 audit evidence items across 13 domains — what good looks like, common gaps, how to verify | [`evidence/index.json`](evidence/index.json) |
| **Threats** | 7 threat actor profiles, 6 known incidents (Stuxnet, TRITON, Ukraine, Colonial Pipeline, Oldsmar, Monterrey 2026 AI-augmented) joined to defending controls via shared SRs | [`threats/`](threats/) |
| **Risk Management** | OT/ICS risk methodology, 5x5 safety-weighted matrix, 20-risk register, assessment checklist, treatment options | [`risk-management/`](risk-management/) |
| **Sectors** | 6 OT-focused sectors (energy, water, oil & gas, transport, manufacturing, building automation) with NACSA NCII obligations | [`sectors/`](sectors/) |
| **Cross-References** | IEC 62443 ↔ NACSA, NIST CSF 2.0, NIST 800-82, MITRE ICS ↔ controls, sector ↔ NACSA CoPs | [`cross-references/`](cross-references/) |
| **Templates** | 8 gold-standard policy templates + FAT/SAT checklist + worked sample reports | [`templates/`](templates/) |
| **Audit Integration** | Maps each control to Tech-Audit work programmes, PBC lists, and finding templates | [`audit-integration.json`](audit-integration.json) |
| **Tools** | Modbus honeypot + PCAP analyser used in the Practitioner tier labs | [`tools/`](tools/) |
| **B.A.S.I.C. S.T.A.R.T.** | 10-pillar AI-prompted programme-builder framework with discovery questions, plan sections, KPIs | [`basic-start/`](basic-start/) |

---

## Learning Path

A 4-tier scaffold lives in [`docs/learn/`](docs/learn/) and is browsable in the SPA via the **Learn** nav. Each tier ends with a checkpoint; later tiers presume the earlier ones.

| Tier | Audience | Duration | Outcome |
|---|---|---|---|
| **T1 — Orientation** | Anyone new to OT | ≈ 1 hour | Can name Purdue levels, explain why patching ≠ IT, list the five canonical OT incidents, articulate the IDMZ |
| **T2 — Practitioner** | IT security professional newly responsible for OT | ≈ 1 week | Passive asset discovery, Purdue mapping, IDMZ gap analysis, drafted remote-access policy |
| **T3 — Programme Builder** | New OT security manager / NACSA NCII operator | 1–3 months | Stand up the 10 B.A.S.I.C. S.T.A.R.T. pillars, NACSA-aligned artefacts, defensible TTX |
| **T4 — Auditor / Assessor** | NACSA-licensed auditor / IESP assessor | Continuous | SL-2/3 zone assessment, FAT/SAT walkthrough, findings that cite SR + NACSA section |

Index: [`docs/learn/index.json`](docs/learn/index.json). Lessons cross-link into the data layer — every cited SR, control, incident, and template is one click away.

---

## Technical Architecture

This repository follows the **GRC Portfolio v2.0 Standardized Schema**, optimised for machine-readability and dynamic SPA rendering.

### The Compliance Chain
Data is structured to maintain a strict bidirectional mapping:
`IEC 62443 Requirement (SR)` ↔ `OT Security Control` ↔ `Audit Evidence` ↔ `Artifact Template`

The SPA enforces this in the UI: a [control detail page](controls/library.json) surfaces its SRs (clickable), MITRE ATT&CK ICS techniques (clickable), evidence items, audit procedure refs from [`audit-integration.json`](audit-integration.json), and the historical incidents the control would have helped defend against — joined via shared SRs.

### Data Layers
- **Controls** ([`controls/library.json`](controls/library.json)) — 25 OT-specific controls mapped to the Purdue Model.
- **Domain Requirements** ([`requirements/by-domain/`](requirements/by-domain/)) — 13 domains, each with detailed legal / technical / governance breakdowns and SL mapping.
- **Evidence** ([`evidence/index.json`](evidence/index.json)) — 36 items with `whatGoodLooksLike` and `commonGaps` for audit speed.
- **Standards** — IEC 62443-3-3 ([`standards/iec62443/`](standards/iec62443/)), NIST 800-82 ([`standards/nist-800-82/`](standards/nist-800-82/)), MITRE ATT&CK ICS ([`standards/mitre-attack-ics/`](standards/mitre-attack-ics/)).

### Consistency & Style
- **Naming:** Kebab-case slugs; safety-weighted risk levels.
- **Scoring:** Standardised 5x5 Likelihood/Impact risk matrix.
- **Audit Ready:** [FAT/SAT checklist](templates/iec-62443-fat-sat-checklist.md), 8 gold-standard policy templates, and a worked sample — all cross-linked from controls.

## Repository Structure

```
OT-Security/
├── index.html                          # Single-page application entry point
├── app.js                              # Application logic and rendering
├── style.css                           # Styles and CSS variables
├── validate.js                         # Data validation script (11 checks)
├── architecture/
│   ├── asset-types.json                # OT asset type definitions
│   ├── purdue-model.json               # Purdue model levels 0-5
│   └── zones-conduits.json             # Zone and conduit definitions
├── artifacts/
│   └── inventory.json                  # 31 audit artifacts with controlSlugs
├── controls/
│   ├── domains.json                    # 13 security domains
│   └── library.json                    # 25 controls with maturity levels
├── cross-references/
│   ├── iec62443-to-nacsa.json          # IEC 62443 ↔ NACSA Act 854
│   ├── iec62443-to-nist80082.json      # IEC 62443 ↔ NIST SP 800-82
│   ├── iec62443-to-nist-csf.json       # IEC 62443 ↔ NIST CSF 2.0
│   ├── mitre-to-controls.json          # MITRE ATT&CK ICS ↔ controls
│   └── sector-to-nacsa-cop.json        # Sectors ↔ NACSA codes of practice
├── evidence/
│   └── index.json                      # Evidence items per domain (36 items across 13 domains)
├── requirements/
│   ├── index.json                      # Domain index (13 domains)
│   └── by-domain/                      # Per-domain requirement files
│       ├── asset-inventory.json
│       ├── backup-recovery.json
│       ├── configuration-management.json
│       ├── data-protection.json
│       ├── identity-access-management.json
│       ├── incident-detection-response.json
│       ├── monitoring-logging.json
│       ├── network-segmentation.json
│       ├── patch-vulnerability-management.json
│       ├── physical-security.json
│       ├── remote-access.json
│       ├── safety-system-security.json
│       └── supply-chain.json
├── risk-management/
│   ├── checklist.json                  # Assessment checklist
│   ├── methodology.json               # Risk methodology
│   ├── risk-matrix.json               # 5x5 safety-weighted matrix
│   ├── risk-register.json             # 20 OT/ICS risks
│   └── treatment-options.json         # Treatment strategies
├── sectors/
│   ├── index.json                      # 6 OT-focused NACSA NCII sectors
│   └── requirements/                   # Sector-specific requirements
│       ├── building-automation.json
│       ├── energy.json
│       ├── manufacturing.json
│       ├── oil-gas.json
│       ├── transport.json
│       └── water.json
├── standards/
│   ├── iec62443/
│   │   ├── index.json                  # IEC 62443 series overview
│   │   ├── foundational-requirements.json  # 7 FRs
│   │   ├── security-levels.json        # SL 1-4 definitions
│   │   └── system-requirements.json    # 51 SRs with SL descriptions
│   ├── mitre-attack-ics/
│   │   ├── index.json                  # MITRE ATT&CK for ICS overview
│   │   └── techniques.json             # ICS techniques
│   └── nist-800-82/
│       └── index.json                  # NIST SP 800-82 Rev 3 overview
├── threats/
│   ├── known-incidents.json            # Stuxnet, TRITON, Ukraine, Colonial, Oldsmar, Monterrey 2026
│   └── threat-actors.json              # OT threat actor profiles
├── templates/
│   ├── index.json                      # Template manifest (loaded by SPA)
│   ├── iec-62443-fat-sat-checklist.md  # FAT/SAT security checklist
│   └── gold-standard/                  # 8 policy templates
├── samples/
│   └── iec-62443-fat-sample.md         # Worked FAT report (the expected output)
├── tools/
│   ├── modbus-honeypot.py              # Used in T2 Practitioner Lesson 2
│   └── pcap-analyzer.py                # Used in T2 Practitioner Lesson 1
├── basic-start/
│   ├── framework.json                  # 10-pillar B.A.S.I.C. S.T.A.R.T. data
│   └── worked-example.json             # Full worked example for one pillar
├── audit-integration.json              # Maps 25 controls → audit procedures
└── docs/
    └── learn/
        ├── index.json                  # 4-tier learning path manifest
        ├── t1-orientation/             # 5 lessons + checkpoint
        ├── t2-practitioner/            # 5 labs + checkpoint
        ├── t3-programme/               # 5 lessons + checkpoint
        └── t4-auditor/                 # 4 lessons + checkpoint
```

---

## Features

- **IEC 62443 SR coverage** — 51 SRs across 7 FRs with SL 1-4 descriptions ([`standards/iec62443/system-requirements.json`](standards/iec62443/system-requirements.json))
- **25 controls** across 13 domains with maturity levels, audit-procedure refs, and incidents-defended joins ([`controls/library.json`](controls/library.json))
- **13 detailed domain requirement files** with legal/technical/governance/SL mapping/MITRE per requirement ([`requirements/by-domain/`](requirements/by-domain/))
- **36 evidence items** with `whatGoodLooksLike` and `commonGaps` per item ([`evidence/index.json`](evidence/index.json))
- **31 audit artefacts** with control-slug mapping ([`artifacts/inventory.json`](artifacts/inventory.json))
- **20 OT/ICS risks** + 5x5 safety-weighted matrix ([`risk-management/`](risk-management/))
- **66 MITRE ATT&CK ICS techniques** mapped to defensive controls ([`cross-references/mitre-to-controls.json`](cross-references/mitre-to-controls.json))
- **5 cross-reference files** — NACSA, NIST CSF 2.0, NIST SP 800-82, MITRE ICS, sector COPs ([`cross-references/`](cross-references/))
- **6 sector requirement files** — energy, water, oil & gas, transport, manufacturing, building automation ([`sectors/requirements/`](sectors/requirements/))
- **8 gold-standard policy templates** + FAT/SAT checklist + worked sample report ([`templates/`](templates/))
- **B.A.S.I.C. S.T.A.R.T. framework** — 10 pillars with discovery questions, plan sections, KPIs ([`basic-start/`](basic-start/))
- **4-tier graduated learning path** — Orientation → Practitioner → Programme → Auditor ([`docs/learn/`](docs/learn/))
- **SPA cross-linking** — every control links to its SRs, MITRE techniques, NACSA sections, evidence, audit procedures, and the historical incidents it defends against
- **Tools** — passive PCAP analyser + Modbus honeypot for hands-on labs ([`tools/`](tools/))
- Dark mode toggle, data validation (`node validate.js`), CC-BY-4.0 licence

---

## NACSA Act 854 Integration

For Malaysian NCII-designated OT operators:

| Act 854 Obligation | OT Security Framework Response |
|---|---|
| **s17** — NCII designation | Asset inventory (SR-7.8) defines NCII asset scope |
| **s18** — Security measures | IEC 62443 SL 2 minimum; SL 3 for critical assets |
| **s21** — Risk assessment | IEC 62443-3-2 zone-based risk assessment methodology |
| **s22** — Code of practice | Sector COP mapping in [`cross-references/sector-to-nacsa-cop.json`](cross-references/sector-to-nacsa-cop.json) |
| **s23** — Security audit | IEC 62443-3-3 SL assessment by NACSA-licensed auditor — see [`audit-integration.json`](audit-integration.json) |
| **s26** — Incident notification | Notification procedure in [`requirements/by-domain/incident-detection-response.json`](requirements/by-domain/incident-detection-response.json). *Specific clocks per the published Act — verify against your sector COP.* |

See full mapping: [`cross-references/iec62443-to-nacsa.json`](cross-references/iec62443-to-nacsa.json)

---

## Quick Reference: Security Levels

| SL | Label | Threat | Malaysia Context |
|---|---|---|---|
| SL 1 | Basic | Casual/opportunistic | Non-NCII OT environments |
| SL 2 | Enhanced | Motivated, generic IT skills | NCII baseline for most OT sectors |
| SL 3 | Advanced | OT-expert attacker | High-criticality NCII assets (TNB transmission, major water works) |
| SL 4 | Critical | Nation-state, SIS-targeting | Safety Instrumented Systems — ALL sectors |

---

## Key Incidents Referenced

| Incident | Year | Impact | Key Lesson |
|---|---|---|---|
| Stuxnet | 2010 | 1,000 centrifuges destroyed | USB hygiene; PLC program integrity |
| TRITON/TRISIS | 2017 | SIS nearly disabled — near mass casualty | SIS must be physically isolated |
| Ukraine Power Grid | 2015/2016 | 230,000+ customers without power | IT/OT separation; OT monitoring |
| Colonial Pipeline | 2021 | 6-day fuel crisis | MFA on remote access is not optional |
| Oldsmar Water | 2021 | Near-chemical contamination | Input validation; setpoint limits |
| Monterrey Water (AI-augmented) | 2026 | OT compromise attempted, **failed**; AI autonomously identified SCADA interface | IDMZ + MFA + auth-failure alerting still answer the question; AI-augmented recon is the threat-model update |

---

## Standards Referenced

- **IEC 62443** — Security for Industrial Automation and Control Systems (paraphrased; obtain from iec.ch)
- **NIST SP 800-82 Rev 3** — Guide to OT Security (public domain; nvlpubs.nist.gov)
- **MITRE ATT&CK for ICS** — OT adversary tactics and techniques (public; attack.mitre.org/matrices/ics)
- **NIST CSF 2.0** — Cybersecurity Framework (public; nist.gov)
- **NACSA Act 854** — Cyber Security Act 2024, Malaysia (public Gazette)

---

## Related Repositories

- [dawuds/cloud-sec](https://github.com/dawuds/cloud-sec) — Cloud cybersecurity framework (CSA CCM v4, CIS Benchmarks, BNM RMiT Cloud)
- [dawuds/AI-Governance](https://github.com/dawuds/AI-Governance) — Multi-framework AI governance reference (11 frameworks, Malaysia NGAIGE anchor)
- [dawuds/nacsa](https://github.com/dawuds/nacsa) — NACSA Act 854 (Act 854) structured compliance database
- [dawuds/RMIT](https://github.com/dawuds/RMIT) — BNM Risk Management in Technology (RMiT)
- [dawuds/pdpa-my](https://github.com/dawuds/pdpa-my) — Malaysia PDPA Act 709 + Amendment A1727
