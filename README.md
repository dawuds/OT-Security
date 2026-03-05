# OT Security Framework

A structured, open-access knowledge base for Operational Technology (OT) cybersecurity — covering international standards, compliance requirements, frameworks, audit evidence, and recommendations.

**Primary Standard:** IEC 62443 (paraphrased)
**Malaysia Focus:** NACSA Act 854 cross-referenced throughout
**Audience:** OT security engineers, GRC practitioners, auditors, NCII-designated operators

---

## Important Notice

> This resource is for educational and indicative purposes only. It does not constitute legal or technical advice. IEC 62443 content is paraphrased from the standard — obtain normative text from [iec.ch](https://iec.ch). NACSA Act 854 references are indicative — verify against official Gazette text. All content marked `sourceType: "constructed-indicative"` has not been verified against official sources.

---

## What This Repository Covers

| Layer | Content |
|---|---|
| **Standards** | IEC 62443 series overview, all 51 SRs with SL 1-4 descriptions, NIST SP 800-82, MITRE ATT&CK for ICS |
| **Architecture** | Purdue model, zones and conduits, IDMZ pattern, asset types |
| **Requirements** | 13 security domains with detailed requirements, SL mapping, NACSA obligations |
| **Controls** | Control library with maturity levels and NACSA/NIST CSF mappings |
| **Evidence** | Audit evidence items per domain — what auditors look for, common gaps, how to verify |
| **Threats** | Threat actor profiles, known incidents (Stuxnet, TRITON, Ukraine, Colonial Pipeline) mapped to preventive controls |
| **Risk Management** | OT/ICS risk methodology, 5x5 safety-weighted matrix, 20-risk register, assessment checklist, treatment options |
| **Sectors** | Energy, water, oil & gas, transport, manufacturing, building automation — with NACSA NCII obligations |
| **Cross-References** | IEC 62443 ↔ NACSA Act 854, NIST CSF 2.0, NIST SP 800-82, sector ↔ NACSA codes of practice |

---

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
│   └── inventory.json                  # 28 audit artifacts with controlSlugs
├── controls/
│   ├── domains.json                    # 13 security domains
│   └── library.json                    # 17 controls with maturity levels
├── cross-references/
│   ├── iec62443-to-nacsa.json          # IEC 62443 ↔ NACSA Act 854
│   ├── iec62443-to-nist80082.json      # IEC 62443 ↔ NIST SP 800-82
│   ├── iec62443-to-nist-csf.json       # IEC 62443 ↔ NIST CSF 2.0
│   ├── mitre-to-controls.json          # MITRE ATT&CK ICS ↔ controls
│   └── sector-to-nacsa-cop.json        # Sectors ↔ NACSA codes of practice
├── evidence/
│   └── index.json                      # Evidence items per domain (48 items)
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
│       ├── energy.json
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
└── threats/
    ├── known-incidents.json            # Stuxnet, TRITON, Ukraine, etc.
    └── threat-actors.json              # OT threat actor profiles
```

---

## NACSA Act 854 Integration

For Malaysian NCII-designated OT operators:

| Act 854 Obligation | OT Security Framework Response |
|---|---|
| **s17** — NCII designation | Asset inventory (SR-7.8) defines NCII asset scope |
| **s18** — Security measures | IEC 62443 SL 2 minimum; SL 3 for critical assets |
| **s21** — Risk assessment | IEC 62443-3-2 zone-based risk assessment methodology |
| **s22** — Code of practice | Sector COP mapping in `cross-references/sector-to-nacsa-cop.json` |
| **s23** — Security audit | IEC 62443-3-3 SL assessment by NACSA-licensed auditor |
| **s26** — Incident notification | 6-hour notification procedure in `requirements/by-domain/incident-detection-response.json` |

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

---

## Standards Referenced

- **IEC 62443** — Security for Industrial Automation and Control Systems (paraphrased; obtain from iec.ch)
- **NIST SP 800-82 Rev 3** — Guide to OT Security (public domain; nvlpubs.nist.gov)
- **MITRE ATT&CK for ICS** — OT adversary tactics and techniques (public; attack.mitre.org/matrices/ics)
- **NIST CSF 2.0** — Cybersecurity Framework (public; nist.gov)
- **NACSA Act 854** — Cyber Security Act 2024, Malaysia (public Gazette)

---

## Related Repositories

- [dawuds/nacsa](https://github.com/dawuds/nacsa) — NACSA Act 854 (Act 854) structured compliance database
- [dawuds/RMIT](https://github.com/dawuds/RMIT) — BNM Risk Management in Technology (RMiT)
- [dawuds/pdpa-my](https://github.com/dawuds/pdpa-my) — Malaysia PDPA Act 709 + Amendment A1727
