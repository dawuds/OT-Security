# OT-Security — IEC 62443 + NACSA OT Security

## What This Is
Structured knowledge base for OT/ICS/SCADA security based on IEC 62443 and NACSA sector requirements. SPA explorer with JSON data layers.

## Architecture
- **SPA**: `index.html` + `app.js` + `style.css` (vanilla JS, no build step)
- **Data**: JSON files across controls, cross-references, sectors, standards, risk-management, evidence, requirements
- **Schema**: GRC Portfolio v2.0 Standardized Schema

## Key Data Files
- `controls/library.json` — 25 controls focused on ICS/SCADA/OT environments
- `controls/domains.json` — 13 domains
- `sectors/requirements/` — 6 sector profiles (energy, transport, water, manufacturing, oil-gas, building-automation)
- `sectors/purdue-model.json` — Purdue Enterprise Reference Architecture mapping
- `standards/iec62443/`, `standards/nist-800-82/`, `standards/mitre-attack-ics/`

## Cross-References
- `cross-references/iec62443-to-nacsa.json` — IEC 62443 to NACSA CoP mapping
- `cross-references/iec62443-to-nist-csf.json` — IEC 62443 to NIST CSF
- `cross-references/iec62443-to-nist80082.json` — IEC 62443 to NIST 800-82
- `cross-references/mitre-to-controls.json` — MITRE ATT&CK for ICS mapping
- `cross-references/sector-to-nacsa-cop.json` — Sector to NACSA CoP alignment

## Conventions
- Kebab-case slugs for all IDs
- Security Levels (SL 1-4) per IEC 62443 zones and conduits
- Sector-specific requirements extend base controls

## Important
- OT environments have safety implications — never weaken controls without safety review
- Purdue model levels must be preserved in network segmentation controls
- MITRE ATT&CK for ICS tactics are OT-specific, not enterprise ATT&CK

## Related Repos
- `nacsa/` — NACSA Act 854 (OT sectors: Energy, Transport, Water are NCII sectors)
- `Tech-Audit/NACSA/Sector-Guides/` — OT sector audit guides
- `nist/` — NIST CSF 2.0 baseline
