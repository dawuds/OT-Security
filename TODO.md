# OT Security Framework — TODO

Tracking all planned enhancements. Grouped by phase. Check off items as completed.

---

## Phase 1 — Bug Fixes (Critical — blocks UI)

- [x] Fix `data.slTargetingProcess.map is not a function` — slTargetingProcess is an object, not array; fix app.js to use `.steps.map()`
- [x] Fix `data.securityLevels` → `data.levels` in renderIecSL (key name mismatch)
- [x] Fix `sl.level` → `sl.sl` and `sl.description` → `sl.shortDescription` in renderIecSL
- [x] Fix `sl.typicalApplicability` (array) rendered via `escHtml` → use `tagList()`
- [x] Fix `data.slToNacsaMapping.map is not a function` — object not array in renderCrossNacsa; convert data to array format
- [x] Fix renderCrossNacsa field mismatches: `m.description` (app) vs `iec62443Alignment` (data); `m.iec62443SRs` vs `relevantSRs`; `m.domains` vs `relevantDomains`
- [x] Fix renderCrossNist field mismatches: `m.iec62443SR` vs `srId`; `m.srName` (missing); `m.nistCsfSubcategories` vs `nistCsf`; similarity case mismatch

---

## Phase 2 — Core Data Gaps

- [x] Populate `standards/iec62443/system-requirements.json` — all 51 SRs across 7 FRs with descriptions, RE enhancements, OT context, NACSA mapping
- [x] Expand `evidence/index.json` — from 4 to 11 domains (add: IAM, remote-access, patch-vulnerability, monitoring-logging, physical-security, backup-recovery, supply-chain, configuration-management)
- [x] Add `requirements/by-domain/data-protection.json` — FR4 (Data Confidentiality) domain requirements
- [x] Expand `controls/library.json` — add physical-security controls, data-protection controls, expand IAM (RBAC, PAM, MFA controls)
- [x] Fix `iec62443-to-nist-csf.json` — add srName, fix field names, fix similarity casing, add all 51 SR entries

---

## Phase 3 — Mapping Enhancements

- [x] Add NACSA s19, s20, s24, s25 to `cross-references/iec62443-to-nacsa.json`
- [x] Convert `slToNacsaMapping` to proper array in `iec62443-to-nacsa.json`
- [x] Add `cross-references/mitre-to-controls.json` — 66 ICS techniques mapped to defensive controls and requirements
- [x] Add `cross-references/iec62443-to-nist80082.json` — IEC 62443 SR to NIST SP 800-82 Rev 3 section mapping
- [x] Add bidirectional lookup to NIST CSF cross-reference (CSF subcategory → which SRs)
- [x] Add sector `regulatoryOverlap` arrays in `sectors/index.json`
- [x] Add sector-specific content (sector controls/threats/requirements arrays)

---

## Phase 4 — Navigation & Framework View

- [x] Add Framework Mapping view to app.js — matrix showing IEC 62443 FRs × NACSA × NIST CSF × MITRE
- [x] Add Framework nav item to index.html
- [x] Add remaining requirement domains to nav (data-protection, config-management, monitoring-logging, backup-recovery, physical-security, supply-chain, asset-inventory)
- [x] Add MITRE → Controls defensive mapping view to app.js (new cross-ref tab)

---

## Phase 5 — Completeness & Quality

- [x] Add `LEARNINGS.md` — document patterns, pitfalls, and prevention checklist specific to OT Security repo
- [x] Expand monitoring-logging requirements (ML-R3 log retention/NACSA s26, ML-R4 threat hunting, ML-R5 SOC integration)
- [x] Expand physical-security requirements (PS-R3 personnel security, PS-R4 removable media/external device controls)
- [x] Expand backup-recovery requirements (BR-R3 backup integrity verification, BR-R4 RTO/RPO definition and testing)
- [x] Expand IAM requirements (IAM-R5 session management, IAM-R6 emergency access/break-glass)
- [x] Add sector-specific requirement files: sectors/requirements/energy.json, water.json, oil-gas.json, transport.json
- [x] Populate `artifacts/inventory.json` — expanded to 31 artifacts covering all domains
- [x] Add validation script (`validate.js`) — 11-check validator

---

## Phase 6 — Audit Package + Domain Standardization (Complete)

- [x] Standardize all domain IDs to canonical IDs from `requirements/index.json`
- [x] Add `controlSlugs[]` to all 31 artifacts in `artifacts/inventory.json`
- [x] Add `artifactSlugs[]` to all 36 evidence items in `evidence/index.json`
- [x] Add `data-protection` evidence section (3 items: E-DP-01, E-DP-02, E-DP-03)
- [x] Implement Audit Package UI in `renderControlDetail()` (accordion-based artifact cards + evidence checklist)
- [x] Add `sourceType` to all 19 JSON files missing it

---

## Phase 7 — Risk Management + Polish (Complete)

- [x] Risk methodology (OT/ICS-specific risk assessment)
- [x] 5x5 safety-weighted risk matrix
- [x] Risk register (20 OT/ICS risks across 7 categories)
- [x] 18-item risk assessment checklist
- [x] Treatment options (4 strategies with OT examples)
- [x] Dark mode toggle
- [x] Favicon
- [x] CSS fixes (layout, Purdue components rendering)
- [x] Fix hardcoded counts and stale documentation

---

## Remaining — Future Enhancements

- [ ] Export functionality (PDF/CSV export of controls, evidence, risk register)
- [ ] ARIA accessibility improvements (screen reader support, keyboard navigation)
- [ ] Manufacturing and building automation sector requirement files
- [x] Search functionality across all data layers
- [ ] Interactive Purdue model diagram
- [ ] SL gap assessment tool (current SL vs target SL analysis)

---

## Known Accuracy Notes

- IEC 62443 content is paraphrased — `sourceType: "paraphrased-from-standard"` on all IEC 62443 files. Obtain normative text from iec.ch.
- NACSA Act 854 section references verified: s17-s26 obligations. Codes of practice **not yet gazetted** as of 2026-03 — marked `constructed-indicative`.
- MITRE ATT&CK for ICS technique IDs (T0xxx) are public domain from attack.mitre.org/matrices/ics.
- NIST CSF 2.0 subcategory codes use `XX.YY-nn` format (e.g., `PR.AA-01`). Verify against nist.gov/cyberframework.
- NIST SP 800-82 Rev 3 references are public domain from nvlpubs.nist.gov.
- All gazette numbers, penalty figures, and legal cross-references must be verified against Federal Gazette before use in formal compliance work.
