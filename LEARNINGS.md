# LEARNINGS.md — OT Security Framework

Lessons from building and auditing this repository. Synthesised from patterns across the NACSA, RMIT, and PDPA-MY compliance repos. Read before generating any new content.

---

## Repo-Specific Lessons

### 1. Data Structure / App.js Mismatches — Silent Rendering Failures

Initial commit had several data-code mismatches that caused silent failures or JS errors:

| File | Data field | App.js expected | Impact |
|---|---|---|---|
| `security-levels.json` | `levels` | `securityLevels` | Empty SL cards |
| `security-levels.json` | `slTargetingProcess` (object) | `.map()` on array | Hard crash — "not a function" |
| `system-requirements.json` | `requirements` | `systemRequirements` | Empty SR table |
| `iec62443-to-nacsa.json` | `slToNacsaMapping` (object) | `.map()` on array | Hard crash |
| `iec62443-to-nist-csf.json` | `srId`, `nistCsf` | `iec62443SR`, `nistCsfSubcategories` | Empty NIST table |
| `requirements/index.json` | `primaryFR` | `primaryFRs` | No FR badges rendered |
| `requirements/by-domain/*.json` | `technical.summary`, `technical.actions` | `technical.requirement`, `technical.implementation` | Empty requirement detail |

**Lesson:** After generating any new JSON file, cross-reference every field name against the app.js renderer for that data. A single field name mismatch causes silent empty rendering or a hard crash. The crash variant (`TypeError: x.map is not a function`) is easier to catch than the silent variant (empty section with no error).

### 2. Empty `systemRequirements` Array — Already Populated in Initial Commit

`system-requirements.json` was initialised with `"systemRequirements": []` (empty array) but a parallel, correctly-structured `"requirements": [...]` array with all 51 SRs existed in the same file. The app.js checked for `systemRequirements` (empty) and returned "No data" without trying `requirements`. Both array names referenced the same data in different files.

**Lesson:** Use a single canonical field name across the entire repo. When a file is first created with an empty array placeholder, the app.js should defensively try alternative field names (`data.requirements || data.systemRequirements || []`). Better: agree on field names before writing the first file.

### 3. Evidence Coverage Gap — 4 of 11 Domains Only

Initial evidence index covered 4 of 11 security domains. The remaining 7 (IAM, remote access, patch/vuln, monitoring, physical security, backup, supply chain) had no evidence items despite having full requirements files. An auditor using this repo for a NACSA s23 assessment would have no evidence guidance for 64% of domains.

**Lesson:** Evidence and requirements are paired — for every requirements domain, there must be a corresponding evidence section. Build them in parallel, not as an afterthought. The evidence index should be checked against the requirements index as a validation step.

### 4. Domain ID Inconsistency — `safety-system` vs `safety-system-security`

The `requirements/index.json` uses domain ID `safety-system-security` (matching the filename). The `evidence/index.json` uses `safety-system`. The nav in `index.html` navigates to `safety-system-security`. The controls library uses `safety-system`. Three different IDs for the same domain.

**Lesson:** Define canonical domain IDs in one place (the requirements index is the source of truth) and use them everywhere: evidence keys, controls domain field, nav data-view attributes. A validation script should assert all IDs match.

### 5. `sourceType` and `verificationNote` on All Files

Every JSON file containing derived or paraphrased content must have:
- `"sourceType": "paraphrased-from-standard"` for IEC 62443 content
- `"sourceType": "constructed-indicative"` for NACSA COP content, cross-references, and framework mappings
- `"verificationNote": "..."` explaining what was paraphrased from where

This is critical for users who need to know whether they can rely on the content for formal compliance decisions.

### 6. NIST CSF 2.0 vs NIST SP 800-53 Code Format

NIST CSF 2.0 uses `XX.YY-nn` format: `PR.AA-01`, `DE.CM-01`, `GV.PO-01`. NIST SP 800-53 uses `XX-n` format: `AC-1`, `CM-3`. These are different frameworks with different code formats. Do not mix them. When mapping IEC 62443 SRs to NIST, specify which NIST framework and verify the code format.

---

## Common Patterns Inherited from NACSA, RMIT, PDPA-MY

### Pattern 1: AI Confabulation of Identifiers

Format-plausible but fabricated identifiers are the hardest to detect:
- NACSA repo: gazette numbers P.U.(A) 291-294/2024 instead of real 219-222/2024
- RMIT repo: clause numbers 10.58-10.63 (nonexistent) in cross-references
- PDPA-MY repo: amendment number Act A1699 instead of real Act A1727

**For OT Security:** Every IEC 62443 SR ID, MITRE technique ID (T0xxx), NIST CSF subcategory code, and gazette reference must be verified against the authoritative source. Format-plausible fabrications pass casual review.

### Pattern 2: Cascading Errors from Wrong Base Layer

If a base field is wrong (e.g., SR ID), every derived field (SR name, evidence items, controls mapping) that references it will be wrong. Fix the base before building derivatives.

**Prevention checklist for this repo:**
- [ ] All IEC 62443 SR IDs are in the range SR-1.1 to SR-7.8 (51 total)
- [ ] All MITRE ICS technique IDs start with T0 (not T1 which is Enterprise)
- [ ] All NIST CSF 2.0 codes use XX.YY-nn format
- [ ] NACSA sections referenced are s17-s26 (not s23 for everything — s26 is incident notification)
- [ ] `slToNacsaMapping` in nacsa cross-ref is an array `[{sl, nacsaMinimum, applicability}]` not an object

### Pattern 3: Status Misrepresentation

NACSA codes of practice under Act 854 were **not gazetted as of 2026-03**. Any content referencing them must be marked `constructed-indicative`. Do not mark any ungazetted instrument as `in-force` or `published`.

### Pattern 4: Hardcoded Counts in app.js

app.js has hardcoded counts like "51 SRs across 7 FRs" in `renderIecSR`. These break if data changes. Prefer dynamic counts from the loaded data: `allSRs.length` not the literal `51`.

### Pattern 5: Data Structure Assumes Array, Data Is Object

When a field can be rendered as a list but the data stores it as an object (e.g., `slToNacsaMapping`), calling `.map()` directly crashes. Always use `Array.isArray(x)` before calling `.map()` or convert objects to arrays at render time.

---

## Verification Checklist

Before publishing any new content in this repo:

- [ ] All IEC 62443 SR IDs verified as real (SR-1.1 through SR-7.8)
- [ ] All MITRE ATT&CK ICS technique IDs verified against attack.mitre.org/matrices/ics
- [ ] All NIST CSF 2.0 codes in `XX.YY-nn` format, not SP 800-53 format
- [ ] All NACSA section references are s17-s26 — s26 is incident notification, s23 is audit
- [ ] All gazette references include P.U. number and year — verify against official Gazette
- [ ] `sourceType` field present on every JSON file
- [ ] All codes of practice marked `constructed-indicative` until formally gazetted
- [ ] Field names in new JSON files cross-referenced against the app.js renderer for that view
- [ ] All cross-references resolvable in both directions (forward and reverse lookup works)
- [ ] Domain IDs consistent between `requirements/index.json`, `evidence/index.json`, `controls/library.json`, and `index.html` nav
- [ ] `slToNacsaMapping` is an array of objects, not a string-keyed object
- [ ] `sectors/index.json` has exactly 6 OT-focused sectors (10 NACSA NCII sectors total; 6 OT-relevant covered here)

---

## Outstanding Work

See `TODO.md` for the full tracked task list. Key remaining items:
1. NIST SP 800-82 → IEC 62443 cross-reference file (iec62443-to-nist80082.json)
2. Expand thin requirement domains (monitoring-logging, physical-security, backup-recovery)
3. Sector-specific requirement files (energy, water, oil-gas)
4. Artifacts inventory population
5. Validation script (validate.js) for automated consistency checks
