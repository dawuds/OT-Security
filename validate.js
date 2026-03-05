#!/usr/bin/env node
/**
 * validate.js — OT Security Framework consistency validator
 *
 * Checks:
 *   1. All JSON files parse without errors
 *   2. Requirements index domain IDs match actual file names
 *   3. All requirement domain files are referenced in requirements/index.json
 *   4. Evidence domains have corresponding requirement domains
 *   5. Control slugs in controls/library.json are unique
 *   6. MITRE technique IDs in mitre-to-controls.json use T0xxx format (not T1)
 *   7. slToNacsaMapping in iec62443-to-nacsa.json is an array
 *   8. All sectors have array regulatoryOverlap
 *   9. SR IDs in system-requirements.json are in SR-x.y format (SR-1.1 through SR-7.8)
 *  10. 51 SRs present in system-requirements.json
 *  11. All controlSlugs in mitre-to-controls.json reference existing control slugs
 *  12. Cross-reference files have required sourceType field
 *  13. Domain IDs are consistent across requirements/index.json, evidence/index.json,
 *      controls/library.json, and index.html nav
 *
 * Usage: node validate.js [--verbose]
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const REPO_ROOT = __dirname;
const verbose   = process.argv.includes('--verbose');

let errors   = 0;
let warnings = 0;
let passed   = 0;

function ok(msg) {
  if (verbose) console.log(`  ✓ ${msg}`);
  passed++;
}

function warn(msg) {
  console.warn(`  ⚠ WARN: ${msg}`);
  warnings++;
}

function fail(msg) {
  console.error(`  ✗ FAIL: ${msg}`);
  errors++;
}

function section(title) {
  console.log(`\n[ ${title} ]`);
}

function loadJson(relPath) {
  const abs = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(abs)) {
    fail(`File not found: ${relPath}`);
    return null;
  }
  try {
    const raw = fs.readFileSync(abs, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    fail(`JSON parse error in ${relPath}: ${e.message}`);
    return null;
  }
}

// ─── 1. Parse all JSON files ────────────────────────────────────────────────

section('1. JSON Parse Validation');

const jsonPaths = [];
function collectJson(dir) {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel  = path.relative(REPO_ROOT, full);
    if (entry.isDirectory()) {
      collectJson(full);
    } else if (entry.name.endsWith('.json')) {
      jsonPaths.push(rel);
    }
  }
}
collectJson(REPO_ROOT);

const parsedFiles = {};
for (const relPath of jsonPaths) {
  const data = loadJson(relPath);
  if (data !== null) {
    parsedFiles[relPath] = data;
    ok(`Parsed: ${relPath}`);
  }
}

// ─── 2. Requirements index vs actual files ───────────────────────────────────

section('2. Requirements Index ↔ Domain Files');

const reqIndex = parsedFiles['requirements/index.json'];
if (reqIndex) {
  const indexedDomainIds = new Set();
  for (const domain of (reqIndex.domains || [])) {
    indexedDomainIds.add(domain.id);
    const file = domain.file;
    if (!file) {
      fail(`Domain ${domain.id}: missing "file" field in requirements/index.json`);
      continue;
    }
    if (!fs.existsSync(path.join(REPO_ROOT, file))) {
      fail(`Domain ${domain.id}: referenced file "${file}" does not exist`);
    } else {
      ok(`Domain ${domain.id}: file "${file}" exists`);
    }
  }

  // Check all by-domain files are indexed
  const byDomainDir = path.join(REPO_ROOT, 'requirements/by-domain');
  if (fs.existsSync(byDomainDir)) {
    for (const fn of fs.readdirSync(byDomainDir)) {
      if (!fn.endsWith('.json')) continue;
      const rel = `requirements/by-domain/${fn}`;
      const indexed = (reqIndex.domains || []).some(d => d.file === rel);
      if (!indexed) {
        fail(`File "${rel}" exists but is NOT referenced in requirements/index.json`);
      } else {
        ok(`"${rel}" is referenced in requirements/index.json`);
      }
    }
  }
}

// ─── 3. Evidence domains have corresponding requirement domains ──────────────

section('3. Evidence ↔ Requirements Domain Pairing');

const evidenceIndex = parsedFiles['evidence/index.json'];
if (evidenceIndex && reqIndex) {
  const reqDomainIds = new Set((reqIndex.domains || []).map(d => d.id));
  // evidence/index.json stores domain entries under evidenceByDomain key
  const evidenceDomains = evidenceIndex.evidenceByDomain || evidenceIndex;
  for (const [domId] of Object.entries(evidenceDomains)) {
    if (domId === '$schema' || domId === 'description' || domId === 'auditorNote' || domId === 'totalDomains') continue;
    if (!reqDomainIds.has(domId)) {
      warn(`Evidence domain "${domId}" has no matching requirements domain in requirements/index.json`);
    } else {
      ok(`Evidence domain "${domId}" has matching requirements domain`);
    }
  }
}

// ─── 4. Control slugs unique ─────────────────────────────────────────────────

section('4. Controls Library — Slug Uniqueness');

const controlsLib = parsedFiles['controls/library.json'];
let controlSlugs  = new Set();
if (controlsLib) {
  const controls = controlsLib.controls || [];
  const slugCounts = {};
  for (const ctrl of controls) {
    if (!ctrl.slug) {
      fail(`Control missing "slug" field: ${ctrl.name || JSON.stringify(ctrl).slice(0, 60)}`);
    } else {
      slugCounts[ctrl.slug] = (slugCounts[ctrl.slug] || 0) + 1;
    }
  }
  for (const [slug, count] of Object.entries(slugCounts)) {
    controlSlugs.add(slug);
    if (count > 1) {
      fail(`Duplicate control slug: "${slug}" appears ${count} times`);
    } else {
      ok(`Control slug unique: "${slug}"`);
    }
  }
  ok(`Total controls: ${controls.length}`);
}

// ─── 5. MITRE technique IDs use T0xxx format ────────────────────────────────

section('5. MITRE ATT&CK for ICS — Technique ID Format');

const mitreToControls = parsedFiles['cross-references/mitre-to-controls.json'];
if (mitreToControls) {
  const techniques = mitreToControls.mappings || mitreToControls.techniques || mitreToControls;
  const techniqueList = Array.isArray(techniques) ? techniques : [];
  for (const t of techniqueList) {
    const id = t.techniqueId;
    if (!id) {
      fail(`MITRE mapping missing techniqueId: ${JSON.stringify(t).slice(0, 80)}`);
    } else if (!/^T0\d{3,4}$/.test(id)) {
      fail(`MITRE technique ID "${id}" does not match T0xxx ICS format (T1xxx is Enterprise ATT&CK — wrong matrix)`);
    } else {
      ok(`Technique ID valid: ${id} — ${t.name || ''}`);
    }
  }

  // 11. Control slugs referenced in mitre-to-controls.json exist in library
  if (controlsLib && controlSlugs.size > 0) {
    section('5b. MITRE → Controls — Slug Resolution');
    for (const t of techniqueList) {
      for (const slug of (t.controlSlugs || [])) {
        if (!controlSlugs.has(slug)) {
          fail(`Technique ${t.techniqueId}: controlSlug "${slug}" not found in controls/library.json`);
        } else {
          ok(`Resolved: ${t.techniqueId} → "${slug}"`);
        }
      }
    }
  }
}

// ─── 6. slToNacsaMapping is an array ────────────────────────────────────────

section('6. NACSA Cross-Reference — slToNacsaMapping Type');

const nacsaCrossRef = parsedFiles['cross-references/iec62443-to-nacsa.json'];
if (nacsaCrossRef) {
  const slMapping = nacsaCrossRef.slToNacsaMapping;
  if (!slMapping) {
    fail('iec62443-to-nacsa.json: missing slToNacsaMapping field');
  } else if (!Array.isArray(slMapping)) {
    fail(`iec62443-to-nacsa.json: slToNacsaMapping is ${typeof slMapping}, expected array — will cause .map() crash`);
  } else {
    ok(`slToNacsaMapping is an array with ${slMapping.length} entries`);
    for (const entry of slMapping) {
      if (typeof entry.sl !== 'number') {
        warn(`slToNacsaMapping entry missing numeric "sl" field: ${JSON.stringify(entry).slice(0, 60)}`);
      }
    }
  }
}

// ─── 7. Sectors have array regulatoryOverlap ────────────────────────────────

section('7. Sectors — regulatoryOverlap Array Type');

const sectorsIndex = parsedFiles['sectors/index.json'];
if (sectorsIndex) {
  for (const sector of (sectorsIndex.sectors || [])) {
    const ro = sector.regulatoryOverlap;
    if (!ro) {
      warn(`Sector "${sector.id}": missing regulatoryOverlap field`);
    } else if (!Array.isArray(ro)) {
      fail(`Sector "${sector.id}": regulatoryOverlap is ${typeof ro}, expected array — will cause .map() crash`);
    } else {
      ok(`Sector "${sector.id}": regulatoryOverlap is array with ${ro.length} entries`);
    }
  }
}

// ─── 8. SR IDs and count ─────────────────────────────────────────────────────

section('8. System Requirements — SR ID Format and Count');

const sysReqFile = parsedFiles['standards/iec62443/system-requirements.json'];
if (sysReqFile) {
  const allSRs = sysReqFile.systemRequirements || sysReqFile.requirements || [];
  ok(`Total SRs found: ${allSRs.length}`);
  if (allSRs.length !== 51) {
    fail(`Expected 51 SRs (IEC 62443-3-3 defines exactly 51 SRs across FR1-FR7), found ${allSRs.length}`);
  } else {
    ok('SR count: 51 ✓');
  }

  const srPattern = /^SR-[1-7]\.\d{1,2}$/;
  const seenSRIds = new Set();
  for (const sr of allSRs) {
    const id = sr.id;
    if (!id) {
      fail(`SR missing "id" field: ${JSON.stringify(sr).slice(0, 60)}`);
    } else if (!srPattern.test(id)) {
      fail(`SR ID "${id}" does not match SR-x.y format (valid range: SR-1.1 to SR-7.8)`);
    } else if (seenSRIds.has(id)) {
      fail(`Duplicate SR ID: "${id}"`);
    } else {
      seenSRIds.add(id);
      ok(`SR ID valid: ${id}`);
    }
  }
}

// ─── 9. sourceType on cross-reference files ──────────────────────────────────

section('9. Cross-Reference Files — sourceType Field');

const crossRefDir = path.join(REPO_ROOT, 'cross-references');
if (fs.existsSync(crossRefDir)) {
  for (const fn of fs.readdirSync(crossRefDir)) {
    if (!fn.endsWith('.json')) continue;
    const rel  = `cross-references/${fn}`;
    const data = parsedFiles[rel];
    if (data) {
      if (!data.sourceType) {
        fail(`${rel}: missing "sourceType" field — required on all cross-reference files`);
      } else {
        ok(`${rel}: sourceType = "${data.sourceType}"`);
      }
    }
  }
}

// ─── 10. Domain ID consistency in index.html nav ────────────────────────────

section('10. Domain ID Consistency — index.html Nav');

const indexHtml = path.join(REPO_ROOT, 'index.html');
if (fs.existsSync(indexHtml) && reqIndex) {
  const html = fs.readFileSync(indexHtml, 'utf8');
  const reqDomainIds = (reqIndex.domains || []).map(d => d.id);
  for (const domId of reqDomainIds) {
    if (html.includes(`navigate('requirements','${domId}')`)) {
      ok(`Nav link found for domain: "${domId}"`);
    } else {
      warn(`No nav link in index.html for requirements domain "${domId}" — consider adding to sidebar`);
    }
  }
}

// ─── 11. NACSA sections reference range s17-s26 ─────────────────────────────

section('11. NACSA Section References — Valid Range (s17-s26)');

if (nacsaCrossRef) {
  const validSections = new Set(['s17','s18','s19','s20','s21','s22','s23','s24','s25','s26']);
  for (const mapping of (nacsaCrossRef.mappings || [])) {
    const sec = mapping.nacsaSection;
    if (!validSections.has(sec)) {
      fail(`iec62443-to-nacsa.json: nacsaSection "${sec}" is outside valid range s17-s26`);
    } else {
      ok(`NACSA section valid: ${sec}`);
    }
  }
}

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log('\n' + '─'.repeat(60));
console.log(`Validation complete:`);
console.log(`  Passed:   ${passed}`);
console.log(`  Warnings: ${warnings}`);
console.log(`  Failed:   ${errors}`);
console.log('─'.repeat(60));

if (errors > 0) {
  console.error(`\nValidation FAILED with ${errors} error(s). Fix before publishing.`);
  process.exit(1);
} else if (warnings > 0) {
  console.warn(`\nValidation passed with ${warnings} warning(s). Review warnings before publishing.`);
  process.exit(0);
} else {
  console.log('\nAll checks passed.');
  process.exit(0);
}
