#!/usr/bin/env node
/**
 * validate.js — OT Security data integrity validator
 *
 * Checks:
 *   1.  All JSON files parse without errors
 *   2.  Controls library — slug uniqueness and required fields
 *   3.  Controls library — domain coverage
 *   4.  Artifact controlSlugs resolve to controls/library.json slugs
 *   5.  Evidence artifactSlugs resolve to artifacts/inventory.json IDs
 *   6.  Cross-reference integrity (IEC 62443, MITRE ATT&CK ICS)
 *   7.  Risk register math
 *   8.  No empty strings where data is expected
 *   9.  Unique IDs across data sets
 *   10. Standards & threats file integrity
 *
 * Usage: node validate.js [--verbose]
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const REPO_ROOT = __dirname;
const verbose   = process.argv.includes('--verbose');

let pass = 0;
let fail = 0;
let warn = 0;

function ok(msg)      { pass++; if (verbose) console.log(`  PASS  ${msg}`); }
function bad(msg)     { fail++; console.log(`  FAIL  ${msg}`); }
function warning(msg) { warn++; console.log(`  WARN  ${msg}`); }

function loadJson(relPath) {
  const abs = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(abs)) return null;
  try {
    return JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (e) {
    return null;
  }
}

// ── 1. JSON Parse Check ─────────────────────────────────────────────

console.log('\n=== 1. JSON Parse Check ===');

function findJsonFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      results.push(...findJsonFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      results.push(path.relative(REPO_ROOT, full));
    }
  }
  return results;
}

const jsonFiles = findJsonFiles(REPO_ROOT);
const parsed = {};
let parseErrors = 0;

for (const file of jsonFiles) {
  try {
    parsed[file] = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, file), 'utf8'));
    ok(`Parsed: ${file}`);
  } catch (e) {
    bad(`JSON parse error: ${file} — ${e.message}`);
    parseErrors++;
  }
}

if (parseErrors === 0) {
  ok(`All ${jsonFiles.length} JSON files parse correctly`);
}

// ── Load core data ──────────────────────────────────────────────────

const controlsLib   = loadJson('controls/library.json');  // top-level array
const domainsFile   = loadJson('controls/domains.json');  // top-level array
const artifactsInv  = loadJson('artifacts/inventory.json'); // top-level array
const evidence      = loadJson('evidence/index.json');
const requirements  = loadJson('requirements/index.json');
const riskRegister  = loadJson('risk-management/risk-register.json');

// OT-Security: library.json is a plain array of controls
const libraryControls = Array.isArray(controlsLib) ? controlsLib : (controlsLib && controlsLib.controls) || [];
const controlSlugSet = new Set(libraryControls.map(c => c.slug).filter(Boolean));

// domains.json is a plain array
const libraryDomains = Array.isArray(domainsFile) ? domainsFile : (domainsFile && domainsFile.domains) || [];
const domainIdSet = new Set(libraryDomains.map(d => d.id || d.slug).filter(Boolean));

// artifacts/inventory.json is a plain array
const allArtifacts = Array.isArray(artifactsInv) ? artifactsInv : (artifactsInv && artifactsInv.artifacts) || [];
const artifactIdSet = new Set(allArtifacts.map(a => a.id || a.slug).filter(Boolean));

// ── 2. Control Slug Uniqueness & Required Fields ─────────────────────

console.log('\n=== 2. Control Slug Uniqueness & Required Fields ===');

const slugCounts = {};
for (const ctrl of libraryControls) {
  if (!ctrl.slug) {
    bad(`Control missing "slug": ${(ctrl.name || '').slice(0, 60)}`);
  } else {
    slugCounts[ctrl.slug] = (slugCounts[ctrl.slug] || 0) + 1;
  }
  if (!ctrl.name || ctrl.name.trim() === '') bad(`Control "${ctrl.slug}" has empty or missing "name"`);
  if (!ctrl.domain) bad(`Control "${ctrl.slug}" missing "domain" field`);
}

const duplicates = Object.entries(slugCounts).filter(([, c]) => c > 1);
if (duplicates.length === 0) {
  ok(`No duplicate control slugs (${libraryControls.length} controls)`);
} else {
  for (const [slug, count] of duplicates) bad(`Duplicate control slug "${slug}" appears ${count} times`);
}

// ── 3. Domain Coverage ───────────────────────────────────────────────

console.log('\n=== 3. Controls Library — Domain Coverage ===');

const controlsByDomain = {};
for (const ctrl of libraryControls) {
  if (ctrl.domain) controlsByDomain[ctrl.domain] = (controlsByDomain[ctrl.domain] || 0) + 1;
}

for (const dom of libraryDomains) {
  const key = dom.id || dom.slug;
  if (!controlsByDomain[key]) {
    bad(`Domain "${key}" has zero controls in library.json`);
  } else {
    ok(`Domain "${key}" has ${controlsByDomain[key]} control(s)`);
  }
}

let domainRefErrors = 0;
for (const ctrl of libraryControls) {
  if (ctrl.domain && domainIdSet.size > 0 && !domainIdSet.has(ctrl.domain)) {
    bad(`Control "${ctrl.slug}" references unknown domain "${ctrl.domain}"`);
    domainRefErrors++;
  }
}
if (domainRefErrors === 0 && libraryControls.length > 0) {
  ok(`All ${libraryControls.length} controls reference valid domains`);
}

// ── 4. Artifact controlSlugs Resolution ──────────────────────────────

console.log('\n=== 4. Artifact controlSlugs Resolution ===');

let controlSlugErrors = 0;
let controlSlugTotal = 0;

for (const artifact of allArtifacts) {
  if (!artifact.controlSlugs) continue;
  for (const slug of artifact.controlSlugs) {
    controlSlugTotal++;
    if (!controlSlugSet.has(slug)) {
      bad(`Artifact "${artifact.id}" references unknown control slug "${slug}"`);
      controlSlugErrors++;
    }
  }
}

if (controlSlugErrors === 0) {
  ok(`All ${controlSlugTotal} controlSlug references in artifacts resolve correctly`);
}

// ── 5. Evidence artifactSlugs Resolution ─────────────────────────────

console.log('\n=== 5. Evidence artifactSlugs Resolution ===');

let artifactSlugErrors = 0;
let artifactSlugTotal = 0;

if (evidence && evidence.evidenceByDomain) {
  for (const [domKey, domData] of Object.entries(evidence.evidenceByDomain)) {
    const items = domData.evidenceItems || domData.items || [];
    for (const item of items) {
      if (!item.artifactSlugs) continue;
      for (const slug of item.artifactSlugs) {
        artifactSlugTotal++;
        if (!artifactIdSet.has(slug)) {
          bad(`Evidence "${item.id}" references unknown artifact "${slug}"`);
          artifactSlugErrors++;
        }
      }
    }
  }
}

if (artifactSlugErrors === 0) {
  ok(`All ${artifactSlugTotal} artifactSlug references in evidence resolve correctly`);
}

// ── 6. Cross-Reference Integrity ─────────────────────────────────────

console.log('\n=== 6. Cross-Reference Integrity ===');

const crossRefFiles = findJsonFiles(path.join(REPO_ROOT, 'cross-references'));
for (const file of crossRefFiles) {
  if (!parsed[file]) bad(`Cross-reference file failed to load: ${file}`);
  else ok(`Cross-reference loaded: ${file}`);
}

// ── 7. Risk Register Math ────────────────────────────────────────────

console.log('\n=== 7. Risk Register Math ===');

if (riskRegister && riskRegister.risks) {
  let mathErrors = 0;
  for (const risk of riskRegister.risks) {
    if (risk.likelihood != null && risk.impact != null && risk.inherentRisk != null) {
      const expected = risk.likelihood * risk.impact;
      if (risk.inherentRisk !== expected) {
        bad(`${risk.id}: inherentRisk ${risk.inherentRisk} != ${risk.likelihood} x ${risk.impact} = ${expected}`);
        mathErrors++;
      }
    }
    if (risk.residualLikelihood != null && risk.residualImpact != null && risk.residualRisk != null) {
      const expected = risk.residualLikelihood * risk.residualImpact;
      if (risk.residualRisk !== expected) {
        bad(`${risk.id}: residualRisk ${risk.residualRisk} != ${risk.residualLikelihood} x ${risk.residualImpact} = ${expected}`);
        mathErrors++;
      }
    }
  }
  if (mathErrors === 0) ok(`All ${riskRegister.risks.length} risk register entries have correct math`);
} else {
  ok('No risk register with risks array found (skipping)');
}

// ── 8. Data Completeness ─────────────────────────────────────────────

console.log('\n=== 8. Data Completeness ===');

let emptyIssues = 0;
for (const ctrl of libraryControls) {
  if (ctrl.description && ctrl.description.trim() === '') { bad(`Control "${ctrl.slug}" has empty description`); emptyIssues++; }
}
for (const artifact of allArtifacts) {
  if (artifact.name && artifact.name.trim() === '') { bad(`Artifact "${artifact.id}" has empty name`); emptyIssues++; }
}
if (emptyIssues === 0) ok('No empty strings detected in core data');

// ── 9. Unique IDs ───────────────────────────────────────────────────

console.log('\n=== 9. Unique IDs ===');

const seenArtIds = {};
for (const art of allArtifacts) {
  const key = art.id || art.slug;
  if (key) seenArtIds[key] = (seenArtIds[key] || 0) + 1;
}
const artDups = Object.entries(seenArtIds).filter(([, c]) => c > 1);
if (artDups.length === 0) ok(`All ${allArtifacts.length} artifact IDs are unique`);
else for (const [id, count] of artDups) bad(`Duplicate artifact ID "${id}" appears ${count} times`);

// ── 10. Standards & Threats Integrity ────────────────────────────────

console.log('\n=== 10. Standards & Threats Integrity ===');

const standardsFiles = findJsonFiles(path.join(REPO_ROOT, 'standards'));
const threatFiles = findJsonFiles(path.join(REPO_ROOT, 'threats'));
const sectorFiles = findJsonFiles(path.join(REPO_ROOT, 'sectors'));

for (const file of [...standardsFiles, ...threatFiles, ...sectorFiles]) {
  if (!parsed[file]) bad(`File failed to load: ${file}`);
  else ok(`Loaded: ${file}`);
}

// ── Summary ──────────────────────────────────────────────────────────

console.log('\n' + '='.repeat(60));
console.log('Validation complete:');
console.log(`  Pass: ${pass}`);
console.log(`  Fail: ${fail}`);
console.log(`  Warn: ${warn}`);
console.log(`  Total: ${pass + fail + warn}`);
console.log('='.repeat(60));

if (fail > 0) {
  console.error(`\nValidation FAILED with ${fail} error(s).`);
  process.exit(1);
} else if (warn > 0) {
  console.log(`\nValidation passed with ${warn} warning(s).`);
  process.exit(0);
} else {
  console.log('\nAll checks passed.');
  process.exit(0);
}
