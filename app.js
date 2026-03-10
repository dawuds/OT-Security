/* OT Security Framework — SPA v2.0
   GRC Presentation Standard compliant.
   Static, zero-dependency, hash-routed.
   Data loaded lazily and cached in Map.
*/

'use strict';

// --- State ---
const cache = new Map();
let searchQuery = '';

// --- Fetch error UI ---
function renderFetchError(el, url, error) {
  el.innerHTML = '<div class="fetch-error">' +
    '<h2>Failed to load data</h2>' +
    '<p>Could not fetch <strong>' + escHtml(url) + '</strong></p>' +
    (error ? '<p class="error-detail">' + escHtml(String(error)) + '</p>' : '') +
    '<button onclick="location.reload()">Retry</button>' +
    '</div>';
}

// --- Data loader ---
async function load(path) {
  if (cache.has(path)) return cache.get(path);
  try {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    cache.set(path, data);
    return data;
  } catch (e) {
    console.error(`Failed to load ${path}:`, e);
    const app = document.getElementById('app');
    if (app) renderFetchError(app, path, e);
    return null;
  }
}

// --- Router (single-hash pattern) ---
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '') || 'overview';
  const i = raw.indexOf('/');
  if (i === -1) return { view: raw, sub: null };
  return { view: raw.substring(0, i), sub: raw.substring(i + 1) };
}

function navigate(hash) {
  location.hash = '#' + hash;
}

async function route() {
  const { view, sub } = parseHash();
  updateNav(view);
  const app = document.getElementById('app');
  app.innerHTML = '<div class="loading"><div class="spinner"></div><span>Loading...</span></div>';
  try {
    await render(view, sub);
  } catch (e) {
    app.innerHTML = '<div class="error-state"><h2>Failed to load data</h2><p class="error-message">' + escHtml(e.message) + '</p><button onclick="location.reload()">Retry</button></div>';
    console.error(e);
  }
}

function updateNav(view) {
  document.querySelectorAll('.nav-link').forEach(function(el) {
    var dv = el.dataset.view;
    el.classList.toggle('active', dv === view || (view === 'overview' && dv === 'overview') || (view === 'control' && dv === 'controls'));
  });
}

// --- Main dispatcher ---
async function render(view, sub) {
  switch (view) {
    case 'overview':     return renderOverview();
    case 'framework':    return renderFramework(sub);
    case 'controls':     return renderControls(sub);
    case 'control':      return renderControlBySlug(sub);
    case 'risk':         return renderRiskManagement(sub);
    case 'threats':      return renderThreats(sub);
    case 'threat':       return renderThreatDetail(sub);
    case 'sectors':      return renderSectors(sub);
    case 'sector':       return renderSectorById(sub);
    case 'architecture': return renderArchitecture(sub);
    case 'reference':    return renderReference(sub);
    case 'search':       return renderSearch(sub);
    default:             return renderOverview();
  }
}

// --- Helpers ---
function setHTML(html) {
  document.getElementById('app').innerHTML = html;
}

function slBadge(sl) {
  if (!sl && sl !== 0) return '';
  var n = String(sl).replace('SL','').replace(' ','').replace(/[^0-9]/g,'');
  if (!n) n = '2';
  return '<span class="badge badge-sl' + n + '">SL ' + n + '</span>';
}

function slDots(level) {
  var n = parseInt(String(level).replace(/[^0-9]/g,'')) || 0;
  return '<div class="sl-indicator">' + [1,2,3,4].map(function(i) {
    return '<div class="sl-dot' + (i <= n ? ' active-' + n : '') + '"></div>';
  }).join('') + '</div>';
}

function typeBadge(type) {
  if (!type) return '';
  var map = { preventive:'preventive', detective:'detective', corrective:'corrective' };
  return '<span class="badge badge-' + (map[type] || '') + '">' + type + '</span>';
}

function nacsaBadge(codes) {
  if (!codes || !codes.length) return '';
  return codes.map(function(c) { return '<span class="badge badge-malaysia">' + escHtml(c) + '</span>'; }).join(' ');
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function tagList(arr) {
  if (!arr || !arr.length) return '';
  return '<div class="tag-list">' + arr.map(function(t) { return '<span class="tag">' + escHtml(t) + '</span>'; }).join('') + '</div>';
}


// --- OVERVIEW ---
async function renderOverview() {
  const [reqs, controls, incidents, actors, sectors, srData] = await Promise.all([
    load('requirements/index.json'),
    load('controls/library.json'),
    load('threats/known-incidents.json'),
    load('threats/threat-actors.json'),
    load('sectors/index.json'),
    load('standards/iec62443/system-requirements.json'),
  ]);

  const allSRs = srData.systemRequirements || srData.requirements || [];
  const srCount = allSRs.length;
  const domainCount = reqs.domains ? reqs.domains.length : 12;
  const controlCount = Array.isArray(controls) ? controls.length : 0;
  const incidentCount = incidents.incidents ? incidents.incidents.length : 0;
  const actorCount = actors.threatActors ? actors.threatActors.length : 0;
  const sectorCount = sectors.sectors ? sectors.sectors.length : 0;

  const quickLinks = [
    { icon: '', label: 'IEC 62443 System Requirements', hash: 'framework/iec-sr', desc: srCount + ' SRs with SL 1-4 descriptions and NACSA mappings' },
    { icon: '', label: 'Purdue Model Architecture', hash: 'architecture/purdue', desc: 'Levels 0-5 with asset types, protocols, and security controls' },
    { icon: '', label: 'Controls Library', hash: 'controls', desc: controlCount + ' controls with audit packages, evidence, and artifacts' },
    { icon: '', label: 'Safety System Security', hash: 'controls', desc: 'SIS isolation, program integrity, TRITON lessons' },
    { icon: '', label: 'Incident Response & NACSA s26', hash: 'controls', desc: '6-hour notification procedure and OT IRP requirements' },
    { icon: '', label: 'Known OT Incidents', hash: 'threats/incidents', desc: 'Stuxnet, TRITON, Ukraine, Colonial Pipeline, Oldsmar' },
  ];

  const sectors_html = sectors.sectors ? sectors.sectors.map(function(s) {
    return `
    <a class="control-card control-card-link" href="#sector/${s.id}" style="text-decoration:none;color:inherit">
      <div class="control-card-title">${escHtml(s.name)}</div>
      <div class="control-card-desc">${escHtml(s.nacsaSectorLead || '')}</div>
      <div class="control-card-meta">${nacsaBadge(['NACSA'])}</div>
    </a>`;}).join('') : '';

  setHTML(`
    <div class="disclaimer">
      <strong>Educational use only.</strong> IEC 62443 content is paraphrased — obtain normative text from iec.ch.
      NACSA Act 854 references are indicative — verify against official Gazette.
    </div>
    <div class="page-title">OT Security Framework</div>
    <div class="page-sub">IEC 62443 · NIST SP 800-82 · MITRE ATT&amp;CK for ICS · NACSA Act 854 (Malaysia)</div>
    <div class="stats-banner">
      <div class="stat-card"><div class="stat-value">${srCount}</div><div class="stat-label">IEC 62443 SRs</div></div>
      <div class="stat-card"><div class="stat-value">${domainCount}</div><div class="stat-label">Security Domains</div></div>
      <div class="stat-card"><div class="stat-value">${controlCount}</div><div class="stat-label">Controls</div></div>
      <div class="stat-card"><div class="stat-value">${incidentCount}</div><div class="stat-label">Incidents</div></div>
      <div class="stat-card"><div class="stat-value">${actorCount}</div><div class="stat-label">Threat Actors</div></div>
      <div class="stat-card"><div class="stat-value">${sectorCount}</div><div class="stat-label">Sectors</div></div>
      <div class="stat-card"><div class="stat-value">4</div><div class="stat-label">Security Levels</div></div>
      <div class="stat-card"><div class="stat-value">6</div><div class="stat-label">NACSA s26</div><div class="stat-label" style="font-size:0.6rem">hour notification</div></div>
    </div>
    <h2>Quick Start</h2>
    <div class="control-grid" style="margin-bottom:1.5rem">
      ${quickLinks.map(l => `
        <a class="control-card control-card-link" href="#${l.hash}" style="text-decoration:none;color:inherit">
          <div class="control-card-title">${escHtml(l.label)}</div>
          <div class="control-card-desc">${escHtml(l.desc)}</div>
        </a>`).join('')}
    </div>
    <h2>Sectors &amp; Malaysia NCII</h2>
    <div class="control-grid">${sectors_html}</div>
    <h2>Security Level Reference</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>SL</th><th>Label</th><th>Threat Profile</th><th>Malaysia Context</th></tr></thead>
      <tbody>
        <tr class="sl-row-1"><td>${slBadge(1)}</td><td>Basic</td><td>Casual / opportunistic</td><td>Non-NCII OT environments</td></tr>
        <tr class="sl-row-2"><td>${slBadge(2)}</td><td>Enhanced</td><td>Motivated, generic IT skills</td><td>NCII baseline for most OT sectors</td></tr>
        <tr class="sl-row-3"><td>${slBadge(3)}</td><td>Advanced</td><td>OT-expert attacker</td><td>High-criticality NCII assets</td></tr>
        <tr class="sl-row-4"><td>${slBadge(4)}</td><td>Critical</td><td>Nation-state, SIS-targeting</td><td>Safety Instrumented Systems</td></tr>
      </tbody>
    </table></div>
    <h2>NACSA Act 854 Key Obligations for OT Operators</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Section</th><th>Obligation</th><th>OT Framework Response</th></tr></thead>
      <tbody>
        <tr><td><span class="badge badge-malaysia">s17</span></td><td>NCII designation</td><td>Asset inventory (SR-7.8) defines NCII asset scope</td></tr>
        <tr><td><span class="badge badge-malaysia">s18</span></td><td>Security measures</td><td>IEC 62443 SL 2 minimum; SL 3 for critical assets</td></tr>
        <tr><td><span class="badge badge-malaysia">s21</span></td><td>Risk assessment</td><td>IEC 62443-3-2 zone-based risk assessment methodology</td></tr>
        <tr><td><span class="badge badge-malaysia">s22</span></td><td>Code of practice</td><td>Sector COP mapping in cross-references</td></tr>
        <tr><td><span class="badge badge-malaysia">s23</span></td><td>Security audit</td><td>IEC 62443-3-3 SL assessment by NACSA-licensed auditor</td></tr>
        <tr><td><span class="badge badge-malaysia">s26</span></td><td>Incident notification</td><td><strong>6-hour</strong> initial notification + 72-hour + 30-day reports</td></tr>
      </tbody>
    </table></div>
  `);
}


// --- FRAMEWORK ---
async function renderFramework(sub) {
  const srData = await load('standards/iec62443/system-requirements.json');
  const srTotal = (srData.systemRequirements || srData.requirements || []).length;
  const tabs = [
    { id: 'iec-overview', label: 'IEC 62443 Overview' },
    { id: 'iec-sl',       label: 'Security Levels' },
    { id: 'iec-fr',       label: 'Foundational Requirements' },
    { id: 'iec-sr',       label: 'System Requirements (' + srTotal + ' SRs)' },
    { id: 'nist',         label: 'NIST SP 800-82' },
    { id: 'mitre',        label: 'MITRE ATT&CK for ICS' },
  ];
  const active = sub || 'iec-overview';

  const tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'framework/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'iec-overview')  content = await renderIecOverview();
  else if (active === 'iec-sl')   content = await renderIecSL();
  else if (active === 'iec-fr')   content = await renderIecFR();
  else if (active === 'iec-sr')   content = await renderIecSR();
  else if (active === 'nist')     content = await renderNist();
  else if (active === 'mitre')    content = await renderMitre();

  setHTML('\
    <div class="page-title">Framework</div>\
    <div class="page-sub">IEC 62443 · NIST SP 800-82 Rev 3 · MITRE ATT&amp;CK for ICS</div>' +
    tabsHtml + content
  );
}

async function renderIecOverview() {
  const data = await load('standards/iec62443/index.json');
  // data.series is [{id, title, description, parts:[{part, title, status, keyContent}]}]
  var seriesHtml = '';
  if (data.series) {
    data.series.forEach(function(s) {
      (s.parts || []).forEach(function(p) {
        seriesHtml += '<tr>\
          <td><strong>' + escHtml(p.part) + '</strong></td>\
          <td>' + escHtml(p.title) + '</td>\
          <td style="font-size:0.75rem">' + escHtml(p.keyContent || '') + '</td>\
          <td>' + escHtml(p.status || '') + '</td>\
        </tr>';
      });
    });
  }

  const conceptsHtml = data.keyConceptSummary ? Object.entries(data.keyConceptSummary).map(function(e) {
    var k = e[0], v = e[1];
    var desc = typeof v === 'string' ? v : (v.definition || JSON.stringify(v));
    return '<div class="control-card">\
      <div class="control-card-title">' + escHtml(k.toUpperCase()) + '</div>\
      <div class="control-card-desc">' + escHtml(desc) + '</div></div>';
  }).join('') : '';

  var malaysiaNexusHtml = '';
  if (data.malaysiaNexus) {
    var nexusText = typeof data.malaysiaNexus === 'string' ? data.malaysiaNexus : (data.malaysiaNexus.summary || '');
    malaysiaNexusHtml = '\
    <h2>Malaysia NCII Nexus</h2>\
    <div class="control-card"><div class="control-card-desc">' + escHtml(nexusText) + '</div></div>';
  }

  return '\
    <div class="disclaimer">' + escHtml(data.verificationNote || 'Paraphrased from IEC 62443') + '</div>\
    <h2>' + escHtml(data.fullTitle || data.title || 'IEC 62443') + '</h2>\
    <div class="detail-body" style="margin-bottom:1rem">' + escHtml(data.scope || data.overview || '') + '</div>\
    <h2>Series Breakdown</h2>\
    <div class="table-wrap"><table>\
      <thead><tr><th>Part</th><th>Title</th><th>Scope</th><th>Status</th></tr></thead>\
      <tbody>' + seriesHtml + '</tbody>\
    </table></div>\
    <h2>Key Concepts</h2>\
    <div class="control-grid">' + conceptsHtml + '</div>' + malaysiaNexusHtml;
}

async function renderIecSL() {
  const data = await load('standards/iec62443/security-levels.json');
  const levelsHtml = data.levels ? data.levels.map(function(sl) { return '\
    <div class="control-card">\
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">' +
        slBadge(sl.sl) + ' ' + slDots(sl.sl) +
        '<span class="control-card-title" style="margin:0">' + escHtml(sl.label) + '</span>\
      </div>\
      <div class="control-card-desc">' + escHtml(sl.shortDescription || sl.description || '') + '</div>\
      <div class="detail-section" style="margin-top:0.75rem">\
        <div style="font-size:0.75rem;color:var(--text-secondary)"><strong>Threat Profile:</strong> ' + escHtml(sl.threatProfile || '') + '</div>\
        <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem"><strong>Malaysia Context:</strong> ' + escHtml(sl.malaysiaContext || '') + '</div>' +
        (Array.isArray(sl.typicalApplicability) ? '<div style="margin-top:0.35rem"><div style="font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.25rem">Typical Applicability</div>' + tagList(sl.typicalApplicability) + '</div>' : '') +
      '</div>' +
      (sl.controlCharacteristics ? '<div style="margin-top:0.75rem"><div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.35rem">Control Characteristics</div>' + (typeof sl.controlCharacteristics === 'string' ? '<p style="font-size:0.8rem;color:var(--text-secondary)">' + escHtml(sl.controlCharacteristics) + '</p>' : tagList(sl.controlCharacteristics)) + '</div>' : '') +
    '</div>';}).join('') : '';

  return '\
    <h2>Security Level Definitions</h2>\
    <div class="control-grid">' + levelsHtml + '</div>' +
    (data.slTargetingProcess ? '\
      <h2>SL Targeting Process (IEC 62443-3-2)</h2>\
      <div class="control-card-desc" style="margin-bottom:0.75rem">' + escHtml(data.slTargetingProcess.description || '') + '</div>\
      <div class="attack-chain">' + (data.slTargetingProcess.steps || []).map(function(step) { return '<div class="attack-step"><strong>Step ' + step.step + ':</strong> ' + escHtml(step.action) + '</div>';}).join('') + '</div>' : '');
}

async function renderIecFR() {
  const data = await load('standards/iec62443/foundational-requirements.json');
  const frsHtml = data.foundationalRequirements ? data.foundationalRequirements.map(function(fr) { return '\
    <div class="control-card">\
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">\
        <span class="badge badge-sl2">' + escHtml(fr.id) + '</span>\
        <span class="control-card-title" style="margin:0">' + escHtml(fr.name) + '</span>\
      </div>\
      <div class="control-card-desc">' + escHtml(fr.description) + '</div>\
      <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.5rem">' + escHtml(fr.rationale || '') + '</div>\
      <div style="margin-top:0.5rem;display:flex;flex-wrap:wrap;gap:0.35rem">\
        <span class="tag">SRs: ' + escHtml(fr.srRange || '') + '</span>\
        <span class="tag">Count: ' + escHtml(String(fr.srCount || '')) + '</span>' +
        (fr.nacsa ? fr.nacsa.map(function(n){return '<span class="badge badge-malaysia">'+escHtml(n)+'</span>';}).join('') : '') +
      '</div>' +
      (fr.otContext ? '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.5rem;border-top:1px solid var(--border);padding-top:0.5rem"><strong>OT Context:</strong> ' + escHtml(fr.otContext) + '</div>' : '') +
    '</div>';}).join('') : '';

  return '\
    <h2>7 Foundational Requirements (FRs)</h2>\
    <div class="page-sub">The 7 FRs define the security property categories. Each FR contains multiple System Requirements (SRs).</div>\
    <div class="control-grid">' + frsHtml + '</div>';
}

async function renderIecSR() {
  const data = await load('standards/iec62443/system-requirements.json');
  const allSRs = data.systemRequirements || data.requirements || [];
  if (!allSRs.length) return '<div class="empty-state"><div class="empty-state-text">No data</div></div>';

  const frGroups = {};
  allSRs.forEach(function(sr) {
    var fr = sr.fr || 'Other';
    if (!frGroups[fr]) frGroups[fr] = [];
    frGroups[fr].push(sr);
  });

  const srHtml = Object.entries(frGroups).map(function(e) {
    var fr = e[0], srs = e[1];
    return '<h2 style="margin-top:1.5rem">' + escHtml(fr) + '</h2>\
    <div class="table-wrap"><table>\
      <thead><tr><th>SR</th><th>Name</th><th>SL1</th><th>SL2</th><th>SL3</th><th>SL4</th><th>NACSA</th></tr></thead>\
      <tbody>' + srs.map(function(sr) { return '\
        <tr class="control-card-link" onclick="showSRDetail(' + JSON.stringify(JSON.stringify(sr)).slice(1,-1).replace(/'/g,'&#39;') + ')" style="cursor:pointer">\
          <td><strong>' + escHtml(sr.id) + '</strong></td>\
          <td>' + escHtml(sr.name) + '</td>\
          <td style="text-align:center">' + (sr.sl1 ? '●' : '○') + '</td>\
          <td style="text-align:center">' + (sr.sl2 ? '●' : '○') + '</td>\
          <td style="text-align:center">' + (sr.sl3 ? '●' : '○') + '</td>\
          <td style="text-align:center">' + (sr.sl4 ? '●' : '○') + '</td>\
          <td>' + (sr.nacsa ? sr.nacsa.map(function(n){return '<span class="badge badge-malaysia" style="margin:1px">'+escHtml(n)+'</span>';}).join('') : '') + '</td>\
        </tr>';}).join('') +
      '</tbody>\
    </table></div>';
  }).join('');

  return '<div class="page-sub">Click any SR for full SL 1-4 descriptions and mappings. ' + allSRs.length + ' SRs across 7 FRs.</div>\
    <div id="sr-detail-panel"></div>' + srHtml;
}

window.showSRDetail = function(srJson) {
  try {
    var sr = JSON.parse(srJson);
    var panel = document.getElementById('sr-detail-panel');
    if (!panel) return;
    panel.innerHTML = '\
      <div class="control-card" style="border-color:var(--accent);margin-bottom:1.5rem">\
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.75rem">\
          <span class="badge badge-sl2">' + escHtml(sr.id) + '</span>\
          <span class="control-card-title" style="margin:0">' + escHtml(sr.name) + '</span>\
          <button onclick="document.getElementById(\'sr-detail-panel\').innerHTML=\'\'" style="margin-left:auto;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1rem">X</button>\
        </div>\
        <div class="control-card-desc">' + escHtml(sr.description || '') + '</div>\
        <div class="control-grid" style="margin-top:1rem">' +
          [1,2,3,4].map(function(l) { return '\
            <div>\
              <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.25rem">' + slBadge(l) + '</div>\
              <div style="font-size:0.8rem">' + escHtml(sr['sl'+l] || '—') + '</div>\
            </div>';}).join('') + '\
        </div>' +
        (sr.otConsiderations ? '<div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border);font-size:0.8rem;color:var(--text-secondary)"><strong>OT Considerations:</strong> ' + escHtml(sr.otConsiderations) + '</div>' : '') + '\
        <div class="control-card-meta" style="margin-top:0.75rem">' +
          (sr.nacsa ? sr.nacsa.map(function(n){return '<span class="badge badge-malaysia">'+escHtml(n)+'</span>';}).join('') : '') +
          (sr.nistCsf ? sr.nistCsf.map(function(n){return '<span class="tag">'+escHtml(n)+'</span>';}).join('') : '') +
          (sr.mitreAttackIcs ? sr.mitreAttackIcs.map(function(m){return '<span class="tag" style="color:var(--danger)">'+escHtml(m)+'</span>';}).join('') : '') + '\
        </div>\
      </div>';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch(e) { console.error('SR detail parse error', e); }
};

async function renderNist() {
  const data = await load('standards/nist-800-82/index.json');
  // data.chapters[].keyContent (not .summary)
  const chapHtml = data.chapters ? data.chapters.map(function(c) { return '\
    <div class="control-card">\
      <div class="control-card-title">Chapter ' + escHtml(String(c.chapter)) + ' — ' + escHtml(c.title) + '</div>\
      <div class="control-card-desc">' + escHtml(c.keyContent || c.summary || '') + '</div>' +
      (c.keyTopics ? tagList(c.keyTopics) : '') +
    '</div>';}).join('') : '';

  return '\
    <div class="disclaimer">NIST SP 800-82 is a US government publication in the public domain.</div>\
    <h2>' + escHtml(data.fullTitle || data.title || 'NIST SP 800-82') + '</h2>\
    <div class="detail-body" style="margin-bottom:1rem">' + escHtml(data.scope || data.overview || '') + '</div>' +
    (data.keyChangesRev3 ? '<h2>Key Changes in Rev 3</h2><div class="attack-chain">' + data.keyChangesRev3.map(function(c){return '<div class="attack-step">'+escHtml(c)+'</div>';}).join('') + '</div>' : '') + '\
    <h2>Chapters</h2>\
    <div class="control-grid">' + chapHtml + '</div>' +
    (data.relationToIEC62443 ? '<h2>Relation to IEC 62443</h2><div class="control-card"><div class="control-card-desc">' + escHtml(data.relationToIEC62443) + '</div></div>' : '');
}

async function renderMitre() {
  const [idx, techniques] = await Promise.all([
    load('standards/mitre-attack-ics/index.json'),
    load('standards/mitre-attack-ics/techniques.json'),
  ]);

  const tacticsHtml = idx.tactics ? idx.tactics.map(function(t) { return '\
    <div class="control-card">\
      <div class="control-card-title">' + escHtml(t.id) + ' — ' + escHtml(t.name) + '</div>\
      <div class="control-card-desc">' + escHtml(t.description || '') + '</div>\
    </div>';}).join('') : '';

  const techsHtml = techniques.techniques ? techniques.techniques.map(function(t) { return '\
    <tr>\
      <td><a href="https://attack.mitre.org/techniques/' + escHtml(t.id) + '/" target="_blank" rel="noopener">' + escHtml(t.id) + '</a></td>\
      <td>' + escHtml(t.name) + '</td>\
      <td>' + escHtml(t.tactic) + '</td>\
      <td style="font-size:0.75rem">' + escHtml(t.description || '') + '</td>\
      <td style="font-size:0.7rem">' + (t.iec62443SRs ? t.iec62443SRs.join(', ') : '') + '</td>\
    </tr>';}).join('') : '';

  // keyIncidentMappings uses .primaryTechniques (not .techniques)
  const incidentsHtml = idx.keyIncidentMappings ? idx.keyIncidentMappings.map(function(i) { return '\
    <tr>\
      <td>' + escHtml(i.incident) + '</td>\
      <td>' + ((i.primaryTechniques || i.techniques || []).map(function(t){return '<span class="tag">'+escHtml(t)+'</span>';}).join(' ')) + '</td>\
    </tr>';}).join('') : '';

  return '\
    <div class="disclaimer">MITRE ATT&amp;CK for ICS is publicly available at attack.mitre.org/matrices/ics</div>\
    <h2>MITRE ATT&amp;CK for ICS</h2>\
    <div class="detail-body" style="margin-bottom:1rem">' + escHtml(idx.description || idx.overview || '') + '</div>\
    <h2>Tactics (' + (idx.tactics ? idx.tactics.length : 0) + ')</h2>\
    <div class="control-grid">' + tacticsHtml + '</div>' +
    (incidentsHtml ? '\
    <h2>Known Incident Mappings</h2>\
    <div class="table-wrap"><table>\
      <thead><tr><th>Incident</th><th>Techniques Used</th></tr></thead>\
      <tbody>' + incidentsHtml + '</tbody>\
    </table></div>' : '') + '\
    <h2>Techniques (' + (techniques.techniques ? techniques.techniques.length : 0) + ')</h2>\
    <div class="table-wrap"><table>\
      <thead><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Description</th><th>IEC 62443 SRs</th></tr></thead>\
      <tbody>' + techsHtml + '</tbody>\
    </table></div>';
}


// --- CONTROLS ---
async function renderControls(sub) {
  const [controls, domains, artifactInventory, evidenceIndex] = await Promise.all([
    load('controls/library.json'),
    load('controls/domains.json'),
    load('artifacts/inventory.json').catch(function() { return []; }),
    load('evidence/index.json').catch(function() { return {}; }),
  ]);

  const allControls = Array.isArray(controls) ? controls : [];

  // domains.json is a FLAT ARRAY (not {domains:[...]})
  var domainMap = {};
  var domainsList = Array.isArray(domains) ? domains : (domains.domains || []);
  domainsList.forEach(function(d) { domainMap[d.id] = d; });

  var grouped = {};
  allControls.forEach(function(c) {
    var d = c.domain || 'other';
    if (!grouped[d]) grouped[d] = [];
    grouped[d].push(c);
  });

  var html = Object.entries(grouped).map(function(e) {
    var domId = e[0], ctrls = e[1];
    var domainInfo = domainMap[domId];
    return `
          <div class="accordion-item">
            <button class="accordion-trigger" data-accordion>
              <span class="accordion-trigger-left">
                <span>${escHtml(domainInfo ? domainInfo.name : domId)}</span>
                <span style="color:var(--text-muted);font-weight:400;font-size:0.8125rem">(${ctrls.length})</span>
              </span>
              <span class="chevron">\u25B6</span>
            </button>
            <div class="accordion-content">
              ${domainInfo && domainInfo.description ? '<p style="font-size:0.8125rem;color:var(--text-secondary);margin-bottom:0.75rem;padding-bottom:0.75rem;border-bottom:1px solid var(--border)">' + escHtml(domainInfo.description) + '</p>' : ''}
              <ul class="clause-list">
                ${ctrls.map(function(c) { return `
                  <li><a class="clause-link" href="#control/${c.slug}">
                    <span class="clause-title">${escHtml(c.name)}</span>
                    ${typeBadge(c.type)}
                    <span style="font-size:0.75rem;color:var(--text-muted)">SL ${c.slMin || '—'}</span>
                  </a></li>`;}).join('')}
              </ul>
            </div>
          </div>`;
  }).join('');

  setHTML(`
    <div class="page-title">Controls</div>
    <div class="page-sub">${allControls.length} controls · IEC 62443 · NACSA Act 854 · NIST CSF 2.0 mapped</div>
    <div class="accordion">
      ${html}
    </div>`
  );
}

async function renderControlBySlug(slug) {
  if (!slug) return renderControls();
  const [controls, artifactInventory, evidenceIndex] = await Promise.all([
    load('controls/library.json'),
    load('artifacts/inventory.json').catch(function() { return []; }),
    load('evidence/index.json').catch(function() { return {}; }),
  ]);
  const allControls = Array.isArray(controls) ? controls : [];
  const ctrl = allControls.find(function(c) { return c.slug === slug; });
  if (!ctrl) {
    setHTML('<div class="error-state"><h2>Control not found</h2><p class="error-message">No control with slug: ' + escHtml(slug) + '</p><button onclick="navigate(\'controls\')">Back to Controls</button></div>');
    return;
  }
  renderControlDetail(ctrl, allControls, artifactInventory, evidenceIndex);
}

function renderControlDetail(ctrl, allControls, artifactInventory, evidenceIndex) {
  var controlSlug = ctrl.slug;
  var domain = ctrl.domain;

  // Requirements section — controls have sections[], iec62443SRs[], not a .requirements object
  var reqsHtml = '';
  if (ctrl.sections && ctrl.sections.length) {
    reqsHtml = '<section class="detail-section"><h2 class="detail-section-title">Requirements Sections</h2><div class="requirements-grid">' +
      '<div class="requirement-block"><div class="requirement-block-label">Linked Requirement Sections</div><ul>' +
      ctrl.sections.map(function(s){return '<li>'+escHtml(s)+'</li>';}).join('') +
      '</ul></div></div></section>';
  }

  // Key Activities
  var activitiesHtml = ctrl.keyActivities ? '<section class="detail-section"><h2 class="detail-section-title">Key Activities</h2><ul class="activity-list">' + ctrl.keyActivities.map(function(a){return '<li>'+escHtml(a)+'</li>';}).join('') + '</ul></section>' : '';

  // Maturity Levels
  var maturityHtml = '';
  if (ctrl.maturity) {
    var levels = Object.entries(ctrl.maturity);
    maturityHtml = '<section class="detail-section"><h2 class="detail-section-title">Maturity Levels</h2><div class="maturity-grid">' +
      levels.map(function(e) {
        var lvl = e[0], desc = e[1];
        var cls = lvl === 'basic' ? 'maturity-basic' : lvl === 'mature' ? 'maturity-mature' : 'maturity-advanced';
        return '<div class="maturity-card ' + cls + '"><div class="maturity-label">' + escHtml(lvl) + '</div><p>' + escHtml(desc) + '</p></div>';
      }).join('') +
    '</div></section>';
  }

  // Audit Package
  var linkedArtifacts = (Array.isArray(artifactInventory) ? artifactInventory : [])
    .filter(function(a) { return Array.isArray(a.controlSlugs) && a.controlSlugs.includes(controlSlug); })
    .sort(function(a, b) { return (b.mandatory ? 1 : 0) - (a.mandatory ? 1 : 0); });

  var linkedArtifactIds = new Set(linkedArtifacts.map(function(a) { return a.id; }));
  var evidenceByDomain = (evidenceIndex || {}).evidenceByDomain || {};
  var domainEvidence = evidenceByDomain[domain];
  var linkedEvidence = [];
  if (domainEvidence && domainEvidence.evidenceItems) {
    domainEvidence.evidenceItems.forEach(function(item) {
      var itemArtifacts = item.artifactSlugs || [];
      if (!itemArtifacts.length || itemArtifacts.some(function(id) { return linkedArtifactIds.has(id); })) {
        linkedEvidence.push(item);
      }
    });
  }

  var evidenceItemsHtml = linkedEvidence.length ? linkedEvidence.map(function(ev) { return '\
    <div class="evidence-item">\
      <div class="evidence-item-header">' +
        (ev.id ? '<span class="evidence-id">' + escHtml(ev.id) + '</span>' : '') +
        '<span class="evidence-item-name">' + escHtml(ev.name) + '</span>' +
        (ev.mandatory ? '<span class="badge badge-mandatory">Mandatory</span>' : '<span class="badge badge-optional">Optional</span>') +
      '</div>' +
      (ev.howToVerify ? '<p class="evidence-item-desc">' + escHtml(ev.howToVerify) + '</p>' : '') + '\
      <div class="evidence-detail-grid">' +
        (ev.whatGoodLooksLike && ev.whatGoodLooksLike.length ? '<div class="evidence-block evidence-good"><div class="evidence-block-label">What Good Looks Like</div><ul>' + ev.whatGoodLooksLike.map(function(w){return '<li>'+escHtml(w)+'</li>';}).join('') + '</ul></div>' : '') +
        (ev.commonGaps && ev.commonGaps.length ? '<div class="evidence-block evidence-gap"><div class="evidence-block-label">Common Gaps</div><ul>' + ev.commonGaps.map(function(g){return '<li>'+escHtml(g)+'</li>';}).join('') + '</ul></div>' : '') + '\
      </div>\
    </div>';}).join('') : '<div class="empty-state"><p class="empty-state-text">No evidence items mapped to this control yet.</p></div>';

  var artifactCardsHtml = linkedArtifacts.length ? linkedArtifacts.map(function(a) { return '\
    <div class="artifact-card">\
      <div class="artifact-card-header">\
        <span class="artifact-card-name">' + escHtml(a.name) + '</span>\
        <div class="artifact-card-badges">' +
          (a.mandatory ? '<span class="badge badge-mandatory">Mandatory</span>' : '<span class="badge badge-optional">Optional</span>') +
          (a.category ? '<span class="badge badge-category">' + escHtml(a.category) + '</span>' : '') +
        '</div>\
      </div>' +
      (a.description ? '<p class="artifact-card-desc">' + escHtml(a.description) + '</p>' : '') + '\
      <div class="artifact-card-meta">' +
        (a.format ? '<span class="meta-item"><strong>Format:</strong> ' + escHtml(a.format) + '</span>' : '') +
      '</div>\
    </div>';}).join('') : '<div class="empty-state"><p class="empty-state-text">No artifacts linked to this control.</p></div>';

  var auditPkgHtml = '<section class="audit-package"><h2 class="audit-package-title">Audit Package<span class="audit-package-counts"><span class="badge badge-evidence">' + linkedEvidence.length + ' evidence</span><span class="badge badge-artifacts">' + linkedArtifacts.length + ' artifacts</span></span></h2>' +
    '<div class="accordion"><div class="accordion-item"><button class="accordion-trigger" aria-expanded="true"><span>Evidence Checklist (' + linkedEvidence.length + ')</span><span class="accordion-icon">&#9660;</span></button><div class="accordion-content" role="region">' + evidenceItemsHtml + '</div></div></div>' +
    '<div class="accordion"><div class="accordion-item"><button class="accordion-trigger" aria-expanded="true"><span>Required Artifacts (' + linkedArtifacts.length + ')</span><span class="accordion-icon">&#9660;</span></button><div class="accordion-content" role="region">' + artifactCardsHtml + '</div></div></div>' +
  '</section>';

  // Framework Mappings
  var fwHtml = '<section class="detail-section"><h2 class="detail-section-title">Framework Mappings</h2><div class="fw-mappings">';
  if (ctrl.iec62443SRs) fwHtml += '<div class="fw-mapping-row"><span class="fw-label">IEC 62443</span><span class="fw-codes">' + ctrl.iec62443SRs.join(', ') + '</span></div>';
  if (ctrl.nistCsf) fwHtml += '<div class="fw-mapping-row"><span class="fw-label">NIST CSF 2.0</span><span class="fw-codes">' + ctrl.nistCsf.join(', ') + '</span></div>';
  if (ctrl.nacsa) fwHtml += '<div class="fw-mapping-row"><span class="fw-label">NACSA Act 854</span><span class="fw-codes">' + ctrl.nacsa.join(', ') + '</span></div>';
  if (ctrl.mitreAttackIcs) fwHtml += '<div class="fw-mapping-row"><span class="fw-label">MITRE ATT&CK ICS</span><span class="fw-codes">' + ctrl.mitreAttackIcs.join(', ') + '</span></div>';
  fwHtml += '</div></section>';

  // Source Provisions
  var provHtml = '';
  if (ctrl.iec62443SRs && ctrl.iec62443SRs.length) {
    provHtml = '<section class="detail-section"><h2 class="detail-section-title">Source Provisions</h2><div class="provision-links">' +
      ctrl.iec62443SRs.map(function(sr) { return '<a href="#framework/iec-sr" class="provision-link"><span class="provision-id">' + escHtml(sr) + '</span><span class="provision-title">IEC 62443 System Requirement</span></a>'; }).join('') +
    '</div></section>';
  }

  setHTML('\
    <article class="control-detail">\
      <nav class="breadcrumbs">\
        <a href="#controls">Controls</a>\
        <span class="sep">/</span>\
        <span class="current">' + escHtml(ctrl.name) + '</span>\
      </nav>\
      <header class="control-detail-header">\
        <div class="control-detail-id-row">\
          <span class="control-id">' + escHtml(ctrl.slug) + '</span>' +
          typeBadge(ctrl.type) +
          slBadge(ctrl.slMin) +
        '</div>\
        <h1 class="control-detail-title">' + escHtml(ctrl.name) + '</h1>\
        <p class="control-detail-desc">' + escHtml(ctrl.description || '') + '</p>\
      </header>' +
      reqsHtml +
      activitiesHtml +
      maturityHtml +
      auditPkgHtml +
      fwHtml +
      provHtml +
    '</article>'
  );
}


// --- THREATS ---
async function renderThreats(sub) {
  const tabs = [
    { id: 'incidents', label: 'Known Incidents' },
    { id: 'actors',    label: 'Threat Actors' },
  ];
  const active = sub || 'incidents';

  const tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'threats/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'incidents') content = await renderIncidents();
  else content = await renderActors();

  setHTML('\
    <div class="page-title">Threats</div>\
    <div class="page-sub">Real-world incidents · Threat actor profiles · MITRE ATT&amp;CK for ICS mapped</div>' +
    tabsHtml + content
  );
}

async function renderThreatDetail(sub) { return renderThreats(sub); }

async function renderIncidents() {
  const data = await load('threats/known-incidents.json');
  const incidents = data.incidents || [];

  // Fields: id, name, year, sector, country, attribution, summary, attackChain, physicalConsequence, detectability, preventiveControls, iec62443SRs
  return incidents.map(function(inc) { return '\
    <div class="control-card" style="margin-bottom:1rem;border-left:4px solid var(--danger)">\
      <div style="display:flex;align-items:flex-start;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.75rem">\
        <div>\
          <div class="control-card-title" style="font-size:1rem;color:var(--danger)">' + escHtml(inc.name) + '</div>\
          <div class="control-card-desc">' + escHtml(String(inc.year || '')) + ' · ' + escHtml(inc.sector || '') + ' · ' + escHtml(inc.country || '') + '</div>\
        </div>\
      </div>\
      <div class="detail-body" style="margin-bottom:0.75rem">' + escHtml(inc.summary || '') + '</div>' +
      (inc.physicalConsequence ? '<div class="control-card" style="background:rgba(239,68,68,0.08);border-color:rgba(239,68,68,0.3);margin-bottom:0.75rem"><div style="font-size:0.75rem;font-weight:700;color:var(--danger);text-transform:uppercase;margin-bottom:0.25rem">Physical Consequence</div><div style="font-size:0.85rem">' + escHtml(inc.physicalConsequence) + '</div></div>' : '') +
      (inc.detectability ? '<div style="font-size:0.85rem;margin-bottom:0.75rem;color:var(--text-secondary)"><strong>Detectability:</strong> ' + escHtml(inc.detectability) + '</div>' : '') +
      (inc.attackChain ? '<h3 style="margin-bottom:0.5rem">Attack Chain</h3><div class="attack-chain" style="margin-bottom:0.75rem">' + inc.attackChain.map(function(step){return '<div class="attack-step"><strong>' + escHtml(step.stage) + ':</strong> ' + (step.technique ? '<span class="tag" style="color:var(--danger);margin:0 0.35rem">' + escHtml(step.technique) + '</span>' : '') + escHtml(step.description || '') + '</div>';}).join('') + '</div>' : '') +
      (inc.preventiveControls ? '<h3 style="margin-bottom:0.5rem">Preventive Controls</h3><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:0.5rem;margin-bottom:0.75rem">' + inc.preventiveControls.map(function(pc){return '<div style="background:rgba(52,211,153,0.05);border:1px solid rgba(52,211,153,0.2);border-radius:6px;padding:0.5rem 0.75rem;font-size:0.8rem"><strong style="color:var(--success)">' + escHtml(pc.control || pc) + '</strong>' + (pc.howItHelps ? '<div style="color:var(--text-secondary);margin-top:0.25rem">' + escHtml(pc.howItHelps) + '</div>' : '') + '</div>';}).join('') + '</div>' : '') +
      (inc.keyLesson ? '<div style="background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.3);border-radius:6px;padding:0.5rem 0.75rem;font-size:0.85rem"><strong style="color:var(--warning)">Key Lesson:</strong> ' + escHtml(inc.keyLesson) + '</div>' : '') +
      (inc.iec62443SRs ? '<div class="control-card-meta" style="margin-top:0.75rem">' + inc.iec62443SRs.map(function(s){return '<span class="badge badge-sl2">'+escHtml(s)+'</span>';}).join('') + '</div>' : '') +
    '</div>';}).join('');
}

async function renderActors() {
  const data = await load('threats/threat-actors.json');
  const actors = data.threatActors || [];

  // Fields: id, name, alternateNames, attribution, actorType, capability, sectors, primaryObjective, demonstratedCapability, primaryTechniques, relevanceToMalaysia, iec62443SLReference
  return actors.map(function(a) {
    var slRef = a.iec62443SLReference || 2;
    return '\
    <div class="control-card" style="margin-bottom:0.75rem;border-left:3px solid var(--accent)">\
      <div style="display:flex;align-items:flex-start;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.5rem">\
        <div>\
          <div class="control-card-title">' + escHtml(a.name) + (a.alternateNames ? ' <span style="font-size:0.75rem;color:var(--text-muted)">(' + a.alternateNames.join(', ') + ')</span>' : '') + '</div>\
          <div class="control-card-desc">' + escHtml(a.attribution || '') + '</div>\
        </div>\
        <div style="margin-left:auto;display:flex;gap:0.35rem;flex-wrap:wrap">' +
          slBadge(slRef) +
          '<span class="tag">' + escHtml(a.actorType || '') + '</span>' +
        '</div>\
      </div>\
      <div class="control-card-desc">' + escHtml(a.capability || '') + '</div>' +
      '<div style="font-size:0.8rem;margin-top:0.5rem"><strong>Objective:</strong> ' + escHtml(a.primaryObjective || '') + '</div>' +
      (a.demonstratedCapability ? '<div style="margin-top:0.5rem"><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem">Demonstrated Capability</div><ul style="font-size:0.8rem;padding-left:1.25rem;margin:0">' + a.demonstratedCapability.map(function(d){return '<li>'+escHtml(d)+'</li>';}).join('') + '</ul></div>' : '') +
      '<div class="control-grid" style="margin-top:0.75rem">' +
        (a.sectors ? '<div><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem">Targeted Sectors</div>' + tagList(a.sectors) + '</div>' : '') +
        (a.primaryTechniques ? '<div><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem">Primary Techniques</div>' + tagList(a.primaryTechniques) + '</div>' : '') +
      '</div>' +
      (a.relevanceToMalaysia ? '<div style="margin-top:0.5rem;font-size:0.8rem;padding:0.5rem;background:rgba(56,189,248,0.05);border-radius:4px"><strong>Malaysia Relevance:</strong> ' + escHtml(a.relevanceToMalaysia) + '</div>' : '') +
    '</div>';
  }).join('');
}


// --- SECTORS ---
async function renderSectors(sub) {
  const data = await load('sectors/index.json');
  const sectors = data.sectors || [];

  const html = sectors.map(function(s) {
    return `
    <a class="control-card control-card-link" href="#sector/${s.id}" style="text-decoration:none;color:inherit">
      <div class="control-card-title">${escHtml(s.name)}</div>
      <div class="control-card-desc">NACSA Sector: ${escHtml(String(s.nacsaSectorNumber || ''))} · Lead: ${escHtml(s.nacsaSectorLead || '')}</div>
      <div class="control-card-desc">${escHtml((s.description || '').substring(0, 200))}${s.description && s.description.length > 200 ? '...' : ''}</div>
      <div class="control-card-meta">
        <span class="badge badge-malaysia">Act 854</span>
        ${(s.keyOtRisks ? s.keyOtRisks.slice(0,2).map(function(r){return '<span class="tag">'+escHtml(r)+'</span>';}).join('') : '')}
      </div>
    </a>`;}).join('');

  setHTML(`
    <div class="page-title">Sectors</div>
    <div class="page-sub">Sector-specific OT risks, NACSA obligations, and SL targeting by zone.</div>
    <div class="control-grid">${html}</div>`
  );
}

async function renderSectorById(id) {
  const data = await load('sectors/index.json');
  const sectors = data.sectors || [];
  const sector = sectors.find(function(s) { return s.id === id; });
  if (!sector) { setHTML('<div class="error-state"><h2>Sector not found</h2><button onclick="navigate(\'sectors\')">Back</button></div>'); return; }

  var slZoneHtml = sector.targetSLByZone ? Object.entries(sector.targetSLByZone).map(function(e) {
    return '<tr><td>' + escHtml(e[0]) + '</td><td>' + slBadge(e[1]) + '</td></tr>';
  }).join('') : '';

  setHTML('\
    <nav class="breadcrumbs"><a href="#sectors">Sectors</a><span class="sep">/</span><span class="current">' + escHtml(sector.name) + '</span></nav>\
    <div class="page-title">' + escHtml(sector.name) + '</div>\
    <div class="page-sub">NACSA Sector: ' + escHtml(String(sector.nacsaSectorNumber || '')) + ' · Lead Agency: ' + escHtml(sector.nacsaSectorLead || '') + '</div>\
    <div class="control-card" style="margin-bottom:1rem"><div class="control-card-desc">' + escHtml(sector.description || '') + '</div></div>\
    <div class="control-grid">\
      <div class="control-card"><h3>OT Environments</h3>' + tagList(sector.otEnvironments || []) + '</div>\
      <div class="control-card"><h3>Primary Standards</h3>' + tagList(sector.primaryStandards || []) + '</div>\
    </div>\
    <div class="control-grid" style="margin-top:0.75rem">\
      <div class="control-card"><h3>Key OT Risks</h3><ul style="padding-left:1.25rem;font-size:0.8rem">' + (sector.keyOtRisks || []).map(function(r){return '<li style="margin-bottom:0.25rem">'+escHtml(r)+'</li>';}).join('') + '</ul></div>\
      <div class="control-card"><h3>SL-T by Zone</h3><div class="table-wrap" style="margin:0"><table><thead><tr><th>Zone</th><th>SL Target</th></tr></thead><tbody>' + slZoneHtml + '</tbody></table></div></div>\
    </div>' +
    (sector.nacsaCopReference ? '<div class="control-card" style="margin-top:0.75rem;border-color:var(--accent)"><h3>NACSA Code of Practice Reference</h3><div class="detail-body">' + escHtml(sector.nacsaCopReference) + '</div></div>' : '') +
    (sector.regulatoryOverlap ? '<h2 style="margin-top:1rem">Regulatory Overlap</h2><div class="attack-chain">' + (Array.isArray(sector.regulatoryOverlap) ? sector.regulatoryOverlap.map(function(r){return '<div class="attack-step">'+escHtml(r)+'</div>';}).join('') : '<div class="attack-step">' + escHtml(String(sector.regulatoryOverlap)) + '</div>') + '</div>' : '')
  );
}


// --- ARCHITECTURE ---
async function renderArchitecture(sub) {
  const tabs = [
    { id: 'purdue',  label: 'Purdue Model' },
    { id: 'zones',   label: 'Zones & Conduits' },
    { id: 'assets',  label: 'Asset Types' },
  ];
  const active = sub || 'purdue';

  const tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'architecture/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'purdue') content = await renderPurdue();
  else if (active === 'zones') content = await renderZones();
  else if (active === 'assets') content = await renderAssets();

  setHTML('\
    <div class="page-title">Architecture</div>\
    <div class="page-sub">Purdue Model · Zones &amp; Conduits · Asset Type Profiles</div>' +
    tabsHtml + content
  );
}

async function renderPurdue() {
  const data = await load('architecture/purdue-model.json');
  if (!data.levels) return '<div class="empty-state"><div class="empty-state-text">No data</div></div>';

  const levelsHtml = data.levels.map(function(l) { return '\
    <div class="control-card" style="border-left:3px solid var(--accent2)">\
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">\
        <span class="badge badge-sl2">Level ' + escHtml(String(l.level)) + '</span>\
        <span class="control-card-title" style="margin:0">' + escHtml(l.name) + '</span>' +
        (l.securityCharacteristics && l.securityCharacteristics.targetSL ? slBadge(l.securityCharacteristics.targetSL) : '') +
      '</div>\
      <div class="control-card-desc">' + escHtml(l.description || '') + '</div>' +
      (l.typicalComponents ? '<div style="margin-top:0.75rem"><div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.35rem">Typical Components</div>' + tagList(l.typicalComponents.map(function(c){return typeof c === 'string' ? c : c.type || c.name || JSON.stringify(c);})) + '</div>' : '') +
      (l.securityCharacteristics ? '<div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:0.75rem;color:var(--text-secondary)"><div><strong>Primary Controls:</strong> ' + escHtml((l.securityCharacteristics.primaryControls || []).join(', ')) + '</div><div style="margin-top:0.25rem"><strong>Key Vulnerabilities:</strong> ' + escHtml(Array.isArray(l.securityCharacteristics.vulnerabilities) ? l.securityCharacteristics.vulnerabilities.join(', ') : (l.securityCharacteristics.vulnerabilities || '')) + '</div></div>' : '') +
    '</div>';}).join('');

  return '\
    <h2>Purdue Model — Levels 0-5</h2>\
    <div class="control-card" style="margin-bottom:1rem;background:rgba(56,189,248,0.05);border-color:var(--accent)">\
      <div class="control-card-title">IDMZ — Industrial Demilitarized Zone (Level 3.5)</div>\
      <div class="control-card-desc">The IDMZ is the critical architectural element separating OT (Levels 0-3) from IT (Level 4+).</div>\
    </div>\
    <div class="control-grid">' + levelsHtml + '</div>';
}

async function renderZones() {
  const data = await load('architecture/zones-conduits.json');

  const zonesHtml = data.referenceZones ? data.referenceZones.map(function(z) {
    var slNum = String(z.slTarget || z.targetSL || 2);
    return '\
    <div class="control-card">\
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;flex-wrap:wrap">\
        <span class="badge badge-sl' + slNum + '">' + escHtml(z.id) + '</span> ' +
        slBadge(z.slTarget || z.targetSL) + ' ' + slDots(z.slTarget || z.targetSL) +
        '<span class="control-card-title" style="margin:0">' + escHtml(z.name) + '</span>\
      </div>\
      <div class="control-card-desc">' + escHtml(z.description || '') + '</div>' +
      (z.typicalAssets ? '<div style="margin-top:0.5rem">' + tagList(z.typicalAssets) + '</div>' : '') +
      (z.keyControls ? '<div style="margin-top:0.5rem"><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem">Key Controls</div>' + tagList(z.keyControls) + '</div>' : '') +
      (z.nacsaRelevance ? '<div style="margin-top:0.5rem;font-size:0.75rem;color:var(--text-secondary)"><strong>NACSA:</strong> ' + escHtml(z.nacsaRelevance) + '</div>' : '') +
    '</div>';}).join('') : '';

  const conduitsHtml = data.referenceConduits ? data.referenceConduits.map(function(c) { return '\
    <div class="control-card">\
      <div class="control-card-title">' + escHtml(c.id) + ' — ' + escHtml(c.name) + '</div>\
      <div class="control-card-desc">' + escHtml(c.from) + ' → ' + escHtml(c.to) + ' · Min SL: ' + slBadge(c.slRequired) + '</div>\
      <div class="control-card-desc">' + escHtml(c.description || '') + '</div>' +
      (c.permittedFlows ? '<div style="margin-top:0.5rem"><span style="font-size:0.7rem;color:var(--success)">Permitted:</span> ' + tagList(c.permittedFlows) + '</div>' : '') +
      (c.prohibitedFlows ? '<div style="margin-top:0.35rem"><span style="font-size:0.7rem;color:var(--danger)">Prohibited:</span> ' + tagList(c.prohibitedFlows) + '</div>' : '') +
    '</div>';}).join('') : '';

  return '\
    <h2>Reference Zones</h2>\
    <div class="control-grid">' + zonesHtml + '</div>\
    <h2 style="margin-top:1.5rem">Reference Conduits</h2>\
    <div class="control-grid">' + conduitsHtml + '</div>';
}

async function renderAssets() {
  const data = await load('architecture/asset-types.json');
  if (!data.assetTypes) return '<div class="empty-state"><div class="empty-state-text">No data</div></div>';

  const assetHtml = data.assetTypes.map(function(a) { return '\
    <div class="control-card">\
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">\
        <span class="badge badge-sl2">' + escHtml(a.id) + '</span>\
        <span class="control-card-title" style="margin:0">' + escHtml(a.name) + '</span>\
      </div>' +
      (a.purdueLevel ? '<div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem">Purdue Level ' + escHtml(String(a.purdueLevel)) + '</div>' : '') +
      (a.vendors ? '<div style="margin-top:0.5rem"><span style="font-size:0.7rem;color:var(--text-muted)">Vendors:</span> ' + tagList(a.vendors) + '</div>' : '') +
      (a.protocols ? '<div style="margin-top:0.35rem"><span style="font-size:0.7rem;color:var(--text-muted)">Protocols:</span> ' + tagList(a.protocols) + '</div>' : '') +
      (a.securityProfile ? '<div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:0.75rem"><div style="color:' + (a.securityProfile.vulnerabilityRisk === 'Extreme' || a.securityProfile.vulnerabilityRisk === 'High' ? 'var(--danger)' : 'var(--text-muted)') + '">Risk: ' + escHtml(a.securityProfile.vulnerabilityRisk || '') + '</div>' + (a.securityProfile.compensatingControls ? '<div style="color:var(--text-muted);margin-top:0.25rem">Controls: ' + escHtml(a.securityProfile.compensatingControls.join(', ')) + '</div>' : '') + '</div>' : '') +
    '</div>';}).join('');

  return '\
    <h2>OT Asset Type Profiles</h2>\
    <div class="page-sub">Security profiles for each OT asset category.</div>\
    <div class="control-grid">' + assetHtml + '</div>';
}


// --- RISK MANAGEMENT ---
async function renderRiskManagement(sub) {
  const tabs = [
    { id: 'methodology', label: 'Methodology' },
    { id: 'matrix',      label: 'Risk Matrix' },
    { id: 'register',    label: 'Risk Register' },
    { id: 'treatment',   label: 'Treatment Options' },
    { id: 'checklist',   label: 'Assessment Checklist' },
  ];
  const active = sub || 'methodology';

  const tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'risk/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'methodology') content = await renderRiskMethodology();
  else if (active === 'matrix') content = await renderRiskMatrix();
  else if (active === 'register') content = await renderRiskRegister();
  else if (active === 'treatment') content = await renderRiskTreatment();
  else if (active === 'checklist') content = await renderRiskChecklist();

  setHTML('\
    <div class="page-title">Risk Management</div>\
    <div class="page-sub">OT/ICS risk assessment methodology · IEC 62443-3-2 · NACSA Act 854 s21</div>' +
    tabsHtml + content
  );
}

async function renderRiskMethodology() {
  const data = await load('risk-management/methodology.json');

  var dimHtml = '';
  if (data.impactDimensions && data.impactDimensions.dimensions) {
    dimHtml = '<h2>Impact Dimensions</h2><div class="control-grid">' + data.impactDimensions.dimensions.map(function(d) { return '\
      <div class="control-card">\
        <div class="control-card-title">' + escHtml(d.name) + '</div>\
        <div class="control-card-desc">Weight: ' + escHtml(d.weight || '') + '</div>\
        <div class="control-card-desc">' + escHtml(d.description || '') + '</div>' +
        (d.examples ? tagList(d.examples) : '') +
      '</div>';}).join('') + '</div>';
  }

  var processHtml = '';
  if (data.assessmentProcess && data.assessmentProcess.steps) {
    processHtml = '<h2>Assessment Process</h2><div class="attack-chain">' +
      data.assessmentProcess.steps.map(function(s) { return '<div class="attack-step"><strong>Step ' + escHtml(String(s.step)) + ': ' + escHtml(s.name || '') + '</strong><div style="font-size:0.8rem;color:var(--text-secondary)">' + escHtml(s.description || '') + '</div></div>'; }).join('') +
    '</div>';
  }

  return '\
    <div class="disclaimer">' + escHtml(data.verificationNote || '') + '</div>\
    <h2>' + escHtml(data.title || 'Risk Assessment Methodology') + '</h2>\
    <div class="control-card" style="margin-bottom:1rem"><div class="control-card-desc">' + escHtml(data.description || '') + '</div></div>' +
    (data.keyPrinciple ? '<div class="control-card" style="border-color:var(--warning);margin-bottom:1rem"><div class="control-card-desc"><strong>Key Principle:</strong> ' + escHtml(data.keyPrinciple) + '</div></div>' : '') +
    (data.standardsAlignment ? '<div style="margin-bottom:1rem">' + tagList(data.standardsAlignment) + '</div>' : '') +
    dimHtml +
    processHtml;
}

async function renderRiskMatrix() {
  const data = await load('risk-management/risk-matrix.json');

  var matrixHtml = '<h2>5x5 Risk Matrix (Safety-Weighted)</h2>';
  var likScale = data.axes && data.axes.likelihood ? data.axes.likelihood.scale : [];
  var impScale = data.axes && data.axes.impact ? data.axes.impact.scale : [];

  var cellLookup = {};
  (data.matrix || []).forEach(function(c) { cellLookup[c.likelihood + '-' + c.impact] = c; });

  matrixHtml += '<div class="table-wrap"><table><thead><tr><th></th>';
  impScale.forEach(function(imp) { matrixHtml += '<th>' + escHtml(imp.label) + '<br><span style="font-size:0.65rem">(' + imp.level + ')</span></th>'; });
  matrixHtml += '</tr></thead><tbody>';
  for (var li = likScale.length; li >= 1; li--) {
    var likItem = likScale.find(function(l) { return l.level === li; });
    matrixHtml += '<tr><td><strong>' + escHtml(likItem ? likItem.label : String(li)) + '</strong> (' + li + ')</td>';
    for (var ii = 1; ii <= impScale.length; ii++) {
      var cell = cellLookup[li + '-' + ii];
      var band = cell ? cell.band : '';
      var colorMap = { Low: '#22C55E', Medium: '#F59E0B', High: '#F97316', Critical: '#EF4444' };
      var bg = colorMap[band] || '#ccc';
      matrixHtml += '<td style="background:' + bg + '20;color:' + bg + ';font-weight:700;text-align:center">' + escHtml(band) + (cell ? '<br><span style="font-size:0.65rem">(' + cell.score + ')</span>' : '') + '</td>';
    }
    matrixHtml += '</tr>';
  }
  matrixHtml += '</tbody></table></div>';

  var bandsHtml = '';
  if (data.bands && data.bands.length) {
    bandsHtml = '<h2>Risk Band Actions</h2><div class="control-grid">' + data.bands.map(function(b) { return '\
      <div class="control-card" style="border-left:3px solid ' + (b.color || '#ccc') + '">\
        <div class="control-card-title">' + escHtml(b.band) + ' (' + escHtml(b.scoreRange || '') + ')</div>\
        <div class="control-card-desc">' + escHtml(b.action || '') + '</div>\
        <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.35rem">Review: ' + escHtml(b.reviewCadence || '') + ' · Escalation: ' + escHtml(b.escalation || '') + '</div>' +
        (b.otNote ? '<div style="font-size:0.75rem;color:var(--warning);margin-top:0.25rem"><strong>OT Note:</strong> ' + escHtml(b.otNote) + '</div>' : '') +
      '</div>';}).join('') + '</div>';
  }

  return matrixHtml + bandsHtml;
}

async function renderRiskRegister() {
  const data = await load('risk-management/risk-register.json');
  const risks = data.risks || [];

  var bandColor = { Low: '#22C55E', Medium: '#F59E0B', High: '#F97316', Critical: '#EF4444' };

  return '<h2>OT/ICS Risk Register (' + risks.length + ' risks)</h2>\
    <div class="table-wrap"><table>\
      <thead><tr><th>ID</th><th>Risk</th><th>Category</th><th>Inherent</th><th>Residual</th><th>Treatment</th><th>IEC 62443</th></tr></thead>\
      <tbody>' + risks.map(function(r) { return '\
        <tr>\
          <td><strong>' + escHtml(r.id) + '</strong>' + (r.safetyImpact ? '<br><span class="badge badge-mandatory" style="font-size:0.55rem">Safety</span>' : '') + '</td>\
          <td style="font-size:0.8rem"><strong>' + escHtml(r.title) + '</strong><div style="color:var(--text-secondary);font-size:0.75rem;margin-top:0.15rem">' + escHtml((r.description || '').substring(0, 120)) + '...</div></td>\
          <td>' + escHtml(r.category || '') + '</td>\
          <td style="color:' + (bandColor[r.inherentRisk] || '#999') + ';font-weight:700">' + escHtml(r.inherentRisk) + '<br><span style="font-size:0.65rem">L' + r.likelihood + ' x I' + r.impact + '</span></td>\
          <td style="color:' + (bandColor[r.residualRisk] || '#999') + ';font-weight:700">' + escHtml(r.residualRisk) + '<br><span style="font-size:0.65rem">L' + r.residualLikelihood + ' x I' + r.residualImpact + '</span></td>\
          <td>' + escHtml(r.treatment || '') + '</td>\
          <td style="font-size:0.7rem">' + (r.iec62443Ref ? r.iec62443Ref.join(', ') : '') + '</td>\
        </tr>';}).join('') +
    '</tbody></table></div>';
}

async function renderRiskTreatment() {
  const data = await load('risk-management/treatment-options.json');
  var strategies = data.strategies || [];

  var safetyHtml = data.safetyConstraint ? '<div class="control-card" style="border-color:var(--danger);margin-bottom:1rem;background:rgba(239,68,68,0.05)"><div class="control-card-title" style="color:var(--danger)">Safety Constraint</div><div class="control-card-desc">' + escHtml(data.safetyConstraint.rule || '') + '</div><div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.5rem">' + escHtml(data.safetyConstraint.rationale || '') + '</div></div>' : '';

  var stratHtml = strategies.map(function(s) { return '\
    <div class="control-card" style="margin-bottom:0.75rem">\
      <div class="control-card-title">' + escHtml(s.name) + '</div>\
      <div class="control-card-desc">' + escHtml(s.description || '') + '</div>\
      <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.35rem"><strong>When to Use:</strong> ' + escHtml(s.whenToUse || '') + '</div>' +
      (s.otExamples ? '<div style="margin-top:0.75rem"><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.35rem">OT Examples</div>' + s.otExamples.map(function(ex) { return '<div style="padding:0.35rem 0;border-top:1px solid var(--border);font-size:0.8rem"><strong>' + escHtml(ex.risk || '') + ':</strong> ' + escHtml(ex.mitigation || '') + '</div>'; }).join('') + '</div>' : '') +
    '</div>';}).join('');

  return safetyHtml + '<h2>Risk Treatment Strategies</h2>' + stratHtml;
}

async function renderRiskChecklist() {
  const data = await load('risk-management/checklist.json');
  var items = data.items || [];

  var groups = {};
  items.forEach(function(item) {
    var cat = item.category || 'General';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(item);
  });

  var html = '<h2>OT Risk Assessment Checklist (' + items.length + ' items)</h2>';
  Object.entries(groups).forEach(function(e) {
    var cat = e[0], catItems = e[1];
    html += '<h3 style="margin-top:1rem">' + escHtml(cat) + '</h3>';
    html += catItems.map(function(item) { return '\
      <div class="control-card" style="margin-bottom:0.5rem">\
        <div style="display:flex;align-items:flex-start;gap:0.5rem">\
          <div>\
            <div style="font-size:0.85rem;font-weight:600">' + escHtml(item.id) + ': ' + escHtml(item.item) + (item.mandatory ? ' <span class="badge badge-mandatory">Mandatory</span>' : '') + '</div>\
            <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem">' + escHtml(item.guidance || '') + '</div>\
            <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem"><strong>Evidence Required:</strong> ' + escHtml(item.evidenceRequired || '') + '</div>\
          </div>\
        </div>\
      </div>';}).join('');
  });

  return html;
}


// --- REFERENCE (cross-references) ---
async function renderReference(sub) {
  const tabs = [
    { id: 'nacsa',      label: 'IEC 62443 to NACSA' },
    { id: 'nist-csf',   label: 'IEC 62443 to NIST CSF' },
    { id: 'nist80082',  label: 'IEC 62443 to NIST 800-82' },
    { id: 'mitre-ctrl', label: 'MITRE to Controls' },
    { id: 'sector-cop', label: 'Sector to NACSA CoP' },
  ];
  const active = sub || 'nacsa';

  const tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'reference/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'nacsa') content = await renderRefNacsa();
  else if (active === 'nist-csf') content = await renderRefNistCsf();
  else if (active === 'nist80082') content = await renderRefNist80082();
  else if (active === 'mitre-ctrl') content = await renderRefMitreCtrl();
  else if (active === 'sector-cop') content = await renderRefSectorCop();

  setHTML('\
    <div class="page-title">Reference</div>\
    <div class="page-sub">Cross-reference mappings between IEC 62443, NACSA, NIST, and MITRE frameworks</div>' +
    tabsHtml + content
  );
}

async function renderRefNacsa() {
  const data = await load('cross-references/iec62443-to-nacsa.json');
  var mappings = data.mappings || [];

  return '<h2>' + escHtml(data.title || 'IEC 62443 to NACSA') + '</h2>\
    <div class="disclaimer">' + escHtml(data.verificationNote || '') + '</div>' +
    mappings.map(function(m) { return '\
    <div class="control-card" style="margin-bottom:0.75rem">\
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">\
        <span class="badge badge-malaysia">' + escHtml(m.nacsaSection) + '</span>\
        <span class="control-card-title" style="margin:0">' + escHtml(m.nacsaTitle || '') + '</span>\
      </div>\
      <div class="control-card-desc"><strong>Obligation:</strong> ' + escHtml(m.nacsaObligation || '') + '</div>\
      <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.5rem"><strong>IEC 62443 Alignment:</strong> ' + escHtml(m.iec62443Alignment || '') + '</div>' +
      (m.relevantSRs && m.relevantSRs.length ? '<div class="control-card-meta" style="margin-top:0.5rem">' + m.relevantSRs.map(function(sr){return '<span class="badge badge-sl2">'+escHtml(sr)+'</span>';}).join('') + '</div>' : '') +
      (m.notes ? '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem;border-top:1px solid var(--border);padding-top:0.5rem">' + escHtml(m.notes) + '</div>' : '') +
    '</div>';}).join('');
}

async function renderRefNistCsf() {
  const data = await load('cross-references/iec62443-to-nist-csf.json');
  var mappings = data.mappings || [];

  return '<h2>' + escHtml(data.title || 'IEC 62443 to NIST CSF') + '</h2>\
    <div class="disclaimer">' + escHtml(data.verificationNote || '') + '</div>\
    <div class="table-wrap"><table>\
      <thead><tr><th>IEC 62443 SR</th><th>SR Name</th><th>NIST CSF Subcategories</th><th>Similarity</th></tr></thead>\
      <tbody>' + mappings.map(function(m) { return '\
        <tr>\
          <td><strong>' + escHtml(m.iec62443SR) + '</strong></td>\
          <td>' + escHtml(m.srName || '') + '</td>\
          <td>' + (m.nistCsfSubcategories ? m.nistCsfSubcategories.map(function(n){return '<span class="tag">'+escHtml(n)+'</span>';}).join(' ') : '') + '</td>\
          <td>' + escHtml(m.similarity || '') + '</td>\
        </tr>';}).join('') +
    '</tbody></table></div>';
}

async function renderRefNist80082() {
  const data = await load('cross-references/iec62443-to-nist80082.json');
  var mappings = data.mappings || [];

  return '<h2>' + escHtml(data.title || 'IEC 62443 to NIST 800-82') + '</h2>\
    <div class="disclaimer">' + escHtml(data.verificationNote || '') + '</div>' +
    mappings.map(function(m) { return '\
    <div class="control-card" style="margin-bottom:0.75rem">\
      <div class="control-card-title">' + escHtml(m.iec62443FR || '') + ' — ' + escHtml(m.frTitle || '') + '</div>\
      <div class="control-card-desc">' + escHtml(m.frDescription || '') + '</div>\
      <div style="font-size:0.8rem;margin-top:0.5rem"><strong>NIST 800-82:</strong> ' + escHtml(m.nist80082Chapter || '') + '</div>' +
      (m.nist80082ControlFamilies ? '<div style="margin-top:0.35rem">' + tagList(m.nist80082ControlFamilies) + '</div>' : '') +
      (m.nist80082OTGuidance ? '<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.5rem">' + escHtml(m.nist80082OTGuidance) + '</div>' : '') +
      (m.srs ? '<div class="table-wrap" style="margin-top:0.75rem"><table><thead><tr><th>SR</th><th>Name</th><th>NIST 800-82 Sections</th><th>Similarity</th></tr></thead><tbody>' + m.srs.map(function(sr) { return '<tr><td>' + escHtml(sr.iec62443SR) + '</td><td>' + escHtml(sr.srName || '') + '</td><td style="font-size:0.75rem">' + (sr.nist80082Sections ? sr.nist80082Sections.join(', ') : '') + '</td><td>' + escHtml(sr.similarity || '') + '</td></tr>'; }).join('') + '</tbody></table></div>' : '') +
    '</div>';}).join('');
}

async function renderRefMitreCtrl() {
  const data = await load('cross-references/mitre-to-controls.json');
  var mappings = data.mappings || [];

  return '<h2>' + escHtml(data.title || 'MITRE ATT&CK ICS to Controls') + '</h2>\
    <div class="disclaimer">' + escHtml(data.verificationNote || '') + '</div>\
    <div class="table-wrap"><table>\
      <thead><tr><th>Technique</th><th>Name</th><th>Control Slugs</th><th>IEC 62443 SRs</th><th>Primary Mitigation</th></tr></thead>\
      <tbody>' + mappings.map(function(m) { return '\
        <tr>\
          <td><a href="https://attack.mitre.org/techniques/' + escHtml(m.techniqueId) + '/" target="_blank" rel="noopener"><strong>' + escHtml(m.techniqueId) + '</strong></a></td>\
          <td>' + escHtml(m.name || '') + '</td>\
          <td style="font-size:0.7rem">' + (m.controlSlugs ? m.controlSlugs.map(function(c){return '<a href="#control/'+c+'" style="color:var(--accent)">'+escHtml(c)+'</a>';}).join(', ') : '') + '</td>\
          <td style="font-size:0.7rem">' + (m.iec62443SRs ? m.iec62443SRs.join(', ') : '') + '</td>\
          <td style="font-size:0.75rem">' + escHtml(m.primaryMitigation || '') + '</td>\
        </tr>';}).join('') +
    '</tbody></table></div>';
}

async function renderRefSectorCop() {
  const data = await load('cross-references/sector-to-nacsa-cop.json');
  var mappings = data.sectorMappings || [];

  return '<h2>' + escHtml(data.title || 'Sector to NACSA CoP') + '</h2>\
    <div class="disclaimer">' + escHtml(data.verificationNote || '') + '</div>' +
    mappings.map(function(m) { return '\
    <div class="control-card" style="margin-bottom:0.75rem">\
      <div class="control-card-title">' + escHtml(m.nacsaSector || m.sector || '') + '</div>\
      <div class="control-card-desc">Sector Lead: ' + escHtml(m.sectorLead || '') + ' · CoP: ' + escHtml(m.nacsaCop || '') + '</div>\
      <div style="font-size:0.8rem;margin-top:0.5rem"><strong>SL Recommendation:</strong> ' + escHtml(m.iec62443SLRecommendation || '') + '</div>' +
      (m.otSpecificOverlays ? '<div style="margin-top:0.5rem"><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem">OT-Specific Overlays</div><ul style="font-size:0.8rem;padding-left:1.25rem;margin:0">' + m.otSpecificOverlays.map(function(o){return '<li>'+escHtml(o)+'</li>';}).join('') + '</ul></div>' : '') +
      (m.keyOtStandards ? '<div style="margin-top:0.5rem">' + tagList(m.keyOtStandards) + '</div>' : '') +
    '</div>';}).join('');
}


// --- SEARCH ---
async function renderSearch(sub) {
  var query = decodeURIComponent(sub || searchQuery || '').toLowerCase().trim();
  if (!query) {
    setHTML('<div class="page-title">Search</div><div class="empty-state"><p class="empty-state-text">Enter a search term above.</p></div>');
    return;
  }

  const [controls, srData, incidents, actors, sectors] = await Promise.all([
    load('controls/library.json'),
    load('standards/iec62443/system-requirements.json'),
    load('threats/known-incidents.json'),
    load('threats/threat-actors.json'),
    load('sectors/index.json'),
  ]);

  var results = [];
  var allControls = Array.isArray(controls) ? controls : [];
  allControls.forEach(function(c) {
    if ((c.name + ' ' + c.description + ' ' + c.slug + ' ' + (c.iec62443SRs || []).join(' ')).toLowerCase().indexOf(query) !== -1) {
      results.push({ type: 'Control', name: c.name, desc: c.description || '', hash: 'control/' + c.slug });
    }
  });

  var allSRs = srData.systemRequirements || srData.requirements || [];
  allSRs.forEach(function(sr) {
    if ((sr.id + ' ' + sr.name + ' ' + sr.description).toLowerCase().indexOf(query) !== -1) {
      results.push({ type: 'System Requirement', name: sr.id + ' — ' + sr.name, desc: sr.description || '', hash: 'framework/iec-sr' });
    }
  });

  (incidents.incidents || []).forEach(function(inc) {
    if ((inc.name + ' ' + (inc.summary || '') + ' ' + inc.sector).toLowerCase().indexOf(query) !== -1) {
      results.push({ type: 'Incident', name: inc.name, desc: inc.summary || '', hash: 'threats/incidents' });
    }
  });

  (actors.threatActors || []).forEach(function(a) {
    if ((a.name + ' ' + (a.alternateNames || []).join(' ') + ' ' + a.attribution).toLowerCase().indexOf(query) !== -1) {
      results.push({ type: 'Threat Actor', name: a.name, desc: a.attribution || '', hash: 'threats/actors' });
    }
  });

  (sectors.sectors || []).forEach(function(s) {
    if ((s.name + ' ' + s.description).toLowerCase().indexOf(query) !== -1) {
      results.push({ type: 'Sector', name: s.name, desc: (s.description || '').substring(0, 150), hash: 'sector/' + s.id });
    }
  });

  var html = results.map(function(r) { return `
    <a class="control-card control-card-link" href="#${r.hash}" style="margin-bottom:0.5rem;text-decoration:none;color:inherit">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">
        <span class="tag">${escHtml(r.type)}</span>
        <span class="control-card-title" style="margin:0">${escHtml(r.name)}</span>
      </div>
      <div class="control-card-desc">${escHtml(r.desc)}</div>
    </a>`;}).join('');

  setHTML('\
    <div class="page-title">Search Results</div>\
    <div class="page-sub">' + results.length + ' results for "' + escHtml(query) + '"</div>' +
    (results.length ? html : '<div class="empty-state"><p class="empty-state-text">No results found.</p></div>')
  );
}


// === Export Functions ===

function exportToPDF() {
  document.body.classList.add('printing');
  window.print();
  document.body.classList.remove('printing');
}

function exportToCSV() {
  var view = parseHash().view;
  var data = [];
  var filename = 'export-' + view + '-' + new Date().toISOString().slice(0,10) + '.csv';

  if (view === 'controls') {
    var controls = cache.get('controls/library.json');
    if (controls) {
      var list = Array.isArray(controls) ? controls : [];
      data = list.map(function(c) {
        return {
          ID: c.slug || '',
          Name: c.name || '',
          Domain: c.domain || '',
          Description: (c.description || '').replace(/\n/g, ' ')
        };
      });
    }
  } else if (view === 'risk') {
    var reg = cache.get('risk-management/risk-register.json');
    if (reg) {
      var risks = reg.risks || [];
      data = risks.map(function(r) {
        return {
          ID: r.id || '',
          Risk: r.title || '',
          Impact: r.impact || '',
          Likelihood: r.likelihood || '',
          Category: r.category || ''
        };
      });
    }
  } else {
    alert('CSV export only supported for Controls and Risk Register views.');
    return;
  }

  if (!data.length) { alert('No data found to export.'); return; }

  var headers = Object.keys(data[0]);
  var csvContent = [
    headers.join(',')
  ].concat(data.map(function(row) {
    return headers.map(function(h) {
      return '"' + (row[h] || '').toString().replace(/"/g, '""') + '"';
    }).join(',');
  })).join('\n');

  var blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  var link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// --- INIT ---
window.addEventListener('hashchange', route);
document.addEventListener('click', function(e) {
  // Accordion toggle (data-accordion pattern)
  var trigger = e.target.closest('[data-accordion]');
  if (trigger) {
    var item = trigger.closest('.accordion-item');
    if (item) item.classList.toggle('open');
    return;
  }
  // Accordion toggle (aria-expanded pattern for audit package)
  var accTrigger = e.target.closest('.accordion-trigger[aria-expanded]');
  if (accTrigger) {
    var expanded = accTrigger.getAttribute('aria-expanded') === 'true';
    accTrigger.setAttribute('aria-expanded', !expanded);
    var content = accTrigger.nextElementSibling;
    if (content) content.hidden = expanded;
    return;
  }
});

document.addEventListener('DOMContentLoaded', function() {
  // Wire export buttons
  var pdfBtn = document.getElementById('btn-pdf');
  var csvBtn = document.getElementById('btn-csv');
  if (pdfBtn) pdfBtn.addEventListener('click', exportToPDF);
  if (csvBtn) csvBtn.addEventListener('click', exportToCSV);

  route();

  var searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        var q = searchInput.value.trim();
        if (q) {
          searchQuery = q;
          navigate('search/' + encodeURIComponent(q));
        }
      }
    });
  }
});
