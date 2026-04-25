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
    el.classList.toggle('active',
      dv === view ||
      (view === 'overview' && dv === 'overview') ||
      (view === 'control' && dv === 'controls') ||
      (dv === 'framework' && (view === 'sectors' || view === 'sector')) ||
      (dv === 'reference' && view === 'architecture')
    );
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
    case 'sectors':      return renderFramework('_sectors');
    case 'sector':       return renderSectorById(sub);
    case 'architecture': return sub ? renderArchitecture(sub) : renderReference('_architecture');
    case 'reference':    return renderReference(sub);
    case 'search':       return renderSearch(sub);
    case 'basic-start':  return renderBasicStart(sub);
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
  // Handle sectors sub-tab
  const showSectors = (sub === '_sectors');

  const srData = await load('standards/iec62443/system-requirements.json');
  const srTotal = (srData.systemRequirements || srData.requirements || []).length;
  const tabs = [
    { id: 'iec-overview', label: 'IEC 62443 Overview' },
    { id: 'iec-sl',       label: 'Security Levels' },
    { id: 'iec-fr',       label: 'Foundational Requirements' },
    { id: 'iec-sr',       label: 'System Requirements (' + srTotal + ' SRs)' },
    { id: 'purdue-interactive', label: 'Purdue Model' },
    { id: 'nist',         label: 'NIST SP 800-82' },
    { id: 'mitre',        label: 'MITRE ATT&CK for ICS' },
    { id: 'sectors',      label: 'Sectors' },
  ];
  const active = showSectors ? 'sectors' : (sub || 'iec-overview');

  const tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'framework/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'iec-overview')  content = await renderIecOverview();
  else if (active === 'iec-sl')   content = await renderIecSL();
  else if (active === 'iec-fr')   content = await renderIecFR();
  else if (active === 'iec-sr')   content = await renderIecSR();
  else if (active === 'purdue-interactive') content = await renderPurdueInteractive();
  else if (active === 'nist')     content = await renderNist();
  else if (active === 'mitre')    content = await renderMitre();
  else if (active === 'sectors')  content = await renderSectorsContent();

  setHTML('\
    <div class="page-title">Framework</div>\
    <div class="page-sub">IEC 62443 · NIST SP 800-82 Rev 3 · MITRE ATT&amp;CK for ICS · Sectors</div>' +
    tabsHtml + content
  );
}

async function renderSectorsContent() {
  const data = await load('sectors/index.json');
  const sectors = data.sectors || [];

  var html = sectors.map(function(s) {
    return '\
    <a class="control-card control-card-link" href="#sector/' + s.id + '" style="text-decoration:none;color:inherit">\
      <div class="control-card-title">' + escHtml(s.name) + '</div>\
      <div class="control-card-desc">NACSA Sector: ' + escHtml(String(s.nacsaSectorNumber || '')) + ' · Lead: ' + escHtml(s.nacsaSectorLead || '') + '</div>\
      <div class="control-card-desc">' + escHtml((s.description || '').substring(0, 200)) + (s.description && s.description.length > 200 ? '...' : '') + '</div>\
      <div class="control-card-meta">\
        <span class="badge badge-malaysia">Act 854</span>' +
        (s.keyOtRisks ? s.keyOtRisks.slice(0,2).map(function(r){return '<span class="tag">'+escHtml(r)+'</span>';}).join('') : '') +
      '</div>\
    </a>';}).join('');

  return '\
    <div class="page-sub">Sector-specific OT risks, NACSA obligations, and SL targeting by zone.</div>\
    <div class="control-grid">' + html + '</div>';
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
  const [data, sectorReqs] = await Promise.all([
    load('sectors/index.json'),
    load('sectors/requirements/' + id + '.json').catch(function() { return null; })
  ]);
  const sectors = data.sectors || [];
  const sector = sectors.find(function(s) { return s.id === id; });
  if (!sector) { setHTML('<div class="error-state"><h2>Sector not found</h2><button onclick="navigate(\'sectors\')">Back</button></div>'); return; }

  var slZoneHtml = sector.targetSLByZone ? Object.entries(sector.targetSLByZone).map(function(e) {
    return '<tr><td>' + escHtml(e[0]) + '</td><td>' + slBadge(e[1]) + '</td></tr>';
  }).join('') : '';

  // Subsectors from requirements file
  var subsectorsHtml = '';
  if (sectorReqs && sectorReqs.subsectors && sectorReqs.subsectors.length) {
    subsectorsHtml = '<h2 style="margin-top:1.5rem">Subsectors</h2><div class="accordion">' +
      sectorReqs.subsectors.map(function(sub) {
        var subZonesHtml = sub.iec62443Zones ? Object.entries(sub.iec62443Zones).map(function(e) {
          return '<tr><td style="font-size:0.75rem">' + escHtml(e[0]) + '</td><td>' + slBadge(e[1]) + '</td></tr>';
        }).join('') : '';

        var nacsaReqsHtml = (sub.nacsaRequirements || []).map(function(r) {
          return '<li style="font-size:0.75rem;margin-bottom:0.2rem">' + escHtml(r) + '</li>';
        }).join('');

        return '<div class="accordion-item">\
          <button class="accordion-trigger" data-accordion>\
            <span class="accordion-trigger-left">\
              <span>' + escHtml(sub.name) + '</span>\
            </span>\
            <span class="chevron">&#9654;</span>\
          </button>\
          <div class="accordion-content">\
            <div class="control-card-desc" style="margin-bottom:0.75rem">' + escHtml(sub.description || '') + '</div>\
            <div class="control-grid">\
              <div>\
                <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">OT Systems</div>' +
                tagList(sub.otSystems || []) +
              '</div>\
              <div>\
                <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">IEC 62443 Zone Assignments</div>\
                <div class="table-wrap" style="margin:0"><table style="font-size:0.75rem"><thead><tr><th>Zone</th><th>SL</th></tr></thead><tbody>' + subZonesHtml + '</tbody></table></div>\
              </div>\
            </div>' +
            (nacsaReqsHtml ? '<div style="margin-top:0.75rem"><div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">NACSA Requirements</div><ul style="padding-left:1.25rem;margin:0">' + nacsaReqsHtml + '</ul></div>' : '') +
          '</div>\
        </div>';
      }).join('') + '</div>';
  }

  // Requirements from requirements file
  var reqsHtml = '';
  if (sectorReqs && sectorReqs.requirements && sectorReqs.requirements.length) {
    reqsHtml = '<h2 style="margin-top:1.5rem">Sector Requirements (' + sectorReqs.requirements.length + ')</h2><div class="accordion">' +
      sectorReqs.requirements.map(function(req) {
        var techActionsHtml = (req.technical && req.technical.actions) ? req.technical.actions.map(function(a) {
          return '<li style="font-size:0.75rem;margin-bottom:0.2rem">' + escHtml(a) + '</li>';
        }).join('') : '';

        var govActionsHtml = (req.governance && req.governance.actions) ? req.governance.actions.map(function(a) {
          return '<li style="font-size:0.75rem;margin-bottom:0.2rem">' + escHtml(a) + '</li>';
        }).join('') : '';

        var slMapHtml = req.slMapping ? Object.entries(req.slMapping).map(function(e) {
          return '<div style="padding:0.35rem 0;border-top:1px solid var(--border);font-size:0.75rem"><strong>' + escHtml(e[0].toUpperCase()) + ':</strong> ' + escHtml(e[1]) + '</div>';
        }).join('') : '';

        return '<div class="accordion-item">\
          <button class="accordion-trigger" data-accordion>\
            <span class="accordion-trigger-left">\
              <span class="badge badge-sl2" style="margin-right:0.5rem">' + escHtml(req.id) + '</span>\
              <span>' + escHtml(req.name) + '</span>\
            </span>\
            <span class="chevron">&#9654;</span>\
          </button>\
          <div class="accordion-content">\
            <div class="control-card-desc" style="margin-bottom:0.75rem">' + escHtml(req.description || '') + '</div>' +
            (req.technical ? '<div style="margin-bottom:0.75rem"><div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Technical Controls</div><div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.35rem">' + escHtml(req.technical.summary || '') + '</div>' + (techActionsHtml ? '<ul style="padding-left:1.25rem;margin:0">' + techActionsHtml + '</ul>' : '') + '</div>' : '') +
            (req.governance ? '<div style="margin-bottom:0.75rem"><div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Governance</div>' + (govActionsHtml ? '<ul style="padding-left:1.25rem;margin:0">' + govActionsHtml + '</ul>' : '') + '</div>' : '') +
            (slMapHtml ? '<div style="margin-bottom:0.75rem"><div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Security Level Mapping</div>' + slMapHtml + '</div>' : '') +
            (req.mitreAttackIcs ? '<div class="control-card-meta">' + req.mitreAttackIcs.map(function(m){return '<span class="tag" style="color:var(--danger)">'+escHtml(m)+'</span>';}).join('') + '</div>' : '') +
          '</div>\
        </div>';
      }).join('') + '</div>';
  }

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
    subsectorsHtml +
    reqsHtml +
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
    { id: 'sl-gap',      label: 'SL Gap Assessment' },
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
  else if (active === 'sl-gap') content = await renderSLGapAssessment();

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
  // Handle architecture sub-routes
  const showArch = (sub === '_architecture');
  if (sub === 'purdue' || sub === 'zones' || sub === 'assets') {
    return renderArchitecture(sub);
  }

  const tabs = [
    { id: 'nacsa',        label: 'IEC 62443 to NACSA' },
    { id: 'nist-csf',     label: 'IEC 62443 to NIST CSF' },
    { id: 'nist80082',    label: 'IEC 62443 to NIST 800-82' },
    { id: 'mitre-ctrl',   label: 'MITRE to Controls' },
    { id: 'sector-cop',   label: 'Sector to NACSA CoP' },
    { id: 'architecture', label: 'Architecture' },
  ];
  const active = showArch ? 'architecture' : (sub || 'nacsa');

  const tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'reference/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'nacsa') content = await renderRefNacsa();
  else if (active === 'nist-csf') content = await renderRefNistCsf();
  else if (active === 'nist80082') content = await renderRefNist80082();
  else if (active === 'mitre-ctrl') content = await renderRefMitreCtrl();
  else if (active === 'sector-cop') content = await renderRefSectorCop();
  else if (active === 'architecture') content = await renderArchitectureContent();

  setHTML('\
    <div class="page-title">Reference</div>\
    <div class="page-sub">Cross-reference mappings between IEC 62443, NACSA, NIST, MITRE, and architecture</div>' +
    tabsHtml + content
  );
}

async function renderArchitectureContent() {
  const archTabs = [
    { id: 'purdue', label: 'Purdue Model' },
    { id: 'zones',  label: 'Zones & Conduits' },
    { id: 'assets', label: 'Asset Types' },
  ];

  var archTabsHtml = '<div class="sub-tabs">' + archTabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === 'purdue' ? ' active' : '') + '" onclick="navigate(\'reference/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var archContent = await renderPurdue();

  return archTabsHtml + archContent;
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


// --- PURDUE MODEL INTERACTIVE ---
async function renderPurdueInteractive() {
  const data = await load('sectors/purdue-model.json');
  if (!data || !data.levels) return '<div class="empty-state"><div class="empty-state-text">No Purdue model data available.</div></div>';

  var levelIcons = {
    sensor: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>',
    controller: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="18" rx="2"/><line x1="6" y1="8" x2="6" y2="16"/><line x1="10" y1="8" x2="10" y2="16"/><circle cx="16" cy="12" r="2"/></svg>',
    monitor: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
    server: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>',
    shield: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    building: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="2" width="16" height="20"/><rect x="8" y="6" width="3" height="3"/><rect x="13" y="6" width="3" height="3"/><rect x="8" y="12" width="3" height="3"/><rect x="13" y="12" width="3" height="3"/><rect x="10" y="18" width="4" height="4"/></svg>',
    cloud: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>'
  };

  // Render stacked levels from top (Level 5) to bottom (Level 0)
  var sortedLevels = data.levels.slice().sort(function(a, b) { return b.level - a.level; });

  var diagramHtml = sortedLevels.map(function(l) {
    var icon = levelIcons[l.icon] || '';
    var levelLabel = l.level === 3.5 ? '3.5' : String(l.level);
    var isDMZ = l.level === 3.5;
    var isOT = l.level <= 3 && l.level !== 3.5;
    var isIT = l.level >= 4;

    var zoneLabel = isOT ? 'OT Zone' : (isDMZ ? 'DMZ' : 'IT Zone');
    var zoneBadgeClass = isOT ? 'badge-sl3' : (isDMZ ? 'badge-sl2' : 'badge-sl1');

    var devicesHtml = (l.typicalDevices || []).map(function(d) {
      return '<span class="tag" style="font-size:0.65rem;margin:1px">' + escHtml(d) + '</span>';
    }).join('');

    var protocolsHtml = (l.allowedProtocols || []).map(function(p) {
      return '<span class="tag" style="font-size:0.6rem;margin:1px;background:rgba(56,189,248,0.1);color:var(--accent)">' + escHtml(p) + '</span>';
    }).join('');

    var secReqsHtml = (l.securityRequirements || []).map(function(r) {
      return '<li style="font-size:0.75rem;margin-bottom:0.15rem">' + escHtml(r) + '</li>';
    }).join('');

    return '\
    <div class="purdue-level" data-purdue-level="' + levelLabel + '" style="border-left:4px solid ' + (l.color || 'var(--accent)') + ';margin-bottom:0;cursor:pointer;position:relative;background:var(--bg-card);border:1px solid var(--border);border-left:4px solid ' + (l.color || 'var(--accent)') + ';border-radius:8px;padding:1rem;transition:all 0.2s" onclick="togglePurdueDetail(this)">\
      <div style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap">\
        <div style="display:flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:8px;background:' + (l.color || 'var(--accent)') + '15;color:' + (l.color || 'var(--accent)') + '">' + icon + '</div>\
        <div style="flex:1;min-width:200px">\
          <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap">\
            <span style="font-weight:700;font-size:0.9rem;color:' + (l.color || 'var(--accent)') + '">Level ' + escHtml(levelLabel) + '</span>\
            <span style="font-weight:700;font-size:0.9rem">' + escHtml(l.name) + '</span>\
            <span class="badge ' + zoneBadgeClass + '" style="font-size:0.6rem">' + zoneLabel + '</span>\
          </div>\
          <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.15rem">' + escHtml(l.subtitle || '') + '</div>\
        </div>\
        <div style="display:flex;align-items:center;gap:0.5rem">\
          <span style="font-size:0.7rem;color:var(--text-muted)">' + escHtml(l.defaultSL || '') + '</span>\
          <span class="chevron" style="transition:transform 0.2s;color:var(--text-muted)">&#9654;</span>\
        </div>\
      </div>\
      <div class="purdue-detail" style="display:none;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border)">\
        <div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem">' + escHtml(l.description || '') + '</div>\
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem">\
          <div>\
            <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.5rem">Typical Devices</div>\
            <div style="display:flex;flex-wrap:wrap;gap:2px">' + devicesHtml + '</div>\
          </div>\
          <div>\
            <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.5rem">Allowed Protocols</div>\
            <div style="display:flex;flex-wrap:wrap;gap:2px">' + protocolsHtml + '</div>\
          </div>\
        </div>\
        <div style="margin-top:0.75rem">\
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.5rem">Security Requirements</div>\
          <ul style="padding-left:1.25rem;margin:0;color:var(--text-secondary)">' + secReqsHtml + '</ul>\
        </div>\
        <div style="margin-top:0.5rem;font-size:0.75rem;color:var(--text-muted)"><strong>IEC 62443 Zone:</strong> ' + escHtml(l.isoZone || '') + '</div>\
      </div>\
    </div>' +
    (isDMZ ? '<div style="text-align:center;padding:0.25rem 0;font-size:0.7rem;font-weight:700;color:var(--warning);letter-spacing:0.15em;text-transform:uppercase">--- IT / OT BOUNDARY ---</div>' : '');
  }).join('');

  // Data flow rules
  var flowRulesHtml = (data.dataFlowRules || []).map(function(r) {
    var color = r.allowed ? 'var(--success)' : 'var(--danger)';
    var icon = r.allowed ? '&#10003;' : '&#10007;';
    return '<tr style="font-size:0.8rem">\
      <td style="color:' + color + ';font-weight:700;text-align:center">' + icon + '</td>\
      <td>' + escHtml(r.from) + '</td>\
      <td>' + escHtml(r.to) + '</td>\
      <td style="font-size:0.75rem">' + escHtml(r.condition) + '</td>\
    </tr>';
  }).join('');

  return '\
    <h2>Interactive Purdue Model</h2>\
    <div class="page-sub">Click any level to expand details. Stacked from Internet (Level 5) down to Process (Level 0).</div>\
    <div class="disclaimer">The Purdue Model / ISA-95 reference architecture defines hierarchical security zones for OT environments. The IDMZ (Level 3.5) is the critical IT/OT boundary.</div>\
    <div style="display:flex;flex-direction:column;gap:2px;margin:1rem 0">' + diagramHtml + '</div>\
    <h2 style="margin-top:1.5rem">Data Flow Rules</h2>\
    <div class="page-sub">Permitted and prohibited data flows between Purdue levels.</div>\
    <div class="table-wrap"><table>\
      <thead><tr><th></th><th>From</th><th>To</th><th>Condition</th></tr></thead>\
      <tbody>' + flowRulesHtml + '</tbody>\
    </table></div>';
}

window.togglePurdueDetail = function(el) {
  var detail = el.querySelector('.purdue-detail');
  var chevron = el.querySelector('.chevron');
  if (detail) {
    var isOpen = detail.style.display !== 'none';
    detail.style.display = isOpen ? 'none' : 'block';
    if (chevron) chevron.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(90deg)';
  }
};


// --- SL GAP ASSESSMENT ---
async function renderSLGapAssessment() {
  const data = await load('sectors/sl-assessment.json');
  if (!data || !data.foundationalRequirements) return '<div class="empty-state"><div class="empty-state-text">No SL assessment data available.</div></div>';

  var frs = data.foundationalRequirements;

  // FR overview cards
  var frOverviewHtml = frs.map(function(fr) {
    return '\
    <div class="control-card" style="border-left:3px solid var(--accent2)">\
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">\
        <span class="badge badge-sl2">' + escHtml(fr.id) + '</span>\
        <span class="control-card-title" style="margin:0">' + escHtml(fr.name) + '</span>\
        <span class="tag" style="font-size:0.6rem">' + fr.srCount + ' SRs</span>\
      </div>\
      <div class="control-card-desc">' + escHtml(fr.description) + '</div>\
      <div style="font-size:0.7rem;color:var(--text-muted);margin-top:0.35rem">' + escHtml(fr.iec62443Reference) + '</div>\
    </div>';
  }).join('');

  // Interactive assessment form
  var assessmentFormHtml = '\
    <div id="sl-gap-tool" style="margin-top:1rem">\
      <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;align-items:flex-end">\
        <div style="flex:1;min-width:200px">\
          <label style="font-size:0.75rem;font-weight:600;color:var(--text-muted);display:block;margin-bottom:0.25rem">Zone Name</label>\
          <input type="text" id="sl-zone-name" placeholder="e.g., Process Control Zone A" style="width:100%;padding:0.5rem;border:1px solid var(--border);border-radius:6px;background:var(--bg-card);color:var(--text-primary);font-size:0.85rem">\
        </div>\
        <div style="min-width:120px">\
          <label style="font-size:0.75rem;font-weight:600;color:var(--text-muted);display:block;margin-bottom:0.25rem">Target SL (SL-T)</label>\
          <select id="sl-target-level" style="width:100%;padding:0.5rem;border:1px solid var(--border);border-radius:6px;background:var(--bg-card);color:var(--text-primary);font-size:0.85rem">\
            <option value="1">SL 1 — Basic</option>\
            <option value="2" selected>SL 2 — Enhanced</option>\
            <option value="3">SL 3 — Advanced</option>\
            <option value="4">SL 4 — Critical</option>\
          </select>\
        </div>\
      </div>';

  // Assessment criteria table per FR
  assessmentFormHtml += '<div id="sl-assessment-criteria">';
  frs.forEach(function(fr) {
    assessmentFormHtml += '\
      <div class="sl-fr-section" style="margin-bottom:1.5rem">\
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:2px solid var(--accent2)">\
          <span class="badge badge-sl2">' + escHtml(fr.id) + '</span>\
          <span style="font-weight:700">' + escHtml(fr.name) + '</span>\
        </div>\
        <div class="table-wrap"><table style="font-size:0.8rem">\
          <thead><tr><th style="width:50%">Criterion</th><th style="width:15%;text-align:center">Required At</th><th style="width:15%;text-align:center">Achieved?</th><th style="width:20%;text-align:center">Gap Status</th></tr></thead>\
          <tbody>';

    (fr.assessmentCriteria || []).forEach(function(c, idx) {
      var criterionId = fr.id + '-c' + idx;
      assessmentFormHtml += '\
        <tr data-sl-criterion="' + c.slTarget + '" data-fr="' + fr.id + '">\
          <td>' + escHtml(c.criterion) + '</td>\
          <td style="text-align:center">' + slBadge(c.slTarget) + '</td>\
          <td style="text-align:center">\
            <select class="sl-achieved-select" data-criterion-id="' + criterionId + '" onchange="updateSLGapStatus(this)" style="padding:0.25rem 0.5rem;border:1px solid var(--border);border-radius:4px;background:var(--bg-card);color:var(--text-primary);font-size:0.75rem">\
              <option value="">--</option>\
              <option value="yes">Yes</option>\
              <option value="partial">Partial</option>\
              <option value="no">No</option>\
              <option value="na">N/A</option>\
            </select>\
          </td>\
          <td style="text-align:center" class="sl-gap-cell" id="gap-' + criterionId + '">--</td>\
        </tr>';
    });

    assessmentFormHtml += '</tbody></table></div></div>';
  });
  assessmentFormHtml += '</div>';

  // SL requirements detail per FR
  var slDetailHtml = frs.map(function(fr) {
    return '\
    <div class="accordion-item">\
      <button class="accordion-trigger" data-accordion>\
        <span class="accordion-trigger-left">\
          <span class="badge badge-sl2" style="margin-right:0.5rem">' + escHtml(fr.id) + '</span>\
          <span>' + escHtml(fr.name) + ' — SL 1-4 Requirements</span>\
        </span>\
        <span class="chevron">&#9654;</span>\
      </button>\
      <div class="accordion-content">\
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:0.75rem">' +
          ['SL1','SL2','SL3','SL4'].map(function(sl, i) {
            var reqs = fr.requirements[sl] || [];
            return '<div style="padding:0.75rem;border-radius:6px;border:1px solid var(--border)">\
              <div style="margin-bottom:0.5rem">' + slBadge(i+1) + '</div>\
              <ul style="padding-left:1rem;margin:0;font-size:0.75rem;color:var(--text-secondary)">' +
                reqs.map(function(r) { return '<li style="margin-bottom:0.2rem">' + escHtml(r) + '</li>'; }).join('') +
              '</ul></div>';
          }).join('') +
        '</div>\
      </div>\
    </div>';
  }).join('');

  // Gap summary section
  assessmentFormHtml += '\
    <div style="margin-top:1.5rem;padding:1rem;border:2px solid var(--accent);border-radius:8px;background:rgba(56,189,248,0.03)">\
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem">\
        <span style="font-weight:700;font-size:1rem">Gap Assessment Summary</span>\
        <button onclick="calculateSLGapSummary()" style="padding:0.35rem 0.75rem;border:1px solid var(--accent);border-radius:6px;background:rgba(56,189,248,0.1);color:var(--accent);font-size:0.8rem;cursor:pointer;font-weight:600">Calculate Summary</button>\
        <button onclick="exportSLGapCSV()" style="padding:0.35rem 0.75rem;border:1px solid var(--border);border-radius:6px;background:var(--bg-card);color:var(--text-secondary);font-size:0.8rem;cursor:pointer">Export CSV</button>\
      </div>\
      <div id="sl-gap-summary" style="font-size:0.85rem;color:var(--text-secondary)">Click "Calculate Summary" after completing the assessment above.</div>\
    </div>';

  assessmentFormHtml += '</div>';

  // Priority scale reference
  var priorityHtml = data.gapAssessmentTemplate ? '\
    <h2 style="margin-top:1.5rem">Gap Priority Scale</h2>\
    <div class="control-grid">' +
    Object.entries(data.gapAssessmentTemplate.priorityScale).map(function(e) {
      var colors = { Critical: 'var(--danger)', High: '#F97316', Medium: 'var(--warning)', Low: 'var(--success)' };
      return '<div class="control-card" style="border-left:3px solid ' + (colors[e[0]] || 'var(--text-muted)') + '">\
        <div class="control-card-title" style="color:' + (colors[e[0]] || 'var(--text-muted)') + '">' + escHtml(e[0]) + '</div>\
        <div class="control-card-desc">' + escHtml(e[1]) + '</div>\
      </div>';
    }).join('') + '</div>' : '';

  return '\
    <h2>SL Gap Assessment Tool</h2>\
    <div class="page-sub">Assess current Security Level (SL-A) against target (SL-T) per IEC 62443-3-3 Foundational Requirements.</div>\
    <div class="disclaimer">' + escHtml(data.verificationNote || '') + '</div>\
    <h2>7 Foundational Requirements</h2>\
    <div class="control-grid">' + frOverviewHtml + '</div>\
    <h2 style="margin-top:1.5rem">SL Requirements Detail (SL 1-4)</h2>\
    <div class="accordion">' + slDetailHtml + '</div>\
    <h2 style="margin-top:1.5rem">Interactive Gap Assessment</h2>\
    <div class="page-sub">Select a target SL and assess each criterion. The tool calculates gaps between your target and achieved levels.</div>' +
    assessmentFormHtml +
    priorityHtml;
}

window.updateSLGapStatus = function(selectEl) {
  var criterionId = selectEl.getAttribute('data-criterion-id');
  var gapCell = document.getElementById('gap-' + criterionId);
  if (!gapCell) return;

  var val = selectEl.value;
  var row = selectEl.closest('tr');
  var requiredSL = parseInt(row.getAttribute('data-sl-criterion') || '1');
  var targetSL = parseInt(document.getElementById('sl-target-level').value || '2');

  if (val === '') { gapCell.innerHTML = '--'; gapCell.style.color = 'var(--text-muted)'; return; }
  if (val === 'na') { gapCell.innerHTML = '<span class="badge" style="background:var(--bg-main);color:var(--text-muted)">N/A</span>'; return; }
  if (requiredSL > targetSL) {
    gapCell.innerHTML = '<span class="badge" style="background:rgba(34,197,94,0.1);color:var(--success)">Not Required</span>';
    return;
  }

  if (val === 'yes') {
    gapCell.innerHTML = '<span class="badge" style="background:rgba(34,197,94,0.1);color:var(--success)">Met</span>';
  } else if (val === 'partial') {
    gapCell.innerHTML = '<span class="badge" style="background:rgba(245,158,11,0.1);color:var(--warning)">Partial Gap</span>';
  } else {
    gapCell.innerHTML = '<span class="badge" style="background:rgba(239,68,68,0.1);color:var(--danger)">Gap</span>';
  }
};

window.calculateSLGapSummary = function() {
  var zoneName = document.getElementById('sl-zone-name').value || 'Unnamed Zone';
  var targetSL = parseInt(document.getElementById('sl-target-level').value || '2');
  var selects = document.querySelectorAll('.sl-achieved-select');

  var totalCriteria = 0;
  var met = 0;
  var partial = 0;
  var gap = 0;
  var na = 0;
  var unanswered = 0;
  var frScores = {};

  selects.forEach(function(s) {
    var row = s.closest('tr');
    var requiredSL = parseInt(row.getAttribute('data-sl-criterion') || '1');
    var frId = row.getAttribute('data-fr');

    if (requiredSL > targetSL) return; // Not required for this SL target
    totalCriteria++;

    if (!frScores[frId]) frScores[frId] = { met: 0, partial: 0, gap: 0, na: 0, unanswered: 0, total: 0 };
    frScores[frId].total++;

    if (s.value === '') { unanswered++; frScores[frId].unanswered++; }
    else if (s.value === 'yes') { met++; frScores[frId].met++; }
    else if (s.value === 'partial') { partial++; frScores[frId].partial++; }
    else if (s.value === 'na') { na++; frScores[frId].na++; }
    else { gap++; frScores[frId].gap++; }
  });

  var applicableCriteria = totalCriteria - na;
  var score = applicableCriteria > 0 ? Math.round((met / applicableCriteria) * 100) : 0;

  var frTableHtml = Object.entries(frScores).map(function(e) {
    var frId = e[0], s = e[1];
    var frApplicable = s.total - s.na;
    var frPct = frApplicable > 0 ? Math.round((s.met / frApplicable) * 100) : 0;
    var barColor = frPct >= 80 ? 'var(--success)' : (frPct >= 50 ? 'var(--warning)' : 'var(--danger)');
    return '<tr>\
      <td><strong>' + escHtml(frId) + '</strong></td>\
      <td style="text-align:center;color:var(--success)">' + s.met + '</td>\
      <td style="text-align:center;color:var(--warning)">' + s.partial + '</td>\
      <td style="text-align:center;color:var(--danger)">' + s.gap + '</td>\
      <td style="width:120px"><div style="background:var(--border);border-radius:4px;height:8px;overflow:hidden"><div style="background:' + barColor + ';width:' + frPct + '%;height:100%"></div></div><div style="font-size:0.65rem;text-align:center;color:var(--text-muted);margin-top:2px">' + frPct + '%</div></td>\
    </tr>';
  }).join('');

  var overallColor = score >= 80 ? 'var(--success)' : (score >= 50 ? 'var(--warning)' : 'var(--danger)');

  var summaryDiv = document.getElementById('sl-gap-summary');
  summaryDiv.innerHTML = '\
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:0.75rem;margin-bottom:1rem">\
      <div style="text-align:center;padding:0.75rem;border-radius:8px;border:1px solid var(--border)">\
        <div style="font-size:1.5rem;font-weight:700;color:' + overallColor + '">' + score + '%</div>\
        <div style="font-size:0.7rem;color:var(--text-muted)">Overall Compliance</div>\
      </div>\
      <div style="text-align:center;padding:0.75rem;border-radius:8px;border:1px solid var(--border)">\
        <div style="font-size:1.5rem;font-weight:700;color:var(--success)">' + met + '</div>\
        <div style="font-size:0.7rem;color:var(--text-muted)">Met</div>\
      </div>\
      <div style="text-align:center;padding:0.75rem;border-radius:8px;border:1px solid var(--border)">\
        <div style="font-size:1.5rem;font-weight:700;color:var(--warning)">' + partial + '</div>\
        <div style="font-size:0.7rem;color:var(--text-muted)">Partial</div>\
      </div>\
      <div style="text-align:center;padding:0.75rem;border-radius:8px;border:1px solid var(--border)">\
        <div style="font-size:1.5rem;font-weight:700;color:var(--danger)">' + gap + '</div>\
        <div style="font-size:0.7rem;color:var(--text-muted)">Gap</div>\
      </div>\
      <div style="text-align:center;padding:0.75rem;border-radius:8px;border:1px solid var(--border)">\
        <div style="font-size:1.5rem;font-weight:700;color:var(--text-muted)">' + unanswered + '</div>\
        <div style="font-size:0.7rem;color:var(--text-muted)">Unanswered</div>\
      </div>\
    </div>\
    <div style="font-size:0.85rem;margin-bottom:0.75rem"><strong>Zone:</strong> ' + escHtml(zoneName) + ' &middot; <strong>Target SL:</strong> SL ' + targetSL + ' &middot; <strong>Applicable Criteria:</strong> ' + applicableCriteria + ' of ' + totalCriteria + '</div>\
    <div class="table-wrap"><table style="font-size:0.8rem">\
      <thead><tr><th>FR</th><th style="text-align:center">Met</th><th style="text-align:center">Partial</th><th style="text-align:center">Gap</th><th>Compliance</th></tr></thead>\
      <tbody>' + frTableHtml + '</tbody>\
    </table></div>';
};

window.exportSLGapCSV = function() {
  var zoneName = document.getElementById('sl-zone-name').value || 'Unnamed Zone';
  var targetSL = document.getElementById('sl-target-level').value || '2';
  var rows = [['Zone', 'FR', 'Criterion', 'Required SL', 'Target SL', 'Achieved', 'Gap Status']];
  var selects = document.querySelectorAll('.sl-achieved-select');

  selects.forEach(function(s) {
    var row = s.closest('tr');
    var frId = row.getAttribute('data-fr') || '';
    var requiredSL = row.getAttribute('data-sl-criterion') || '';
    var criterion = row.querySelector('td').textContent || '';
    var achieved = s.value || '';
    var gapCell = document.getElementById('gap-' + s.getAttribute('data-criterion-id'));
    var gapStatus = gapCell ? gapCell.textContent.trim() : '';

    rows.push([zoneName, frId, criterion, 'SL ' + requiredSL, 'SL ' + targetSL, achieved, gapStatus]);
  });

  var csv = rows.map(function(r) {
    return r.map(function(c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(',');
  }).join('\n');

  var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  var link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.setAttribute('download', 'sl-gap-assessment-' + new Date().toISOString().slice(0,10) + '.csv');
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};


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

// --- B.A.S.I.C. S.T.A.R.T. ---
async function renderBasicStart(sub) {
  var data = await load('basic-start/framework.json');
  if (!data) return;
  var pillars = data.framework.pillars || [];

  var tabs = [
    { id: 'overview',       label: 'Framework Overview' },
    { id: 'pillars',        label: 'All 10 Pillars' },
    { id: 'worked-example', label: 'Worked Example' },
    { id: 'tools',          label: 'Python Tools' },
  ];
  var active = sub || 'overview';

  var tabsHtml = '<div class="sub-tabs">' + tabs.map(function(t) {
    return '<button class="sub-tab' + (t.id === active ? ' active' : '') + '" onclick="navigate(\'basic-start/' + t.id + '\')">' + t.label + '</button>';
  }).join('') + '</div>';

  var content = '';
  if (active === 'overview')            content = await renderBSOverview(data, pillars);
  else if (active === 'pillars')        content = renderBSPillars(pillars);
  else if (active === 'worked-example') content = await renderBSWorkedExample(pillars);
  else if (active === 'tools')          content = renderBSTools();
  else if (active.indexOf('pillar-') === 0) {
    var slug = active.replace('pillar-', '');
    var pillar = pillars.find(function(p) { return p.slug === slug; });
    content = pillar ? renderBSPillarDetail(pillar) : '<div class="error-state"><h2>Pillar not found</h2></div>';
  } else {
    content = await renderBSOverview(data, pillars);
  }

  setHTML(
    '<div class="page-header">' +
      '<h1 class="page-title">B.A.S.I.C. S.T.A.R.T.</h1>' +
      '<p class="page-subtitle">10-Pillar OT/ICS Cybersecurity Programme Framework &middot; Mike Holcomb / UtilSec, LLC</p>' +
    '</div>' +
    '<div class="disclaimer"><strong>Source:</strong> Framework structure and pillar names are from <em>GenAI Prompts to Help You Build OT/ICS Cybersecurity</em> by Mike Holcomb (UtilSec, LLC). ' +
    'The worked example uses a <strong>fictional company (SABESB)</strong> for illustration only. All plans must be validated by certified OT professionals before operational use.</div>' +
    tabsHtml + content
  );
}

async function renderBSOverview(data, pillars) {
  var fw = data.framework;
  var basicPillars = pillars.filter(function(p) { return p.phase === 'BASIC'; });
  var startPillars = pillars.filter(function(p) { return p.phase === 'START'; });

  function phaseBlock(label, items, colour) {
    return '<div class="card" style="border-left:4px solid ' + colour + ';margin-bottom:0.75rem">' +
      '<div class="card-title" style="letter-spacing:0.05em">' + escHtml(label) + '</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-top:0.5rem">' +
      items.map(function(p) {
        return '<div onclick="navigate(\'basic-start/pillar-' + p.slug + '\')" style="cursor:pointer;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:0.4rem 0.75rem;display:flex;align-items:center;gap:0.5rem">' +
          '<span style="font-size:1.1rem;font-weight:800;color:' + colour + '">' + escHtml(p.letter) + '</span>' +
          '<span style="font-size:0.8rem;font-weight:600">' + p.id + '. ' + escHtml(p.name) + '</span>' +
          '</div>';
      }).join('') + '</div></div>';
  }

  var pa = fw.promptArchitecture || {};
  var stepsHtml = [
    { n: 1, t: 'Discovery & Context Gathering', d: pa.phase1 || '' },
    { n: 2, t: 'Strategy Generation', d: pa.phase2 || '' },
    { n: 3, t: 'Next Steps', d: pa.phase3 || '' },
  ].map(function(s) {
    return '<div class="attack-step"><strong>Phase ' + s.n + ': ' + escHtml(s.t) + '</strong>' +
      '<div style="font-size:0.8rem;margin-top:0.25rem">' + escHtml(s.d) + '</div></div>';
  }).join('');

  var pillarCardsHtml = pillars.map(function(p) {
    var colour = p.phase === 'BASIC' ? '#3B82F6' : '#8B5CF6';
    var badges = (p.iec62443Ref||[]).map(function(r) { return '<span class="badge badge-sl2" style="font-size:0.6rem">' + escHtml(r) + '</span>'; }).join('') +
      (p.nacsaRef||[]).map(function(r) { return '<span class="badge badge-malaysia" style="font-size:0.6rem">' + escHtml(r) + '</span>'; }).join('');
    return '<div class="card card-link" onclick="navigate(\'basic-start/pillar-' + p.slug + '\')">' +
      '<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">' +
        '<span style="font-size:1.6rem;font-weight:900;color:' + colour + ';min-width:2rem">' + escHtml(p.letter) + '</span>' +
        '<div><div class="card-title" style="margin:0">' + p.id + '. ' + escHtml(p.name) + '</div>' +
        '<div style="font-size:0.65rem;color:' + colour + '">' + escHtml(p.phase) + '</div></div>' +
      '</div>' +
      '<div class="card-desc">' + escHtml(p.description.substring(0,140)) + '&hellip;</div>' +
      '<div style="margin-top:0.5rem;display:flex;gap:0.3rem;flex-wrap:wrap">' + badges + '</div>' +
      '</div>';
  }).join('');

  return '<div class="card" style="border-left:3px solid var(--accent);margin-bottom:1.5rem">' +
    '<div class="card-title">' + escHtml(fw.acronym||'B.A.S.I.C. S.T.A.R.T.') + '</div>' +
    '<div class="card-desc">' + escHtml(fw.description||'') + '</div></div>' +
    '<div class="two-col" style="margin-bottom:1.5rem">' +
      phaseBlock('B.A.S.I.C. &mdash; Foundation', basicPillars, '#3B82F6') +
      phaseBlock('S.T.A.R.T. &mdash; Programme Maturity', startPillars, '#8B5CF6') +
    '</div>' +
    '<h2>Prompt Architecture &mdash; 3-Phase Design</h2>' +
    '<div class="attack-chain">' + stepsHtml + '</div>' +
    '<h2>All 10 Pillars</h2>' +
    '<div class="two-col">' + pillarCardsHtml + '</div>';
}

function renderBSPillars(pillars) {
  return '<div class="two-col">' + pillars.map(function(p) {
    var colour = p.phase === 'BASIC' ? '#3B82F6' : '#8B5CF6';
    var badges = (p.iec62443Ref||[]).map(function(r) { return '<span class="badge badge-sl2" style="font-size:0.6rem">' + escHtml(r) + '</span>'; }).join('') +
      (p.nacsaRef||[]).map(function(r) { return '<span class="badge badge-malaysia" style="font-size:0.6rem">' + escHtml(r) + '</span>'; }).join('') +
      (p.nistCsfRef||[]).slice(0,2).map(function(r) { return '<span class="badge" style="font-size:0.6rem;background:var(--bg-card);border:1px solid var(--border)">' + escHtml(r) + '</span>'; }).join('');
    return '<div class="card card-link" onclick="navigate(\'basic-start/pillar-' + p.slug + '\')">' +
      '<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem">' +
        '<span style="font-size:2rem;font-weight:900;color:' + colour + ';min-width:2.5rem">' + escHtml(p.letter) + '</span>' +
        '<div><div class="card-title" style="margin:0">' + p.id + '. ' + escHtml(p.name) + '</div>' +
        '<span style="font-size:0.65rem;background:' + colour + '20;color:' + colour + ';padding:0.15rem 0.4rem;border-radius:3px;font-weight:600">' + escHtml(p.phase) + '</span></div>' +
      '</div>' +
      '<div class="card-desc">' + escHtml(p.description.substring(0,160)) + '&hellip;</div>' +
      '<div style="margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid var(--border)">' +
        '<div style="font-size:0.7rem;color:var(--text-muted);margin-bottom:0.25rem"><strong>Key Principle:</strong> ' + escHtml((p.keyPrinciple||'').substring(0,120)) + '&hellip;</div>' +
        '<div style="display:flex;gap:0.3rem;flex-wrap:wrap;margin-top:0.25rem">' + badges + '</div>' +
      '</div></div>';
  }).join('') + '</div>';
}

function renderBSPillarDetail(p) {
  var colour = p.phase === 'BASIC' ? '#3B82F6' : '#8B5CF6';

  var questionsHtml = (p.discoveryQuestions||[]).map(function(q, i) {
    return '<div class="attack-step"><strong>Q' + (i+1) + ': ' + escHtml(q.topic) + '</strong>' +
      '<div style="font-size:0.8rem;color:var(--text-muted);margin-top:0.15rem">e.g., ' + escHtml(q.example) + '</div></div>';
  }).join('');

  var sectionsHtml = (p.planSections||[]).map(function(s) {
    return '<div class="card" style="margin-bottom:0.75rem">' +
      '<div class="card-title">Section ' + s.section + ': ' + escHtml(s.title) + '</div>' +
      '<ul style="font-size:0.8rem;padding-left:1.25rem;margin:0">' +
      (s.keyTopics||[]).map(function(t) { return '<li style="margin-bottom:0.35rem">' + escHtml(t) + '</li>'; }).join('') +
      '</ul></div>';
  }).join('');

  var kpis = p.kpis || {};
  var leadHtml = (kpis.leading||[]).map(function(k) { return '<li style="margin-bottom:0.35rem">' + escHtml(k) + '</li>'; }).join('');
  var lagHtml  = (kpis.lagging||[]).map(function(k) { return '<li style="margin-bottom:0.35rem">' + escHtml(k) + '</li>'; }).join('');
  var iecBadges   = (p.iec62443Ref||[]).map(function(r) { return '<span class="badge badge-sl2" style="margin:2px">' + escHtml(r) + '</span>'; }).join('');
  var nacsaBadges = (p.nacsaRef||[]).map(function(r) { return '<span class="badge badge-malaysia" style="margin:2px">' + escHtml(r) + '</span>'; }).join('');
  var nistBadges  = (p.nistCsfRef||[]).map(function(r) { return '<span class="badge" style="margin:2px;background:var(--bg-card);border:1px solid var(--border);font-size:0.65rem">' + escHtml(r) + '</span>'; }).join('');

  return '<div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem">' +
    '<span style="font-size:3rem;font-weight:900;color:' + colour + ';line-height:1">' + escHtml(p.letter) + '</span>' +
    '<div><h2 style="margin:0">' + p.id + '. ' + escHtml(p.name) + '</h2>' +
    '<span style="font-size:0.75rem;background:' + colour + '20;color:' + colour + ';padding:0.2rem 0.5rem;border-radius:4px;font-weight:600">' + escHtml(p.phase) + ' Pillar</span></div></div>' +

    '<div class="card" style="border-left:3px solid ' + colour + ';margin-bottom:1rem"><div class="card-desc">' + escHtml(p.description) + '</div></div>' +
    '<div class="card" style="border-left:3px solid var(--danger);margin-bottom:1.5rem"><div class="card-title">Key Principle</div><div class="card-desc">' + escHtml(p.keyPrinciple||'') + '</div></div>' +

    '<div class="two-col" style="margin-bottom:1.5rem">' +
      '<div><h3>Framework Mappings</h3>' +
        '<div style="margin-bottom:0.5rem"><strong style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em">IEC 62443</strong><br>' + iecBadges + '</div>' +
        '<div style="margin-bottom:0.5rem"><strong style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em">NACSA Act 854</strong><br>' + nacsaBadges + '</div>' +
        '<div><strong style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em">NIST CSF 2.0</strong><br>' + nistBadges + '</div></div>' +
      '<div><h3>Phase 1: Discovery Questions</h3><div class="attack-chain">' + questionsHtml + '</div></div>' +
    '</div>' +

    '<h2>Plan Sections (Phase 2 Output)</h2>' + sectionsHtml +

    '<h2>KPI Framework</h2>' +
    '<div class="two-col">' +
      '<div class="card"><div class="card-title">Leading Indicators</div>' +
        '<div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem">Predictive &mdash; measure programme health before failure occurs</div>' +
        '<ul style="font-size:0.8rem;padding-left:1.25rem;margin:0">' + leadHtml + '</ul></div>' +
      '<div class="card"><div class="card-title">Lagging Indicators</div>' +
        '<div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem">Reactive &mdash; measure outcomes after the fact</div>' +
        '<ul style="font-size:0.8rem;padding-left:1.25rem;margin:0">' + lagHtml + '</ul></div>' +
    '</div>' +

    '<div style="margin-top:1.5rem;display:flex;gap:0.5rem">' +
      '<button class="btn-secondary" onclick="navigate(\'basic-start/pillars\')">&#8592; All Pillars</button>' +
      '<button class="btn-secondary" onclick="navigate(\'basic-start/worked-example\')">Worked Example &#8594;</button>' +
    '</div>';
}

async function renderBSWorkedExample(pillars) {
  var ex = await load('basic-start/worked-example.json');
  if (!ex) return '<div class="error-state"><h2>Could not load worked example</h2></div>';
  var scenario = ex.scenario || {};
  var outputs  = ex.outputs  || [];

  var systemsHtml = Object.entries(scenario.systems||{}).map(function(entry) {
    return '<tr><td style="font-weight:600;font-size:0.8rem;white-space:nowrap">' + escHtml(entry[0]) + '</td>' +
      '<td style="font-size:0.8rem">' + escHtml(entry[1]) + '</td></tr>';
  }).join('');

  var gapHtml = Object.entries(scenario.currentMaturity||{}).filter(function(e) { return typeof e[1]==='string'; }).map(function(e) {
    return '<li style="margin-bottom:0.25rem;font-size:0.8rem"><strong>' + escHtml(e[0]) + ':</strong> ' + escHtml(e[1]) + '</li>';
  }).join('');

  var threatTags = (scenario.threats&&scenario.threats.primary||[]).map(function(t) {
    return '<span class="badge">' + escHtml(t) + '</span>';
  }).join(' ');

  var outputsHtml = outputs.map(function(o) {
    var pillar  = pillars.find(function(p) { return p.slug === o.slug; }) || {};
    var colour  = pillar.phase === 'BASIC' ? '#3B82F6' : '#8B5CF6';
    var kpis    = o.kpis || {};
    var leadHtml = (kpis.leading||[]).map(function(k) { return '<li style="font-size:0.75rem;margin-bottom:0.25rem">' + escHtml(k) + '</li>'; }).join('');
    var lagHtml  = (kpis.lagging||[]).map(function(k) { return '<li style="font-size:0.75rem;margin-bottom:0.25rem">' + escHtml(k) + '</li>'; }).join('');

    var findingsHtml = Object.entries(o)
      .filter(function(e) { return !['pillarId','slug','title','contextSummary','kpis'].includes(e[0]); })
      .slice(0, 3)
      .map(function(entry) {
        var key = entry[0]; var val = entry[1];
        var label = key.replace(/([A-Z])/g,' $1').replace(/^./,function(s){return s.toUpperCase();});
        var preview = '';
        if (typeof val === 'string') {
          preview = escHtml(val.substring(0, 220)) + (val.length > 220 ? '&hellip;' : '');
        } else if (Array.isArray(val) && val.length) {
          var items = val.slice(0, 2).map(function(item) {
            if (typeof item === 'string') return escHtml(item.substring(0, 130));
            var text = item.step || item.name || item.asset || item.programme || item.test || item.incident || '';
            var detail = item.description || item.procedure || item.backupMethod || item.vector || '';
            return escHtml(text) + (detail ? ': ' + escHtml(String(detail).substring(0, 80)) : '');
          }).join('<br>');
          if (val.length > 2) items += '<br><em style="color:var(--text-muted)">+' + (val.length-2) + ' more&hellip;</em>';
          preview = items;
        } else if (val && typeof val === 'object') {
          var subVals = Object.values(val).filter(function(v){return typeof v==='string';}).slice(0,2);
          preview = subVals.map(function(v){return escHtml(v.substring(0,130));}).join('<br>');
        }
        return preview ? '<div style="margin-bottom:0.75rem">' +
          '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.2rem">' + escHtml(label) + '</div>' +
          '<div style="font-size:0.8rem">' + preview + '</div></div>' : '';
      }).filter(Boolean).join('');

    return '<div class="card" style="margin-bottom:1rem;border-left:4px solid ' + colour + '">' +
      '<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem">' +
        '<span style="font-size:1.8rem;font-weight:900;color:' + colour + ';line-height:1">' + escHtml(pillar.letter||'') + '</span>' +
        '<div><div class="card-title" style="margin:0">' + o.pillarId + '. ' + escHtml(o.title) + '</div>' +
        '<div style="font-size:0.7rem;color:var(--text-muted);margin-top:0.1rem">' + escHtml(o.contextSummary||'') + '</div></div>' +
      '</div>' +
      findingsHtml +
      ((kpis.leading||kpis.lagging) ? '<div class="two-col" style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)">' +
        (kpis.leading&&kpis.leading.length ? '<div><strong style="font-size:0.7rem;text-transform:uppercase">Leading KPIs</strong><ul style="padding-left:1.25rem;margin:0.25rem 0 0">' + leadHtml + '</ul></div>' : '') +
        (kpis.lagging&&kpis.lagging.length ? '<div><strong style="font-size:0.7rem;text-transform:uppercase">Lagging KPIs</strong><ul style="padding-left:1.25rem;margin:0.25rem 0 0">' + lagHtml + '</ul></div>' : '') +
      '</div>' : '') +
      '<div style="margin-top:0.5rem"><span onclick="navigate(\'basic-start/pillar-' + o.slug + '\')" style="font-size:0.75rem;color:var(--accent);cursor:pointer">View pillar framework &#8594;</span></div>' +
      '</div>';
  }).join('');

  return '<h2>Scenario: ' + escHtml(scenario.company) + ' (' + escHtml(scenario.abbreviation) + ')</h2>' +
    '<div class="card" style="border-left:3px solid var(--accent);margin-bottom:1.5rem">' +
      '<div class="card-desc">' + escHtml(scenario.description||'') + '</div>' +
      '<div style="margin-top:0.5rem;display:flex;gap:0.5rem;flex-wrap:wrap">' +
        (scenario.nciiDesignated ? '<span class="badge badge-malaysia">NCII Designated</span>' : '') +
        '<span class="badge badge-sl2">SL 1 &rarr; SL 2 Target</span>' +
        '<span class="badge">' + escHtml(scenario.sector||'') + '</span>' +
        '<span class="badge">' + escHtml(scenario.location||'') + '</span>' +
      '</div></div>' +
    '<div class="two-col" style="margin-bottom:1.5rem">' +
      '<div><h3>OT System Landscape</h3>' +
        '<div class="table-wrap"><table><thead><tr><th>System</th><th>Details</th></tr></thead>' +
        '<tbody>' + systemsHtml + '</tbody></table></div></div>' +
      '<div><h3>Current Gaps</h3>' +
        '<div class="card" style="border-left:3px solid var(--danger)"><ul style="padding-left:1.25rem;margin:0">' + gapHtml + '</ul></div>' +
        '<div style="margin-top:0.75rem"><div style="font-size:0.75rem;font-weight:600;margin-bottom:0.4rem">Primary Threats</div>' + threatTags + '</div>' +
      '</div>' +
    '</div>' +
    '<h2>B.A.S.I.C. S.T.A.R.T. Plan Outputs &mdash; All 10 Pillars</h2>' +
    '<div class="disclaimer"><strong>Note:</strong> SABESB is entirely fictional. These outputs show what the framework produces when run with real sector, technology, and constraint context.</div>' +
    outputsHtml;
}

function renderBSTools() {
  function codeBlock(code) {
    return '<pre style="background:var(--bg-card);padding:0.5rem 0.75rem;border-radius:4px;font-size:0.75rem;overflow-x:auto;margin:0.25rem 0">' + escHtml(code) + '</pre>';
  }

  var honeypot = '<div class="card" style="margin-bottom:1.5rem">' +
    '<div class="card-title" style="font-size:1.05rem">Industrial Modbus TCP Honeypot</div>' +
    '<div style="display:flex;gap:0.5rem;margin:0.5rem 0">' +
      '<span class="badge">Python 3</span><span class="badge badge-sl2">tools/modbus-honeypot.py</span>' +
    '</div>' +
    '<div class="card-desc">Simulates a Water Treatment Plant PLC responding to Modbus TCP on port 502. Detects pings, TCP SYN scans, and all Modbus function codes. Red alerts on writes to Crown Jewel registers (chlorination setpoint, treatment stage, maintenance mode). Logs structured JSON to rotating file; forwards to remote syslog.</div>' +
    '<div class="two-col" style="margin-top:1rem">' +
      '<div>' +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem">Install</div>' +
        codeBlock('pip install pymodbus scapy') +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin:0.75rem 0 0.25rem">Usage</div>' +
        codeBlock('sudo python3 modbus-honeypot.py\\\n  --host 0.0.0.0 --port 502\\\n  --syslog-host 10.0.0.50') +
        '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.4rem"><strong>Run as:</strong> root/sudo (raw socket + port 502)</div>' +
      '</div>' +
      '<div>' +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem">Alert Colours</div>' +
        '<div style="display:flex;align-items:flex-start;gap:0.5rem;margin-bottom:0.4rem"><span style="background:#EF4444;color:white;padding:0.1rem 0.4rem;border-radius:3px;font-size:0.7rem;font-weight:700;white-space:nowrap">RED</span><span style="font-size:0.8rem">Write to any register or coil (attacker modifying PLC state)</span></div>' +
        '<div style="display:flex;align-items:flex-start;gap:0.5rem;margin-bottom:0.4rem"><span style="background:#F59E0B;color:white;padding:0.1rem 0.4rem;border-radius:3px;font-size:0.7rem;font-weight:700;white-space:nowrap">YELLOW</span><span style="font-size:0.8rem">TCP SYN scan on OT ports (Nmap reconnaissance)</span></div>' +
        '<div style="display:flex;align-items:flex-start;gap:0.5rem;margin-bottom:0.75rem"><span style="background:#06B6D4;color:white;padding:0.1rem 0.4rem;border-radius:3px;font-size:0.7rem;font-weight:700;white-space:nowrap">CYAN</span><span style="font-size:0.8rem">New TCP connection or ICMP ping</span></div>' +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem">Crown Jewel Registers</div>' +
        '<div style="font-size:0.8rem">HR0: Chlorine Dosing Setpoint &bull; HR6: Treatment Stage &bull; HR7: Maintenance Mode Flag</div>' +
      '</div>' +
    '</div></div>';

  var pcap = '<div class="card" style="margin-bottom:1.5rem">' +
    '<div class="card-title" style="font-size:1.05rem">Passive OT PCAP Analyzer</div>' +
    '<div style="display:flex;gap:0.5rem;margin:0.5rem 0">' +
      '<span class="badge">Python 3</span><span class="badge badge-sl2">tools/pcap-analyzer.py</span>' +
    '</div>' +
    '<div class="card-desc">Reads an offline .pcap/.pcapng file via GUI file selector (no live sniffing). Extracts asset inventory with OUI vendor resolution, detects industrial protocols, maps communication flows, and alerts on public IP interactions. Exports two structured CSV files.</div>' +
    '<div class="two-col" style="margin-top:1rem">' +
      '<div>' +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem">Install</div>' +
        codeBlock('pip install pyshark\n# Also: sudo apt install tshark') +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin:0.75rem 0 0.25rem">Usage</div>' +
        codeBlock('python3 pcap-analyzer.py\n# GUI file selector opens automatically') +
        '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.4rem"><strong>Run as:</strong> any user (no root needed &mdash; offline only)</div>' +
      '</div>' +
      '<div>' +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem">Output Files</div>' +
        '<div style="margin-bottom:0.5rem"><span class="badge badge-sl2" style="font-size:0.65rem">ot_asset_inventory.csv</span><div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.2rem">MAC, IP, OUI Vendor, Protocols Observed</div></div>' +
        '<div style="margin-bottom:0.75rem"><span class="badge badge-sl2" style="font-size:0.65rem">ot_communication_map.csv</span><div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.2rem">Src/Dst IP+MAC, Protocol, Port, Packet Count, Public_Internet_Routing</div></div>' +
        '<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem">Protocols Detected</div>' +
        '<div style="font-size:0.8rem">Modbus/502 &bull; DNP3/20000 &bull; ENIP-CIP/44818 &bull; S7Comm/102 &bull; OPC-UA/4840 &bull; BACnet/47808 &bull; PROFINET</div>' +
      '</div>' +
    '</div></div>';

  return '<div class="card" style="border-left:3px solid var(--accent);margin-bottom:1.5rem">' +
    '<div class="card-title">OT Security Python Tools</div>' +
    '<div class="card-desc">Practical tools for OT environments. Source in <code>tools/</code> directory.</div></div>' +
    '<div class="disclaimer"><strong>Lab/testbed only.</strong> Never deploy the Modbus honeypot on a production OT network. The PCAP analyzer is offline-only and safe for sensitive environments.</div>' +
    honeypot + pcap;
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
