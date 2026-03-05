/* OT Security Framework — SPA v1.1
   Static, zero-dependency, hash-routed.
   Data loaded lazily and cached in Map.
*/

'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
const cache = new Map();
let currentView = null;
let currentSub  = null;
let searchQuery = '';

// ─── Data loader ─────────────────────────────────────────────────────────────
async function load(path) {
  if (cache.has(path)) return cache.get(path);
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to load ${path}: ${res.status}`);
  const data = await res.json();
  cache.set(path, data);
  return data;
}

// ─── Router ──────────────────────────────────────────────────────────────────
function parseHash() {
  const hash = location.hash.replace('#', '') || 'overview';
  const parts = hash.split('/');
  return { view: parts[0], sub: parts[1] || null };
}

function navigate(view, sub) {
  const hash = sub ? `#${view}/${sub}` : `#${view}`;
  history.pushState(null, '', hash);
  route();
}

async function route() {
  const { view, sub } = parseHash();
  currentView = view;
  currentSub  = sub;
  updateNav(view);
  const main = document.getElementById('main');
  main.innerHTML = '<div class="empty-state"><div class="empty-state-text">Loading…</div></div>';
  try {
    await render(view, sub);
  } catch (e) {
    main.innerHTML = `<div class="empty-state"><div class="empty-state-text">Error loading view.</div><div style="font-size:0.75rem;margin-top:0.5rem;color:var(--danger)">${e.message}</div></div>`;
    console.error(e);
  }
}

function updateNav(view) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.view === view);
  });
}

// ─── Main dispatcher ─────────────────────────────────────────────────────────
async function render(view, sub) {
  switch (view) {
    case 'overview':        return renderOverview();
    case 'standards':       return renderStandards(sub);
    case 'architecture':    return renderArchitecture(sub);
    case 'requirements':    return renderRequirements(sub);
    case 'controls':        return renderControls(sub);
    case 'evidence':        return renderEvidence(sub);
    case 'threats':         return renderThreats(sub);
    case 'sectors':         return renderSectors(sub);
    case 'cross-ref':       return renderCrossRef(sub);
    case 'framework':       return renderFramework(sub);
    case 'artifacts':       return renderArtifacts(sub);
    case 'risk-management': return renderRiskManagement(sub);
    case 'search':          return renderSearch(sub);
    default:                return renderOverview();
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function setMain(html) {
  document.getElementById('main').innerHTML = html;
}

function slBadge(sl) {
  if (!sl && sl !== 0) return '';
  const n = String(sl).replace('SL','').replace(' ','');
  return `<span class="badge badge-sl${n}">SL ${n}</span>`;
}

function slDots(level) {
  const n = parseInt(level) || 0;
  return `<div class="sl-indicator">${[1,2,3,4].map(i =>
    `<div class="sl-dot${i <= n ? ` active-${n}` : ''}"></div>`
  ).join('')}</div>`;
}

function typeBadge(type) {
  if (!type) return '';
  const map = { preventive:'preventive', detective:'detective', corrective:'corrective' };
  const cls = map[type] || '';
  return `<span class="badge badge-${cls}">${type}</span>`;
}

function nacsaBadge(codes) {
  if (!codes || !codes.length) return '';
  return codes.map(c => `<span class="badge badge-malaysia">${c}</span>`).join(' ');
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function tagList(arr) {
  if (!arr || !arr.length) return '';
  return `<div class="tag-list">${arr.map(t => `<span class="tag">${escHtml(t)}</span>`).join('')}</div>`;
}

function cardClick(view, sub) {
  return `onclick="navigate('${view}','${sub}')" style="cursor:pointer"`;
}

// ─── OVERVIEW ─────────────────────────────────────────────────────────────────
async function renderOverview() {
  const [reqs, controls, incidents, actors, sectors] = await Promise.all([
    load('requirements/index.json'),
    load('controls/library.json'),
    load('threats/known-incidents.json'),
    load('threats/threat-actors.json'),
    load('sectors/index.json'),
  ]);

  const domainCount = reqs.domains ? reqs.domains.length : 12;
  const controlCount = Array.isArray(controls) ? controls.length : 0;
  const incidentCount = incidents.incidents ? incidents.incidents.length : 0;
  const actorCount = actors.threatActors ? actors.threatActors.length : 0;
  const sectorCount = sectors.sectors ? sectors.sectors.length : 0;

  const quickLinks = [
    { icon: '📋', label: 'IEC 62443 System Requirements', view: 'standards', sub: 'iec-sr', desc: '51 SRs with SL 1-4 descriptions and NACSA mappings' },
    { icon: '🏗️', label: 'Purdue Model Architecture', view: 'architecture', sub: 'purdue', desc: 'Levels 0–5 with asset types, protocols, and security controls' },
    { icon: '🔒', label: 'Network Segmentation Requirements', view: 'requirements', sub: 'network-segmentation', desc: 'IDMZ, zone enforcement, OT protocol-aware firewall' },
    { icon: '⚡', label: 'Safety System Security', view: 'requirements', sub: 'safety-system-security', desc: 'SIS isolation, program integrity, TRITON lessons' },
    { icon: '🚨', label: 'Incident Response & NACSA s26', view: 'requirements', sub: 'incident-detection-response', desc: '6-hour notification procedure and OT IRP requirements' },
    { icon: '🎯', label: 'Known OT Incidents', view: 'threats', sub: 'incidents', desc: 'Stuxnet, TRITON, Ukraine, Colonial Pipeline, Oldsmar' },
  ];

  const sectors_html = sectors.sectors ? sectors.sectors.map(s => `
    <div class="card card-link" onclick="navigate('sectors','${s.id}')">
      <div class="card-title">${escHtml(s.name)}</div>
      <div class="card-sub">${escHtml(s.nacsaSectorLead || '')} · SL-T: ${escHtml(s.defaultSLTarget || 'SL 2 min')}</div>
      <div class="card-tags">${nacsaBadge(['NACSA'])}<span class="badge badge-sl${s.defaultSLTarget ? s.defaultSLTarget.replace('SL ','') : '2'}">${s.defaultSLTarget || 'SL 2'}</span></div>
    </div>`).join('') : '';

  setMain(`
    <div class="disclaimer">
      <strong>Educational use only.</strong> IEC 62443 content is paraphrased — obtain normative text from iec.ch.
      NACSA Act 854 references are indicative — verify against official Gazette. Content marked <code>constructed-indicative</code> has not been verified against official sources.
    </div>

    <div class="page-title">OT Security Framework</div>
    <div class="page-sub">IEC 62443 · NIST SP 800-82 · MITRE ATT&amp;CK for ICS · NACSA Act 854 (Malaysia)</div>

    <div class="stats-banner">
      <div class="stat-card"><div class="stat-number">51</div><div class="stat-label">IEC 62443 SRs</div></div>
      <div class="stat-card"><div class="stat-number">${domainCount}</div><div class="stat-label">Security Domains</div></div>
      <div class="stat-card"><div class="stat-number">${controlCount}</div><div class="stat-label">Controls</div></div>
      <div class="stat-card"><div class="stat-number">${incidentCount}</div><div class="stat-label">Incidents</div></div>
      <div class="stat-card"><div class="stat-number">${actorCount}</div><div class="stat-label">Threat Actors</div></div>
      <div class="stat-card"><div class="stat-number">${sectorCount}</div><div class="stat-label">Sectors</div></div>
      <div class="stat-card"><div class="stat-number">4</div><div class="stat-label">Security Levels</div></div>
      <div class="stat-card"><div class="stat-number">6</div><div class="stat-label">NACSA s26</div><div class="stat-label" style="font-size:0.6rem">hour notification</div></div>
    </div>

    <h2>Quick Start</h2>
    <div class="two-col" style="margin-bottom:1.5rem">
      ${quickLinks.map(l => `
        <div class="card card-link" onclick="navigate('${l.view}','${l.sub}')">
          <div class="card-title">${l.icon} ${escHtml(l.label)}</div>
          <div class="card-desc">${escHtml(l.desc)}</div>
        </div>`).join('')}
    </div>

    <h2>Sectors &amp; Malaysia NCII</h2>
    <div class="three-col">${sectors_html}</div>

    <h2>Security Level Reference</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>SL</th><th>Label</th><th>Threat Profile</th><th>Malaysia Context</th></tr></thead>
      <tbody>
        <tr class="sl-row-1"><td>${slBadge(1)}</td><td>Basic</td><td>Casual / opportunistic</td><td>Non-NCII OT environments</td></tr>
        <tr class="sl-row-2"><td>${slBadge(2)}</td><td>Enhanced</td><td>Motivated, generic IT skills</td><td>NCII baseline for most OT sectors</td></tr>
        <tr class="sl-row-3"><td>${slBadge(3)}</td><td>Advanced</td><td>OT-expert attacker</td><td>High-criticality NCII assets (TNB transmission, major water works)</td></tr>
        <tr class="sl-row-4"><td>${slBadge(4)}</td><td>Critical</td><td>Nation-state, SIS-targeting</td><td>Safety Instrumented Systems — ALL sectors</td></tr>
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

// ─── STANDARDS ────────────────────────────────────────────────────────────────
async function renderStandards(sub) {
  const tabs = [
    { id: 'iec-overview', label: 'IEC 62443 Overview' },
    { id: 'iec-sl',       label: 'Security Levels' },
    { id: 'iec-fr',       label: 'Foundational Requirements' },
    { id: 'iec-sr',       label: 'System Requirements (51 SRs)' },
    { id: 'nist',         label: 'NIST SP 800-82' },
    { id: 'mitre',        label: 'MITRE ATT&CK for ICS' },
  ];
  const active = sub || 'iec-overview';

  const tabsHtml = `<div class="tabs">${tabs.map(t =>
    `<button class="tab-btn${t.id === active ? ' active' : ''}" onclick="navigate('standards','${t.id}')">${t.label}</button>`
  ).join('')}</div>`;

  let content = '';
  if (active === 'iec-overview')  content = await renderIecOverview();
  else if (active === 'iec-sl')   content = await renderIecSL();
  else if (active === 'iec-fr')   content = await renderIecFR();
  else if (active === 'iec-sr')   content = await renderIecSR();
  else if (active === 'nist')     content = await renderNist();
  else if (active === 'mitre')    content = await renderMitre();

  setMain(`
    <div class="page-title">Standards Reference</div>
    <div class="page-sub">IEC 62443 · NIST SP 800-82 Rev 3 · MITRE ATT&amp;CK for ICS</div>
    ${tabsHtml}
    ${content}
  `);
}

async function renderIecOverview() {
  const data = await load('standards/iec62443/index.json');
  const seriesHtml = data.seriesBreakdown ? data.seriesBreakdown.map(s => `
    <tr>
      <td><strong>${escHtml(s.part)}</strong></td>
      <td>${escHtml(s.title)}</td>
      <td>${escHtml(s.scope)}</td>
      <td>${escHtml(s.status || '')}</td>
    </tr>`).join('') : '';

  const conceptsHtml = data.keyConceptSummary ? Object.entries(data.keyConceptSummary).map(([k,v]) => `
    <div class="card">
      <div class="card-title">${escHtml(k)}</div>
      <div class="card-desc">${escHtml(v.definition || v)}</div>
      ${v.examples ? tagList(v.examples) : ''}
    </div>`).join('') : '';

  return `
    <div class="disclaimer">${escHtml(data.verificationNote || 'Paraphrased from IEC 62443 — obtain normative text from iec.ch')}</div>
    <h2>${escHtml(data.title || 'IEC 62443')}</h2>
    <div class="detail-body" style="margin-bottom:1rem">${escHtml(data.overview || '')}</div>

    <h2>Series Breakdown</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Part</th><th>Title</th><th>Scope</th><th>Status</th></tr></thead>
      <tbody>${seriesHtml}</tbody>
    </table></div>

    <h2>Key Concepts</h2>
    <div class="two-col">${conceptsHtml}</div>

    ${data.malaysiaNexus ? `
    <h2>Malaysia NCII Nexus</h2>
    <div class="card">
      <div class="card-desc">${escHtml(data.malaysiaNexus.summary || '')}</div>
      ${data.malaysiaNexus.nacsaAlignmentPoints ? `<ul style="margin-top:0.75rem;padding-left:1.25rem;font-size:0.8rem;color:var(--text-muted)">${data.malaysiaNexus.nacsaAlignmentPoints.map(p=>`<li>${escHtml(p)}</li>`).join('')}</ul>` : ''}
    </div>` : ''}
  `;
}

async function renderIecSL() {
  const data = await load('standards/iec62443/security-levels.json');
  const levelsHtml = data.levels ? data.levels.map(sl => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
        ${slBadge(sl.sl)} ${slDots(sl.sl)}
        <span class="card-title" style="margin:0">${escHtml(sl.label)}</span>
      </div>
      <div class="card-desc">${escHtml(sl.shortDescription || sl.description || '')}</div>
      <div class="detail-section" style="margin-top:0.75rem">
        <div style="font-size:0.75rem;color:var(--text-muted)"><strong>Threat Profile:</strong> ${escHtml(sl.threatProfile || '')}</div>
        <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem"><strong>Malaysia Context:</strong> ${escHtml(sl.malaysiaContext || '')}</div>
        ${Array.isArray(sl.typicalApplicability) ? `
        <div style="margin-top:0.35rem"><div style="font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.25rem">Typical Applicability</div>${tagList(sl.typicalApplicability)}</div>` : ''}
      </div>
      ${sl.controlCharacteristics ? `
        <div style="margin-top:0.75rem">
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.35rem">Control Characteristics</div>
          ${typeof sl.controlCharacteristics === 'string' ? `<p style="font-size:0.8rem;color:var(--text-muted)">${escHtml(sl.controlCharacteristics)}</p>` : tagList(sl.controlCharacteristics)}
        </div>` : ''}
    </div>`).join('') : '';

  return `
    <h2>Security Level Definitions</h2>
    <div class="two-col">${levelsHtml}</div>
    ${data.slTargetingProcess ? `
      <h2>SL Targeting Process (IEC 62443-3-2)</h2>
      <div class="card-desc" style="margin-bottom:0.75rem">${escHtml(data.slTargetingProcess.description || '')}</div>
      <div class="attack-chain">${(data.slTargetingProcess.steps || []).map(step => `
        <div class="attack-step"><strong>Step ${step.step}:</strong> ${escHtml(step.action)}</div>`).join('')}
      </div>` : ''}
  `;
}

async function renderIecFR() {
  const data = await load('standards/iec62443/foundational-requirements.json');
  const frsHtml = data.foundationalRequirements ? data.foundationalRequirements.map(fr => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
        <span class="badge badge-sl2">${escHtml(fr.id)}</span>
        <span class="card-title" style="margin:0">${escHtml(fr.name)}</span>
      </div>
      <div class="card-desc">${escHtml(fr.description)}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem">${escHtml(fr.rationale || '')}</div>
      <div style="margin-top:0.5rem;display:flex;flex-wrap:wrap;gap:0.35rem">
        <span class="tag">SRs: ${escHtml(fr.srRange || '')}</span>
        <span class="tag">Count: ${escHtml(String(fr.srCount || ''))}</span>
        ${fr.nacsa ? fr.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('') : ''}
      </div>
      ${fr.otContext ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem;border-top:1px solid var(--border);padding-top:0.5rem"><strong>OT Context:</strong> ${escHtml(fr.otContext)}</div>` : ''}
    </div>`).join('') : '';

  return `
    <h2>7 Foundational Requirements (FRs)</h2>
    <div class="page-sub">The 7 FRs define the security property categories. Each FR contains multiple System Requirements (SRs).</div>
    <div class="two-col">${frsHtml}</div>
  `;
}

async function renderIecSR() {
  const data = await load('standards/iec62443/system-requirements.json');
  const allSRs = data.systemRequirements || data.requirements || [];
  if (!allSRs.length) return '<div class="empty-state">No data</div>';

  const frGroups = {};
  allSRs.forEach(sr => {
    const fr = sr.fr || 'Other';
    if (!frGroups[fr]) frGroups[fr] = [];
    frGroups[fr].push(sr);
  });

  const srHtml = Object.entries(frGroups).map(([fr, srs]) => `
    <h2 style="margin-top:1.5rem">${escHtml(fr)} — ${escHtml(srs[0]?.frName || '')}</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>SR</th><th>Name</th><th>SL1</th><th>SL2</th><th>SL3</th><th>SL4</th><th>NACSA</th></tr></thead>
      <tbody>${srs.map(sr => `
        <tr class="card-link" onclick="showSRDetail(${JSON.stringify(JSON.stringify(sr)).slice(1,-1).replace(/'/g,'&#39;')})" style="cursor:pointer">
          <td><strong>${escHtml(sr.id)}</strong></td>
          <td>${escHtml(sr.name)}</td>
          <td style="text-align:center">${sr.sl1 ? '●' : '○'}</td>
          <td style="text-align:center">${sr.sl2 ? '●' : '○'}</td>
          <td style="text-align:center">${sr.sl3 ? '●' : '○'}</td>
          <td style="text-align:center">${sr.sl4 ? '●' : '○'}</td>
          <td>${sr.nacsa ? sr.nacsa.map(n => `<span class="badge badge-malaysia" style="margin:1px">${escHtml(n)}</span>`).join('') : ''}</td>
        </tr>`).join('')}
      </tbody>
    </table></div>
  `).join('');

  return `
    <div class="page-sub">Click any SR for full SL 1–4 descriptions and mappings. ${allSRs.length} SRs across 7 FRs.</div>
    <div id="sr-detail-panel"></div>
    ${srHtml}
  `;
}

// expose SR detail globally
window.showSRDetail = function(srJson) {
  try {
    const sr = JSON.parse(srJson);
    const panel = document.getElementById('sr-detail-panel');
    if (!panel) return;
    panel.innerHTML = `
      <div class="card" style="border-color:var(--accent);margin-bottom:1.5rem">
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.75rem">
          <span class="badge badge-sl2">${escHtml(sr.id)}</span>
          <span class="card-title" style="margin:0">${escHtml(sr.name)}</span>
          <button onclick="document.getElementById('sr-detail-panel').innerHTML=''" style="margin-left:auto;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1rem">✕</button>
        </div>
        <div class="card-desc">${escHtml(sr.description || '')}</div>
        <div class="two-col" style="margin-top:1rem">
          ${[1,2,3,4].map(l => `
            <div>
              <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.25rem">${slBadge(l)}</div>
              <div style="font-size:0.8rem">${escHtml(sr[`sl${l}`] || '—')}</div>
            </div>`).join('')}
        </div>
        ${sr.otConsiderations ? `<div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border);font-size:0.8rem;color:var(--text-muted)"><strong>OT Considerations:</strong> ${escHtml(sr.otConsiderations)}</div>` : ''}
        <div class="card-tags" style="margin-top:0.75rem">
          ${sr.nacsa ? sr.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('') : ''}
          ${sr.nistCsf ? sr.nistCsf.map(n => `<span class="tag">${escHtml(n)}</span>`).join('') : ''}
          ${sr.mitreAttackIcs ? sr.mitreAttackIcs.map(m => `<span class="tag" style="color:var(--danger)">${escHtml(m)}</span>`).join('') : ''}
        </div>
      </div>
    `;
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch(e) { console.error('SR detail parse error', e); }
};

async function renderNist() {
  const data = await load('standards/nist-800-82/index.json');
  const chapHtml = data.chapters ? data.chapters.map(c => `
    <div class="card">
      <div class="card-title">${escHtml(c.chapter)} — ${escHtml(c.title)}</div>
      <div class="card-desc">${escHtml(c.summary || '')}</div>
      ${c.keyTopics ? tagList(c.keyTopics) : ''}
    </div>`).join('') : '';

  return `
    <div class="disclaimer">NIST SP 800-82 is a US government publication in the public domain. Available free at nvlpubs.nist.gov.</div>
    <h2>${escHtml(data.title || 'NIST SP 800-82')}</h2>
    <div class="detail-body" style="margin-bottom:1rem">${escHtml(data.overview || '')}</div>
    ${data.keyChangesRev3 ? `<h2>Key Changes in Rev 3</h2><div class="attack-chain">${data.keyChangesRev3.map(c => `<div class="attack-step">${escHtml(c)}</div>`).join('')}</div>` : ''}
    <h2>Chapters</h2>
    <div class="two-col">${chapHtml}</div>
    ${data.relationToIEC62443 ? `<h2>Relation to IEC 62443</h2><div class="card"><div class="card-desc">${escHtml(data.relationToIEC62443)}</div></div>` : ''}
  `;
}

async function renderMitre() {
  const [idx, techniques] = await Promise.all([
    load('standards/mitre-attack-ics/index.json'),
    load('standards/mitre-attack-ics/techniques.json'),
  ]);

  const tacticsHtml = idx.tactics ? idx.tactics.map(t => `
    <div class="card">
      <div class="card-title">${escHtml(t.id)} — ${escHtml(t.name)}</div>
      <div class="card-desc">${escHtml(t.description || '')}</div>
    </div>`).join('') : '';

  const techsHtml = techniques.techniques ? techniques.techniques.map(t => `
    <tr>
      <td><a href="https://attack.mitre.org/techniques/${escHtml(t.id)}/" target="_blank" rel="noopener">${escHtml(t.id)}</a></td>
      <td>${escHtml(t.name)}</td>
      <td>${escHtml(t.tactic)}</td>
      <td style="font-size:0.75rem">${escHtml(t.description || '')}</td>
      <td style="font-size:0.7rem">${t.iec62443SRs ? t.iec62443SRs.join(', ') : ''}</td>
    </tr>`).join('') : '';

  const incidentsHtml = idx.keyIncidentMappings ? idx.keyIncidentMappings.map(i => `
    <tr>
      <td>${escHtml(i.incident)}</td>
      <td>${i.techniques ? i.techniques.map(t => `<span class="tag">${escHtml(t)}</span>`).join(' ') : ''}</td>
    </tr>`).join('') : '';

  return `
    <div class="disclaimer">MITRE ATT&amp;CK for ICS is publicly available at attack.mitre.org/matrices/ics</div>
    <h2>MITRE ATT&amp;CK for ICS</h2>
    <div class="detail-body" style="margin-bottom:1rem">${escHtml(idx.overview || '')}</div>
    <h2>Tactics (${idx.tactics ? idx.tactics.length : 0})</h2>
    <div class="three-col">${tacticsHtml}</div>
    ${incidentsHtml ? `
    <h2>Known Incident Mappings</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Incident</th><th>Techniques Used</th></tr></thead>
      <tbody>${incidentsHtml}</tbody>
    </table></div>` : ''}
    <h2>Techniques (${techniques.techniques ? techniques.techniques.length : 0})</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Description</th><th>IEC 62443 SRs</th></tr></thead>
      <tbody>${techsHtml}</tbody>
    </table></div>
  `;
}

// ─── ARCHITECTURE ─────────────────────────────────────────────────────────────
async function renderArchitecture(sub) {
  const tabs = [
    { id: 'purdue',  label: 'Purdue Model' },
    { id: 'zones',   label: 'Zones & Conduits' },
    { id: 'assets',  label: 'Asset Types' },
  ];
  const active = sub || 'purdue';

  const tabsHtml = `<div class="tabs">${tabs.map(t =>
    `<button class="tab-btn${t.id === active ? ' active' : ''}" onclick="navigate('architecture','${t.id}')">${t.label}</button>`
  ).join('')}</div>`;

  let content = '';
  if (active === 'purdue') content = await renderPurdue();
  else if (active === 'zones') content = await renderZones();
  else if (active === 'assets') content = await renderAssets();

  setMain(`
    <div class="page-title">OT Architecture Reference</div>
    <div class="page-sub">Purdue Model · Zones &amp; Conduits · Asset Type Profiles</div>
    ${tabsHtml}
    ${content}
  `);
}

async function renderPurdue() {
  const data = await load('architecture/purdue-model.json');
  if (!data.levels) return '<div class="empty-state">No data</div>';

  const levelsHtml = data.levels.map(l => `
    <div class="card" style="border-left:3px solid var(--accent2)">
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
        <span class="badge badge-sl2">Level ${escHtml(String(l.level))}</span>
        <span class="card-title" style="margin:0">${escHtml(l.name)}</span>
        ${l.securityCharacteristics?.targetSL ? slBadge(l.securityCharacteristics.targetSL) : ''}
      </div>
      <div class="card-desc">${escHtml(l.description || '')}</div>
      ${l.typicalComponents ? `
        <div style="margin-top:0.75rem">
          <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.35rem">Typical Components</div>
          ${tagList(l.typicalComponents.map(c => typeof c === 'string' ? c : c.name || JSON.stringify(c)))}
        </div>` : ''}
      ${l.securityCharacteristics ? `
        <div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:0.75rem;color:var(--text-muted)">
          <div><strong>Primary Controls:</strong> ${escHtml((l.securityCharacteristics.primaryControls || []).join(', '))}</div>
          <div style="margin-top:0.25rem"><strong>Key Vulnerabilities:</strong> ${escHtml(Array.isArray(l.securityCharacteristics.vulnerabilities) ? l.securityCharacteristics.vulnerabilities.join(', ') : (l.securityCharacteristics.vulnerabilities || ''))}</div>
        </div>` : ''}
    </div>`).join('');

  return `
    <h2>Purdue Model — Levels 0–5</h2>
    <div class="card" style="margin-bottom:1rem;background:rgba(56,189,248,0.05);border-color:var(--accent)">
      <div class="card-title">IDMZ — Industrial Demilitarized Zone (Level 3.5)</div>
      <div class="card-desc">The IDMZ is the critical architectural element separating OT (Levels 0–3) from IT (Level 4+). Implemented as a two-firewall DMZ with no direct Layer 3 routing between OT and IT zones. All traffic flows through proxy/intermediary services in the IDMZ buffer.</div>
    </div>
    <div class="two-col">${levelsHtml}</div>
  `;
}

async function renderZones() {
  const data = await load('architecture/zones-conduits.json');

  const zonesHtml = data.referenceZones ? data.referenceZones.map(z => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
        <span class="badge badge-sl${z.targetSL}">${escHtml(z.id)}</span>
        ${slBadge(z.targetSL)} ${slDots(z.targetSL)}
        <span class="card-title" style="margin:0">${escHtml(z.name)}</span>
      </div>
      <div class="card-desc">${escHtml(z.description || '')}</div>
      <div class="card-tags">
        ${z.nacsa ? z.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('') : ''}
        ${z.purdueLevel !== undefined ? `<span class="tag">Purdue L${escHtml(String(z.purdueLevel))}</span>` : ''}
      </div>
    </div>`).join('') : '';

  const conduitsHtml = data.referenceConduits ? data.referenceConduits.map(c => `
    <div class="card">
      <div class="card-title">${escHtml(c.id)} — ${escHtml(c.name)}</div>
      <div class="card-sub">${escHtml(c.from)} → ${escHtml(c.to)} · Min SL: ${slBadge(c.slRequired)}</div>
      <div class="card-desc">${escHtml(c.description || '')}</div>
      ${c.permittedFlows ? `<div style="margin-top:0.5rem"><span style="font-size:0.7rem;color:var(--success)">✓ Permitted:</span> ${tagList(c.permittedFlows)}</div>` : ''}
      ${c.prohibitedFlows ? `<div style="margin-top:0.35rem"><span style="font-size:0.7rem;color:var(--danger)">✗ Prohibited:</span> ${tagList(c.prohibitedFlows)}</div>` : ''}
    </div>`).join('') : '';

  return `
    <h2>Reference Zones</h2>
    <div class="two-col">${zonesHtml}</div>
    <h2 style="margin-top:1.5rem">Reference Conduits</h2>
    <div class="two-col">${conduitsHtml}</div>
  `;
}

async function renderAssets() {
  const data = await load('architecture/asset-types.json');
  if (!data.assetTypes) return '<div class="empty-state">No data</div>';

  const assetHtml = data.assetTypes.map(a => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
        <span class="badge badge-sl2">${escHtml(a.id)}</span>
        <span class="card-title" style="margin:0">${escHtml(a.name)}</span>
      </div>
      <div class="card-desc">${escHtml(a.description || '')}</div>
      ${a.vendors ? `<div style="margin-top:0.5rem"><span style="font-size:0.7rem;color:var(--text-muted)">Vendors:</span> ${tagList(a.vendors)}</div>` : ''}
      ${a.protocols ? `<div style="margin-top:0.35rem"><span style="font-size:0.7rem;color:var(--text-muted)">Protocols:</span> ${tagList(a.protocols)}</div>` : ''}
      ${a.securityProfile ? `
        <div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:0.75rem">
          <div style="color:${a.securityProfile.vulnerabilityRisk === 'Very High' || a.securityProfile.vulnerabilityRisk === 'High' ? 'var(--danger)' : 'var(--text-muted)'}">
            Risk: ${escHtml(a.securityProfile.vulnerabilityRisk || '')}
          </div>
          ${a.securityProfile.compensatingControls ? `<div style="color:var(--text-muted);margin-top:0.25rem">Controls: ${escHtml(a.securityProfile.compensatingControls.join(', '))}</div>` : ''}
        </div>` : ''}
    </div>`).join('');

  return `
    <h2>OT Asset Type Profiles</h2>
    <div class="page-sub">Security profiles for each OT asset category — authentication capabilities, patching, compensating controls.</div>
    <div class="three-col">${assetHtml}</div>
  `;
}

// ─── REQUIREMENTS ─────────────────────────────────────────────────────────────
async function renderRequirements(sub) {
  const index = await load('requirements/index.json');
  const domains = index.domains || [];

  // If sub is a specific domain, show detail
  if (sub && domains.find(d => d.id === sub)) {
    return renderDomainDetail(sub, domains);
  }

  // Overview
  const domainHtml = domains.map(d => `
    <div class="card card-link" onclick="navigate('requirements','${d.id}')">
      <div class="card-title">${escHtml(d.name)}</div>
      <div class="card-sub">${escHtml(d.id)}</div>
      <div class="card-desc">${escHtml(d.description || '')}</div>
      <div class="card-tags">
        ${(d.primaryFRs || d.primaryFR || []).map(f => `<span class="badge badge-sl2">${escHtml(f)}</span>`).join('')}
        ${(d.nacsa || []).map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('')}
      </div>
    </div>`).join('');

  setMain(`
    <div class="page-title">Security Requirements by Domain</div>
    <div class="page-sub">${domains.length} domains · IEC 62443-3-3 System Requirements · NACSA Act 854 obligations</div>
    <div class="two-col">${domainHtml}</div>
  `);
}

async function renderDomainDetail(domainId, domains) {
  const domain = domains.find(d => d.id === domainId);
  const filePath = domain?.file || `requirements/by-domain/${domainId}.json`;
  const data = await load(filePath);
  const reqs = data.requirements || [];

  const backLink = `<button class="back-link" onclick="navigate('requirements',null)">← All Domains</button>`;

  const reqsHtml = reqs.map(r => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;flex-wrap:wrap">
        <span class="badge badge-sl2">${escHtml(r.id)}</span>
        <span class="card-title" style="margin:0">${escHtml(r.name)}</span>
      </div>
      ${r.description ? `<div class="card-desc">${escHtml(r.description)}</div>` : ''}

      ${r.legal ? `
        <div class="detail-section" style="margin-top:0.75rem">
          <h3>Legal Basis</h3>
          <div class="detail-body">${escHtml(r.legal.summary || '')}</div>
          <div class="card-tags" style="margin-top:0.35rem">
            ${Array.isArray(r.legal.basis) ? r.legal.basis.map(s => `<span class="badge badge-sl2" style="margin:1px">${escHtml(s)}</span>`).join('') : ''}
          </div>
          ${r.legal.owner ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.35rem"><strong>Owner:</strong> ${escHtml(r.legal.owner)}</div>` : ''}
        </div>` : ''}

      ${r.technical ? `
        <div class="detail-section">
          <h3>Technical Implementation</h3>
          <div class="detail-body">${escHtml(r.technical.summary || r.technical.requirement || '')}</div>
          ${Array.isArray(r.technical.actions) ? `<ul style="margin-top:0.5rem;padding-left:1.25rem;font-size:0.8rem;color:var(--text-muted)">${r.technical.actions.map(a => `<li style="margin-bottom:0.2rem">${escHtml(a)}</li>`).join('')}</ul>` : ''}
        </div>` : ''}

      ${r.governance ? `
        <div class="detail-section">
          <h3>Governance</h3>
          <div class="detail-body">${escHtml(r.governance.summary || '')}</div>
          ${Array.isArray(r.governance.actions) ? `<ul style="margin-top:0.5rem;padding-left:1.25rem;font-size:0.8rem;color:var(--text-muted)">${r.governance.actions.map(a => `<li style="margin-bottom:0.2rem">${escHtml(a)}</li>`).join('')}</ul>` : ''}
        </div>` : ''}

      ${r.slMapping ? `
        <div class="detail-section">
          <h3>SL Mapping</h3>
          <div class="two-col">
            ${Object.entries(r.slMapping).map(([sl, desc]) => `
              <div>${slBadge(sl.replace('sl',''))} <span style="font-size:0.8rem">${escHtml(desc)}</span></div>`).join('')}
          </div>
        </div>` : ''}

      ${r.evidenceItems ? `
        <div class="detail-section">
          <h3>Audit Evidence Required</h3>
          <ul style="font-size:0.8rem;color:var(--text-muted);padding-left:1.25rem">${r.evidenceItems.map(e => `<li>${escHtml(e)}</li>`).join('')}</ul>
        </div>` : ''}

      <div class="card-tags" style="margin-top:0.5rem">
        ${(r.nacsa || (r.legal && r.legal.nacsa) || []).map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('')}
        ${(r.mitreAttackIcs || []).map(m => `<span class="tag" style="color:var(--danger)">${escHtml(m)}</span>`).join('')}
      </div>
    </div>`).join('');

  // Special: NACSA notification timeline if present
  const notifHtml = data.nacsaNotificationSummary ? `
    <div class="card" style="border-color:var(--warning);margin-bottom:1rem">
      <div class="card-title" style="color:var(--warning)">NACSA Notification Timeline (s26)</div>
      <div class="attack-chain" style="margin-top:0.75rem">
        ${data.nacsaNotificationSummary.timeline ? data.nacsaNotificationSummary.timeline.map(t => `
          <div class="attack-step">
            <strong style="color:var(--warning)">${escHtml(t.window)}:</strong> ${escHtml(t.requirement)}
            ${t.content ? `<div style="margin-top:0.35rem;font-size:0.75rem">${escHtml(t.content)}</div>` : ''}
          </div>`).join('') : ''}
      </div>
    </div>` : '';

  setMain(`
    ${backLink}
    <div class="page-title">${escHtml(domain?.name || domainId)}</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>
    ${notifHtml}
    ${reqsHtml}
  `);
}

// ─── CONTROLS ─────────────────────────────────────────────────────────────────
async function renderControls(sub) {
  const [controls, domains, artifactInventory, evidenceIndex] = await Promise.all([
    load('controls/library.json'),
    load('controls/domains.json'),
    load('artifacts/inventory.json').catch(() => []),
    load('evidence/index.json').catch(() => ({})),
  ]);

  const allControls = Array.isArray(controls) ? controls : [];

  if (sub) {
    const ctrl = allControls.find(c => c.slug === sub);
    if (ctrl) return renderControlDetail(ctrl, allControls, artifactInventory, evidenceIndex);
  }

  // Group by domain
  const domainMap = {};
  if (domains.domains) domains.domains.forEach(d => { domainMap[d.id] = d; });

  const grouped = {};
  allControls.forEach(c => {
    const d = c.domain || 'other';
    if (!grouped[d]) grouped[d] = [];
    grouped[d].push(c);
  });

  const html = Object.entries(grouped).map(([domId, ctrls]) => `
    <h2 style="margin-top:1.25rem">${escHtml(domainMap[domId]?.name || domId)}</h2>
    <div class="two-col">${ctrls.map(c => `
      <div class="card card-link" onclick="navigate('controls','${c.slug}')">
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.35rem;flex-wrap:wrap">
          ${typeBadge(c.type)}
          ${slBadge(c.slMin)} min
        </div>
        <div class="card-title">${escHtml(c.name)}</div>
        <div class="card-desc">${escHtml(c.description || '')}</div>
        <div class="card-tags">
          ${c.nacsa ? c.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('') : ''}
          ${c.nistCsf ? c.nistCsf.slice(0,3).map(n => `<span class="tag">${escHtml(n)}</span>`).join('') : ''}
        </div>
      </div>`).join('')}
    </div>`).join('');

  setMain(`
    <div class="page-title">Controls Library</div>
    <div class="page-sub">${allControls.length} controls · IEC 62443 · NACSA Act 854 · NIST CSF 2.0 mapped</div>
    ${html}
  `);
}

function renderControlDetail(ctrl, allControls, artifactInventory, evidenceIndex) {
  const backHtml = `<button class="back-link" onclick="navigate('controls',null)">← All Controls</button>`;

  const maturityHtml = ctrl.maturity ? Object.entries(ctrl.maturity).map(([lvl, desc]) => `
    <div class="card">
      <div class="card-title" style="text-transform:capitalize">${escHtml(lvl)}</div>
      <div class="card-desc">${escHtml(desc)}</div>
    </div>`).join('') : '';

  // Audit Package
  const controlSlug = ctrl.slug;
  const domain = ctrl.domain;
  const linkedArtifacts = (Array.isArray(artifactInventory) ? artifactInventory : [])
    .filter(a => Array.isArray(a.controlSlugs) && a.controlSlugs.includes(controlSlug))
    .sort((a, b) => (b.mandatory ? 1 : 0) - (a.mandatory ? 1 : 0));

  const linkedArtifactIds = new Set(linkedArtifacts.map(a => a.id));
  const evidenceByDomain = (evidenceIndex || {}).evidenceByDomain || {};
  const domainEvidence = evidenceByDomain[domain];
  const linkedEvidence = [];
  if (domainEvidence && domainEvidence.evidenceItems) {
    domainEvidence.evidenceItems.forEach(item => {
      const itemArtifacts = item.artifactSlugs || [];
      if (!itemArtifacts.length || itemArtifacts.some(id => linkedArtifactIds.has(id))) {
        linkedEvidence.push(item);
      }
    });
  }

  const artifactsHtml = linkedArtifacts.length ? linkedArtifacts.map(a => `
    <div class="artifact-link-card">
      <div class="artifact-link-header">
        <span class="artifact-link-name">${escHtml(a.name)}</span>
        ${a.mandatory ? '<span class="badge badge-malaysia">Mandatory</span>' : '<span class="badge">Optional</span>'}
      </div>
      <div class="artifact-link-meta">${escHtml(a.category || '')} · ${escHtml(a.id)}</div>
      ${a.description ? `<div class="artifact-link-desc">${escHtml(a.description)}</div>` : ''}
      ${a.format ? `<div class="artifact-link-format"><strong>Format:</strong> ${escHtml(a.format)}</div>` : ''}
    </div>`).join('') : '<p class="text-muted">No artifacts linked to this control.</p>';

  const evidenceHtml = linkedEvidence.length ? linkedEvidence.map(ev => `
    <div class="accordion-item">
      <div class="accordion-header" data-accordion>
        <span>
          ${ev.mandatory ? '<span class="badge badge-malaysia" style="margin-right:0.35rem">Mandatory</span>' : '<span class="badge" style="margin-right:0.35rem">Optional</span>'}
          ${escHtml(ev.name)}
        </span>
        <span class="accordion-arrow">&#9654;</span>
      </div>
      <div class="accordion-body">
        ${ev.howToVerify ? `<div class="evidence-how-to-verify"><strong>How to verify:</strong> ${escHtml(ev.howToVerify)}</div>` : ''}
        ${ev.whatGoodLooksLike && ev.whatGoodLooksLike.length ? `
          <div class="evidence-good">
            <strong>What good looks like:</strong>
            <ul>${ev.whatGoodLooksLike.map(w => `<li>${escHtml(w)}</li>`).join('')}</ul>
          </div>` : ''}
        ${ev.commonGaps && ev.commonGaps.length ? `
          <div class="evidence-gap">
            <strong>Common gaps:</strong>
            <ul>${ev.commonGaps.map(g => `<li>${escHtml(g)}</li>`).join('')}</ul>
          </div>` : ''}
      </div>
    </div>`).join('') : '<p class="text-muted">No evidence items linked to this control.</p>';

  const auditPackageHTML = `
    <div class="audit-package" style="margin-top:1.5rem">
      <h2>Audit Package</h2>
      <div class="audit-package-section">
        <h3>Linked Artifacts <span class="badge">${linkedArtifacts.length}</span></h3>
        ${artifactsHtml}
      </div>
      <div class="audit-package-section" style="margin-top:1rem">
        <h3>Evidence Checklist <span class="badge">${linkedEvidence.length}</span></h3>
        ${evidenceHtml}
      </div>
    </div>`;

  setMain(`
    ${backHtml}
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap">
      ${typeBadge(ctrl.type)}
      ${slBadge(ctrl.slMin)} minimum
      <span class="card-title" style="margin:0;font-size:1.1rem">${escHtml(ctrl.name)}</span>
    </div>
    <div class="page-sub">${escHtml(ctrl.domain || '')}</div>

    <div class="card" style="margin-bottom:1rem">
      <div class="detail-body">${escHtml(ctrl.description || '')}</div>
    </div>

    ${ctrl.keyActivities ? `
      <h2>Key Activities</h2>
      <div class="attack-chain">${ctrl.keyActivities.map(a => `<div class="attack-step">${escHtml(a)}</div>`).join('')}</div>` : ''}

    ${ctrl.maturity ? `<h2 style="margin-top:1rem">Maturity Levels</h2><div class="three-col">${maturityHtml}</div>` : ''}

    <div class="two-col" style="margin-top:1rem">
      ${ctrl.iec62443SRs ? `
        <div class="card">
          <h3>IEC 62443 SRs</h3>
          ${tagList(ctrl.iec62443SRs)}
        </div>` : ''}
      ${ctrl.nacsa ? `
        <div class="card">
          <h3>NACSA Act 854</h3>
          ${ctrl.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span> `).join('')}
        </div>` : ''}
      ${ctrl.nistCsf ? `
        <div class="card">
          <h3>NIST CSF 2.0</h3>
          ${tagList(ctrl.nistCsf)}
        </div>` : ''}
      ${ctrl.mitreAttackIcs ? `
        <div class="card">
          <h3>MITRE ATT&amp;CK for ICS</h3>
          ${ctrl.mitreAttackIcs.map(m => `<span class="tag" style="color:var(--danger)">${escHtml(m)}</span> `).join('')}
        </div>` : ''}
    </div>

    ${auditPackageHTML}
  `);
}

// ─── EVIDENCE ─────────────────────────────────────────────────────────────────
async function renderEvidence(sub) {
  const data = await load('evidence/index.json');
  const byDomain = data.evidenceByDomain || {};

  const domains = Object.keys(byDomain);
  const active = sub && domains.includes(sub) ? sub : domains[0];

  const domainLabels = {
    'network-segmentation': 'Network Segmentation', 'identity-access': 'Identity & Access',
    'remote-access': 'Remote Access', 'patch-vulnerability': 'Patch & Vulnerability',
    'monitoring-logging': 'Monitoring & Logging', 'incident-response': 'Incident Response',
    'asset-management': 'Asset Management', 'safety-system': 'Safety Systems',
    'configuration-management': 'Configuration Mgmt', 'supply-chain': 'Supply Chain',
    'backup-recovery': 'Backup & Recovery', 'physical-security': 'Physical Security',
    'data-protection': 'Data Protection',
  };
  const tabsHtml = `<div class="tabs" style="flex-wrap:wrap">${domains.map(d =>
    `<button class="tab-btn${d === active ? ' active' : ''}" onclick="navigate('evidence','${d}')">${escHtml(domainLabels[d] || d)}</button>`
  ).join('')}</div>`;

  const domainData = byDomain[active] || {};
  const items = domainData.evidenceItems || [];

  const itemsHtml = items.map(item => `
    <div class="card">
      <div style="display:flex;align-items:flex-start;gap:0.5rem;margin-bottom:0.5rem;flex-wrap:wrap">
        <span class="badge badge-sl2">${escHtml(item.id)}</span>
        <span class="card-title" style="margin:0;flex:1">${escHtml(item.name)}</span>
        ${item.mandatory ? '<span class="badge badge-critical" style="flex-shrink:0">Mandatory</span>' : '<span class="badge badge-minor" style="flex-shrink:0">Advisory</span>'}
      </div>
      <div class="two-col">
        <div class="detail-section">
          <h3>What Good Looks Like</h3>
          <ul style="font-size:0.8rem;color:var(--text);padding-left:1.25rem">${(item.whatGoodLooksLike || []).map(w => `<li style="margin-bottom:0.25rem">${escHtml(w)}</li>`).join('')}</ul>
        </div>
        <div class="detail-section">
          <h3>Common Gaps</h3>
          <ul style="font-size:0.8rem;color:var(--danger);padding-left:1.25rem">${(item.commonGaps || []).map(g => `<li style="margin-bottom:0.25rem">${escHtml(g)}</li>`).join('')}</ul>
        </div>
      </div>
      ${item.howToVerify ? `
        <div class="detail-section" style="background:rgba(52,211,153,0.05);border-radius:6px;padding:0.5rem 0.75rem;margin-top:0.5rem">
          <h3 style="color:var(--success)">How to Verify</h3>
          <div class="detail-body">${escHtml(item.howToVerify)}</div>
        </div>` : ''}
    </div>`).join('');

  setMain(`
    <div class="page-title">Audit Evidence</div>
    <div class="page-sub">${escHtml(data.auditorNote || '')}</div>
    <div class="disclaimer"><strong>NACSA s23 Auditors:</strong> Evidence should demonstrate both policy (documents exist) and operational effectiveness (controls are working). Passive evidence is more reliable than documentation alone.</div>
    ${tabsHtml}
    <div style="margin-bottom:1rem;font-size:0.85rem;color:var(--text-muted)">${escHtml(domainData.description || '')}</div>
    ${itemsHtml || '<div class="empty-state"><div class="empty-state-text">No evidence items for this domain yet.</div></div>'}
  `);
}

// ─── THREATS ─────────────────────────────────────────────────────────────────
async function renderThreats(sub) {
  const tabs = [
    { id: 'incidents', label: 'Known Incidents' },
    { id: 'actors',    label: 'Threat Actors' },
  ];
  const active = sub || 'incidents';

  const tabsHtml = `<div class="tabs">${tabs.map(t =>
    `<button class="tab-btn${t.id === active ? ' active' : ''}" onclick="navigate('threats','${t.id}')">${t.label}</button>`
  ).join('')}</div>`;

  let content = '';
  if (active === 'incidents') content = await renderIncidents();
  else content = await renderActors();

  setMain(`
    <div class="page-title">OT Threat Intelligence</div>
    <div class="page-sub">Real-world incidents · Threat actor profiles · MITRE ATT&amp;CK for ICS mapped</div>
    ${tabsHtml}
    ${content}
  `);
}

async function renderIncidents() {
  const data = await load('threats/known-incidents.json');
  const incidents = data.incidents || [];

  return incidents.map(inc => `
    <div class="card incident-card" style="margin-bottom:1rem">
      <div style="display:flex;align-items:flex-start;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.75rem">
        <div>
          <div class="card-title" style="font-size:1rem">${escHtml(inc.name)}</div>
          <div class="card-sub">${escHtml(inc.year || '')} · ${escHtml(inc.sector || '')} · ${escHtml(inc.country || '')}</div>
        </div>
        <div style="margin-left:auto;display:flex;gap:0.35rem;flex-wrap:wrap">
          <span class="badge badge-critical">${escHtml(inc.impact || 'Critical')}</span>
        </div>
      </div>

      <div class="detail-body" style="margin-bottom:0.75rem">${escHtml(inc.description || '')}</div>

      ${inc.physicalConsequence ? `
        <div class="card" style="background:rgba(239,68,68,0.08);border-color:rgba(239,68,68,0.3);margin-bottom:0.75rem">
          <div style="font-size:0.75rem;font-weight:700;color:var(--danger);text-transform:uppercase;margin-bottom:0.25rem">Physical Consequence</div>
          <div style="font-size:0.85rem">${escHtml(inc.physicalConsequence)}</div>
        </div>` : ''}

      ${inc.attackChain ? `
        <h3 style="margin-bottom:0.5rem">Attack Chain</h3>
        <div class="attack-chain" style="margin-bottom:0.75rem">
          ${inc.attackChain.map(step => `
            <div class="attack-step">
              <strong>${escHtml(step.stage)}:</strong>
              ${step.technique ? `<span class="tag" style="color:var(--danger);margin:0 0.35rem">${escHtml(step.technique)}</span>` : ''}
              ${escHtml(step.description || '')}
            </div>`).join('')}
        </div>` : ''}

      ${inc.preventiveControls ? `
        <h3 style="margin-bottom:0.5rem">Preventive Controls</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:0.5rem;margin-bottom:0.75rem">
          ${inc.preventiveControls.map(pc => `
            <div style="background:rgba(52,211,153,0.05);border:1px solid rgba(52,211,153,0.2);border-radius:6px;padding:0.5rem 0.75rem;font-size:0.8rem">
              <strong style="color:var(--success)">${escHtml(pc.control || pc)}</strong>
              ${pc.howItHelps ? `<div style="color:var(--text-muted);margin-top:0.25rem">${escHtml(pc.howItHelps)}</div>` : ''}
            </div>`).join('')}
        </div>` : ''}

      ${inc.keyLesson ? `
        <div style="background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.3);border-radius:6px;padding:0.5rem 0.75rem;font-size:0.85rem">
          <strong style="color:var(--warning)">Key Lesson:</strong> ${escHtml(inc.keyLesson)}
        </div>` : ''}

      ${inc.iec62443SRs ? `<div class="card-tags" style="margin-top:0.75rem">${inc.iec62443SRs.map(s => `<span class="badge badge-sl2">${escHtml(s)}</span>`).join('')}</div>` : ''}
    </div>`).join('');
}

async function renderActors() {
  const data = await load('threats/threat-actors.json');
  const actors = data.threatActors || [];

  return actors.map(a => {
    const slClass = a.sophisticationSL ? `sl-row-${a.sophisticationSL}` : '';
    return `
    <div class="card" style="margin-bottom:0.75rem;${a.sophisticationSL === 4 ? 'border-left:3px solid var(--sl4)' : a.sophisticationSL === 3 ? 'border-left:3px solid var(--sl3)' : 'border-left:3px solid var(--sl2)'}">
      <div style="display:flex;align-items:flex-start;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.5rem">
        <div>
          <div class="card-title">${escHtml(a.name)}</div>
          <div class="card-sub">${escHtml(a.attribution || '')} · ${escHtml(a.motivation || '')}</div>
        </div>
        <div style="margin-left:auto;display:flex;gap:0.35rem;flex-wrap:wrap">
          ${slBadge(a.sophisticationSL)} sophistication
          ${a.malaysiaRelevance ? `<span class="badge badge-malaysia">MY: ${escHtml(a.malaysiaRelevance)}</span>` : ''}
        </div>
      </div>
      <div class="card-desc">${escHtml(a.description || '')}</div>
      <div class="two-col" style="margin-top:0.75rem">
        ${a.targetedSectors ? `<div><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem">Targeted Sectors</div>${tagList(a.targetedSectors)}</div>` : ''}
        ${a.knownTactics ? `<div><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem">Known Tactics</div>${tagList(a.knownTactics)}</div>` : ''}
      </div>
      ${a.defensiveFocus ? `<div style="margin-top:0.5rem;font-size:0.8rem;color:var(--success)"><strong>Defensive Focus:</strong> ${escHtml(a.defensiveFocus)}</div>` : ''}
    </div>`;
  }).join('');
}

// ─── SECTORS ─────────────────────────────────────────────────────────────────
async function renderSectors(sub) {
  const data = await load('sectors/index.json');
  const sectors = data.sectors || [];

  if (sub) {
    const sector = sectors.find(s => s.id === sub);
    if (sector) return renderSectorDetail(sector);
  }

  const html = sectors.map(s => `
    <div class="card card-link" onclick="navigate('sectors','${s.id}')">
      <div class="card-title">${escHtml(s.name)}</div>
      <div class="card-sub">NACSA Sector: ${escHtml(s.nacsaSectorNumber || '')} · Lead: ${escHtml(s.nacsaSectorLead || '')}</div>
      <div class="card-desc">${escHtml(s.description || '')}</div>
      <div class="card-tags">
        <span class="badge badge-malaysia">Act 854</span>
        ${s.defaultSLTarget ? slBadge(s.defaultSLTarget) : ''}
        ${s.keyOtRisks ? s.keyOtRisks.slice(0,2).map(r => `<span class="tag">${escHtml(r)}</span>`).join('') : ''}
      </div>
    </div>`).join('');

  setMain(`
    <div class="page-title">OT Sectors &amp; Malaysia NCII</div>
    <div class="page-sub">Sector-specific OT risks, NACSA obligations, and SL targeting by zone.</div>
    <div class="two-col">${html}</div>
  `);
}

function renderSectorDetail(sector) {
  const backLink = `<button class="back-link" onclick="navigate('sectors',null)">← All Sectors</button>`;

  const slZoneHtml = sector.targetSLByZone ? Object.entries(sector.targetSLByZone).map(([zone, sl]) => `
    <tr><td>${escHtml(zone)}</td><td>${slBadge(sl)} ${slDots(sl)}</td></tr>`).join('') : '';

  setMain(`
    ${backLink}
    <div class="page-title">${escHtml(sector.name)}</div>
    <div class="page-sub">NACSA Sector: ${escHtml(sector.nacsaSectorNumber || '')} · Lead Agency: ${escHtml(sector.nacsaSectorLead || '')}</div>

    <div class="two-col">
      <div class="card">
        <h3>OT Environments</h3>
        ${tagList(sector.otEnvironments || [])}
      </div>
      <div class="card">
        <h3>Primary Standards</h3>
        ${tagList(sector.primaryStandards || [])}
      </div>
    </div>

    <div class="two-col" style="margin-top:0.75rem">
      <div class="card">
        <h3>Key OT Risks</h3>
        <ul style="padding-left:1.25rem;font-size:0.8rem">${(sector.keyOtRisks || []).map(r => `<li style="margin-bottom:0.25rem">${escHtml(r)}</li>`).join('')}</ul>
      </div>
      <div class="card">
        <h3>SL-T by Zone</h3>
        <div class="table-wrap" style="margin:0"><table>
          <thead><tr><th>Zone</th><th>SL Target</th></tr></thead>
          <tbody>${slZoneHtml}</tbody>
        </table></div>
      </div>
    </div>

    ${sector.nacsaCopReference ? `
      <div class="card" style="margin-top:0.75rem;border-color:var(--accent)">
        <h3>NACSA Code of Practice Reference</h3>
        <div class="detail-body">${escHtml(sector.nacsaCopReference)}</div>
      </div>` : ''}

    ${sector.regulatoryOverlap ? `
      <h2 style="margin-top:1rem">Regulatory Overlap</h2>
      <div class="attack-chain">${Array.isArray(sector.regulatoryOverlap)
        ? sector.regulatoryOverlap.map(r => `<div class="attack-step">${escHtml(r)}</div>`).join('')
        : `<div class="attack-step">${escHtml(String(sector.regulatoryOverlap))}</div>`}</div>` : ''}
  `);
}

// ─── CROSS-REFERENCES ─────────────────────────────────────────────────────────
async function renderCrossRef(sub) {
  const tabs = [
    { id: 'nacsa',   label: 'IEC 62443 → NACSA Act 854' },
    { id: 'nist',    label: 'IEC 62443 → NIST CSF 2.0' },
    { id: 'sector',  label: 'Sector → NACSA COP' },
  ];
  const active = sub || 'nacsa';

  const tabsHtml = `<div class="tabs">${tabs.map(t =>
    `<button class="tab-btn${t.id === active ? ' active' : ''}" onclick="navigate('cross-ref','${t.id}')">${t.label}</button>`
  ).join('')}</div>`;

  let content = '';
  if (active === 'nacsa')  content = await renderCrossNacsa();
  else if (active === 'nist')   content = await renderCrossNist();
  else if (active === 'sector') content = await renderCrossSector();

  setMain(`
    <div class="page-title">Cross-References</div>
    <div class="page-sub">Mappings between IEC 62443, NACSA Act 854, NIST CSF 2.0, and sector codes of practice.</div>
    <div class="disclaimer">Cross-reference mappings are constructed-indicative. Verify against official standard texts before use in formal assessments.</div>
    ${tabsHtml}
    ${content}
  `);
}

async function renderCrossNacsa() {
  const data = await load('cross-references/iec62443-to-nacsa.json');
  const mappings = data.mappings || [];

  const html = mappings.map(m => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;flex-wrap:wrap">
        <span class="badge badge-malaysia">${escHtml(m.nacsaSection)}</span>
        <span class="card-title" style="margin:0">${escHtml(m.nacsaTitle || m.nacsaObligation || '')}</span>
      </div>
      <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.5rem;font-style:italic">${escHtml(m.nacsaObligation || '')}</div>
      <div class="card-desc">${escHtml(m.iec62443Alignment || m.description || '')}</div>
      <div style="margin-top:0.75rem">
        <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.35rem">Related IEC 62443 SRs</div>
        ${tagList(m.relevantSRs || m.iec62443SRs || [])}
      </div>
      ${(m.relevantDomains || m.domains) ? `<div style="margin-top:0.35rem">${tagList(m.relevantDomains || m.domains)}</div>` : ''}
      ${m.notes ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem;border-top:1px solid var(--border);padding-top:0.5rem">${escHtml(m.notes)}</div>` : ''}
    </div>`).join('');

  const slMapping = data.slToNacsaMapping;
  const slHtml = slMapping ? `
    <h2 style="margin-top:1.5rem">Security Level → NACSA Obligation</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>SL</th><th>NACSA Minimum</th><th>Applicability</th></tr></thead>
      <tbody>${Array.isArray(slMapping)
        ? slMapping.map(m => `
        <tr><td>${slBadge(m.sl)}</td><td>${escHtml(m.nacsaMinimum || '')}</td><td>${escHtml(m.applicability || '')}</td></tr>`).join('')
        : Object.entries(slMapping).map(([sl, desc]) => `
        <tr><td>${slBadge(parseInt(sl.replace('sl', '')))}</td><td colspan="2">${escHtml(String(desc))}</td></tr>`).join('')}
      </tbody>
    </table></div>` : '';

  return `<div class="two-col">${html}</div>${slHtml}`;
}

async function renderCrossNist() {
  const data = await load('cross-references/iec62443-to-nist-csf.json');
  const mappings = data.mappings || [];

  const html = `
    <div class="table-wrap"><table>
      <thead><tr><th>IEC 62443 SR</th><th>SR Name</th><th>NIST CSF 2.0 Subcategories</th><th>Similarity</th></tr></thead>
      <tbody>${mappings.map(m => {
        const srId = m.iec62443SR || m.srId || '';
        const srName = m.srName || '';
        const csf = (m.nistCsfSubcategories || m.nistCsf || []).join(', ');
        const sim = m.similarity || '';
        const simNorm = sim.charAt(0).toUpperCase() + sim.slice(1).toLowerCase();
        return `
        <tr>
          <td><strong>${escHtml(srId)}</strong></td>
          <td>${escHtml(srName)}</td>
          <td style="font-size:0.75rem">${escHtml(csf)}</td>
          <td><span class="badge ${simNorm === 'High' ? 'badge-preventive' : simNorm === 'Medium' ? 'badge-corrective' : 'badge-minor'}">${escHtml(simNorm)}</span></td>
        </tr>`;}).join('')}
      </tbody>
    </table></div>
  `;

  return html;
}

async function renderCrossSector() {
  const data = await load('cross-references/sector-to-nacsa-cop.json');
  const mappings = data.sectorMappings || [];

  const html = mappings.map(m => `
    <div class="card">
      <div class="card-title">${escHtml(m.sector)}</div>
      <div class="card-sub">${escHtml(m.nacsaCopReference || '')}</div>
      ${m.otSpecificOverlays ? `
        <div style="margin-top:0.5rem">
          <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.35rem">OT-Specific Overlays</div>
          ${tagList(m.otSpecificOverlays)}
        </div>` : ''}
      <div class="card-tags" style="margin-top:0.5rem">
        ${m.iec62443SLRecommendation ? slBadge(m.iec62443SLRecommendation) : ''}
        <span class="badge badge-malaysia">Act 854</span>
      </div>
      ${m.regulatoryOverlap ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem">${escHtml(m.regulatoryOverlap)}</div>` : ''}
    </div>`).join('');

  return `<div class="two-col">${html}</div>`;
}

// ─── ARTIFACTS ────────────────────────────────────────────────────────────────
async function renderArtifacts(sub) {
  const data = await load('artifacts/inventory.json');
  const items = Array.isArray(data) ? data : [];

  if (sub) {
    const item = items.find(a => a.id === sub);
    if (item) {
      const backLink = `<button class="back-link" onclick="navigate('artifacts',null)">← All Artifacts</button>`;
      setMain(`
        ${backLink}
        <div class="page-title">${escHtml(item.name)}</div>
        <div class="page-sub">${escHtml(item.category || '')} · Format: ${escHtml(item.format || '')}</div>
        <div class="card">
          <div class="detail-body">${escHtml(item.description || '')}</div>
          <div class="card-tags" style="margin-top:1rem">
            ${item.mandatory ? '<span class="badge badge-critical">Mandatory</span>' : '<span class="badge badge-minor">Optional</span>'}
            ${item.sections ? item.sections.map(s => `<span class="badge badge-sl2">${escHtml(s)}</span>`).join('') : ''}
          </div>
        </div>
      `);
      return;
    }
  }

  const grouped = {};
  items.forEach(a => {
    const cat = a.category || 'other';
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(a);
  });

  const html = Object.entries(grouped).map(([cat, arts]) => `
    <h2 style="margin-top:1.25rem;text-transform:capitalize">${escHtml(cat)}</h2>
    <div class="two-col">${arts.map(a => `
      <div class="card card-link" onclick="navigate('artifacts','${a.id}')">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:0.5rem">
          <div class="card-title">${escHtml(a.name)}</div>
          ${a.mandatory ? '<span class="badge badge-critical" style="flex-shrink:0">Mandatory</span>' : ''}
        </div>
        <div class="card-desc">${escHtml(a.description || '')}</div>
        <div class="card-tags">${(a.sections || []).map(s => `<span class="badge badge-sl2">${escHtml(s)}</span>`).join('')}</div>
      </div>`).join('')}
    </div>`).join('');

  setMain(`
    <div class="page-title">OT Security Artifacts</div>
    <div class="page-sub">${items.filter(a=>a.mandatory).length} mandatory · ${items.length} total — documents and records required for audit readiness.</div>
    ${html}
  `);
}

// ─── SEARCH ───────────────────────────────────────────────────────────────────
async function renderSearch(query) {
  const q = (query || searchQuery || '').toLowerCase().trim();
  if (!q) {
    setMain(`<div class="empty-state"><div class="empty-state-text">Enter a search term above.</div></div>`);
    return;
  }

  // Load all searchable datasets
  const [reqs, controls, incidents, actors, sectors, srs, evidence] = await Promise.all([
    load('requirements/index.json').then(d => d.domains || []),
    load('controls/library.json').then(d => Array.isArray(d) ? d : []),
    load('threats/known-incidents.json').then(d => d.incidents || []),
    load('threats/threat-actors.json').then(d => d.threatActors || []),
    load('sectors/index.json').then(d => d.sectors || []),
    load('standards/iec62443/system-requirements.json').then(d => d.systemRequirements || []),
    load('evidence/index.json').then(d => {
      const items = [];
      Object.entries(d.evidenceByDomain || {}).forEach(([dom, dd]) => {
        (dd.evidenceItems || []).forEach(e => items.push({ ...e, domain: dom }));
      });
      return items;
    }),
  ]);

  const results = [];

  srs.forEach(sr => {
    if ([sr.id, sr.name, sr.description, sr.sl1, sr.sl2, sr.sl3, sr.sl4].some(f => String(f||'').toLowerCase().includes(q))) {
      results.push({ type: 'SR', title: `${sr.id} — ${sr.name}`, desc: sr.description || '', action: () => navigate('standards','iec-sr') });
    }
  });

  reqs.forEach(d => {
    if ([d.id, d.name, d.description].some(f => String(f||'').toLowerCase().includes(q))) {
      results.push({ type: 'Domain', title: d.name, desc: d.description || '', action: () => navigate('requirements', d.id) });
    }
  });

  controls.forEach(c => {
    if ([c.name, c.description, c.slug].some(f => String(f||'').toLowerCase().includes(q))) {
      results.push({ type: 'Control', title: c.name, desc: c.description || '', action: () => navigate('controls', c.slug) });
    }
  });

  incidents.forEach(inc => {
    if ([inc.name, inc.description, inc.keyLesson].some(f => String(f||'').toLowerCase().includes(q))) {
      results.push({ type: 'Incident', title: inc.name, desc: inc.description || '', action: () => navigate('threats','incidents') });
    }
  });

  actors.forEach(a => {
    if ([a.name, a.description, a.motivation].some(f => String(f||'').toLowerCase().includes(q))) {
      results.push({ type: 'Actor', title: a.name, desc: a.description || '', action: () => navigate('threats','actors') });
    }
  });

  sectors.forEach(s => {
    if ([s.name, s.description].some(f => String(f||'').toLowerCase().includes(q))) {
      results.push({ type: 'Sector', title: s.name, desc: s.description || '', action: () => navigate('sectors', s.id) });
    }
  });

  evidence.forEach(e => {
    if ([e.id, e.name, e.howToVerify].some(f => String(f||'').toLowerCase().includes(q))) {
      results.push({ type: 'Evidence', title: `${e.id} — ${e.name}`, desc: e.howToVerify || '', action: () => navigate('evidence', e.domain) });
    }
  });

  const typeBadgeMap = {
    'SR': 'badge-sl2', 'Domain': 'badge-sl3', 'Control': 'badge-preventive',
    'Incident': 'badge-critical', 'Actor': 'badge-significant', 'Sector': 'badge-malaysia', 'Evidence': 'badge-detective'
  };

  const html = results.length ? results.map((r, i) => `
    <div class="card card-link" onclick="window.__searchResult${i}()">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">
        <span class="badge ${typeBadgeMap[r.type] || 'badge-minor'}">${escHtml(r.type)}</span>
        <span class="card-title" style="margin:0">${escHtml(r.title)}</span>
      </div>
      <div class="card-desc">${escHtml(r.desc.substring(0, 120))}${r.desc.length > 120 ? '…' : ''}</div>
    </div>`).join('') : `<div class="empty-state"><div class="empty-state-text">No results for "${escHtml(q)}".</div></div>`;

  results.forEach((r, i) => { window[`__searchResult${i}`] = r.action; });

  setMain(`
    <div class="page-title">Search Results</div>
    <div class="page-sub">${results.length} result${results.length !== 1 ? 's' : ''} for "${escHtml(q)}"</div>
    ${html}
  `);
}

// ─── Search input handler ─────────────────────────────────────────────────────
function initSearch() {
  const input = document.getElementById('search-input');
  if (!input) return;
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const q = input.value.trim();
      searchQuery = q;
      if (q.length >= 2) {
        history.pushState(null, '', `#search/${encodeURIComponent(q)}`);
        route();
      }
    }, 300);
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { input.value = ''; searchQuery = ''; navigate('overview'); }
  });
}

// ─── FRAMEWORK MAPPING ───────────────────────────────────────────────────────
async function renderFramework(sub) {
  const tabs = [
    { id: 'matrix',   label: 'FR → NACSA × CSF Matrix' },
    { id: 'flow',     label: 'How Standards Connect' },
    { id: 'mitre',    label: 'MITRE → Controls' },
  ];
  const active = sub || 'matrix';

  const tabsHtml = `<div class="tabs">${tabs.map(t =>
    `<button class="tab-btn${t.id === active ? ' active' : ''}" onclick="navigate('framework','${t.id}')">${t.label}</button>`
  ).join('')}</div>`;

  let content = '';
  if (active === 'matrix')  content = await renderFrameworkMatrix();
  else if (active === 'flow')   content = renderFrameworkFlow();
  else if (active === 'mitre')  content = await renderFrameworkMitre();

  setMain(`
    <div class="page-title">Framework Mapping</div>
    <div class="page-sub">How IEC 62443, NACSA Act 854, NIST CSF 2.0, and MITRE ATT&amp;CK for ICS interconnect — navigation guide for security professionals.</div>
    <div class="disclaimer">All cross-framework mappings are constructed-indicative. Verify against official standard texts before use in formal assessments.</div>
    ${tabsHtml}
    ${content}
  `);
}

async function renderFrameworkMatrix() {
  const [frData, nacsaData, nistData] = await Promise.all([
    load('standards/iec62443/foundational-requirements.json'),
    load('cross-references/iec62443-to-nacsa.json'),
    load('cross-references/iec62443-to-nist-csf.json'),
  ]);

  const frs = frData.foundationalRequirements || [];
  const nacsaMappings = nacsaData.mappings || [];
  const nistMappings = nistData.mappings || [];

  // Build a quick lookup: NACSA section → which FRs are relevant
  const frToNacsa = {};
  const frToNist = {};

  frs.forEach(fr => {
    // Map based on FR → SR ranges; look up NIST subcategories for the FR's SRs
    const frSRs = nistMappings.filter(m => {
      const srId = m.srId || m.iec62443SR || '';
      return srId.startsWith(`SR-${fr.id.replace('FR','')}.`);
    });
    const csfCodes = [...new Set(frSRs.flatMap(m => m.nistCsf || m.nistCsfSubcategories || []))].slice(0, 4);
    frToNist[fr.id] = csfCodes;

    // NACSA: find relevant sections mentioning any SR in this FR
    const nacsaForFR = nacsaMappings
      .filter(nm => (nm.relevantSRs || nm.iec62443SRs || []).some(sr => sr.includes(`-${fr.id.replace('FR','')}.`)))
      .map(nm => nm.nacsaSection);
    frToNacsa[fr.id] = [...new Set(nacsaForFR)];
  });

  const frColors = { FR1: 'badge-sl2', FR2: 'badge-sl3', FR3: 'badge-preventive', FR4: 'badge-corrective', FR5: 'badge-critical', FR6: 'badge-sl2', FR7: 'badge-sl3' };

  const rows = frs.map(fr => {
    const nacsa = (frToNacsa[fr.id] || [fr.nacsa || []].flat()).slice(0, 4);
    const nist = frToNist[fr.id] || [];
    return `
    <tr>
      <td><span class="badge ${frColors[fr.id] || 'badge-minor'}">${escHtml(fr.id)}</span></td>
      <td><strong>${escHtml(fr.abbreviation || '')}</strong><div style="font-size:0.75rem;color:var(--text-muted)">${escHtml(fr.name)}</div></td>
      <td><span class="tag">${escHtml(fr.srRange || '')}</span></td>
      <td>${nacsa.length ? nacsa.map(n => `<span class="badge badge-malaysia" style="margin:1px">${escHtml(n)}</span>`).join('') : '<span style="color:var(--text-muted);font-size:0.75rem">—</span>'}</td>
      <td style="font-size:0.75rem">${nist.length ? nist.map(c => `<span class="tag" style="margin:1px">${escHtml(c)}</span>`).join('') : '<span style="color:var(--text-muted)">—</span>'}</td>
      <td><button class="back-link" style="font-size:0.75rem;padding:0.2rem 0.5rem" onclick="navigate('standards','iec-fr')">View FRs</button></td>
    </tr>`;
  }).join('');

  return `
    <h2>IEC 62443 FRs × NACSA Act 854 × NIST CSF 2.0</h2>
    <p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:1rem">Each IEC 62443 Foundational Requirement (FR) and its related NACSA obligations and NIST CSF 2.0 subcategories. Use this to plan assessments that satisfy multiple frameworks simultaneously.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>FR</th><th>Name</th><th>SRs</th><th>NACSA Act 854</th><th>NIST CSF 2.0</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>

    <h2 style="margin-top:1.5rem">Coverage Summary</h2>
    <div class="two-col">
      <div class="card">
        <div class="card-title">IEC 62443 Scope</div>
        <div class="card-desc">7 Foundational Requirements (FRs), 51 System Requirements (SRs). SRs are the measurable, testable technical requirements used in IEC 62443-3-2 zone assessments and IEC 62443-3-3 system specification.</div>
        <div class="card-tags"><span class="tag">7 FRs</span><span class="tag">51 SRs</span><span class="tag">4 Security Levels</span></div>
      </div>
      <div class="card">
        <div class="card-title">NACSA Act 854 Scope</div>
        <div class="card-desc">IEC 62443 SL 2 substantially satisfies s18 duties for most NCII-designated OT operators. s21 risk assessment uses IEC 62443-3-2 methodology. s23 audit uses IEC 62443-3-3 SL assessment framework.</div>
        <div class="card-tags"><span class="badge badge-malaysia">s17</span><span class="badge badge-malaysia">s18</span><span class="badge badge-malaysia">s21</span><span class="badge badge-malaysia">s22</span><span class="badge badge-malaysia">s23</span><span class="badge badge-malaysia">s26</span></div>
      </div>
    </div>`;
}

function renderFrameworkFlow() {
  const nodes = [
    { id: 'iec', label: 'IEC 62443', sub: '7 FRs · 51 SRs · 4 Security Levels', view: 'standards', vsub: 'iec-overview', color: 'var(--sl3)' },
    { id: 'nacsa', label: 'NACSA Act 854', sub: 's17-s26 obligations · NCII-designated entities', view: 'cross-ref', vsub: 'nacsa', color: 'var(--accent)' },
    { id: 'csf', label: 'NIST CSF 2.0', sub: '6 Functions · 22 Categories · 106 Subcategories', view: 'cross-ref', vsub: 'nist', color: 'var(--success)' },
    { id: 'nist80082', label: 'NIST SP 800-82 Rev 3', sub: 'OT security guidance · Publicly available', view: 'standards', vsub: 'nist', color: 'var(--sl2)' },
    { id: 'mitre', label: 'MITRE ATT&CK for ICS', sub: '12 Tactics · 80+ Techniques · public domain', view: 'standards', vsub: 'mitre', color: 'var(--danger)' },
    { id: 'iec61511', label: 'IEC 61511 / SIL', sub: 'Functional safety · SIS design · SIL certification', view: 'requirements', vsub: 'safety-system-security', color: 'var(--sl4)' },
  ];

  const nodesHtml = nodes.map(n => `
    <div class="card card-link" onclick="navigate('${n.view}','${n.vsub}')" style="border-left:3px solid ${n.color}">
      <div class="card-title">${escHtml(n.label)}</div>
      <div class="card-desc">${escHtml(n.sub)}</div>
    </div>`).join('');

  const relationships = [
    { from: 'IEC 62443', to: 'NACSA Act 854', rel: 'IEC 62443 SL 2 is the implementation standard for NACSA s18 security measures and s21 risk assessment methodology (IEC 62443-3-2).' },
    { from: 'IEC 62443', to: 'NIST CSF 2.0', rel: '51 SRs map to CSF 2.0 Protect/Detect subcategories. CSF provides governance context; IEC 62443 provides OT-specific technical requirements.' },
    { from: 'IEC 62443', to: 'NIST SP 800-82', rel: 'NIST 800-82 provides OT security guidance complementary to IEC 62443. 800-82 covers legacy OT without SL targeting; IEC 62443 provides the SL framework.' },
    { from: 'MITRE ATT&CK ICS', to: 'IEC 62443', rel: 'Each MITRE ICS technique maps to the IEC 62443 SRs that prevent or detect it. SR-5.1/5.2 (segmentation) counters most lateral movement techniques.' },
    { from: 'IEC 61511', to: 'IEC 62443', rel: 'IEC 61511 governs SIS functional safety (SIL). IEC 62443 adds security (SL 4 required for SIS). Both standards must be satisfied simultaneously for safety system security.' },
    { from: 'NACSA Act 854', to: 'NIST CSF 2.0', rel: 'CSF 2.0 Identify/Govern functions align with NACSA s21 risk assessment and s18 governance duties. NACSA does not mandate CSF but it is a useful parallel framework.' },
  ];

  const relHtml = relationships.map(r => `
    <div class="card" style="margin-bottom:0.5rem">
      <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.35rem">
        <strong style="font-size:0.85rem">${escHtml(r.from)}</strong>
        <span style="color:var(--text-muted)">→</span>
        <strong style="font-size:0.85rem">${escHtml(r.to)}</strong>
      </div>
      <div class="card-desc">${escHtml(r.rel)}</div>
    </div>`).join('');

  return `
    <h2>Standards in this Framework</h2>
    <div class="two-col">${nodesHtml}</div>
    <h2 style="margin-top:1.5rem">How They Relate</h2>
    ${relHtml}
    <div class="card" style="margin-top:1rem;background:rgba(99,102,241,0.06);border-color:var(--accent)">
      <div class="card-title">Recommended Assessment Order</div>
      <div class="attack-chain" style="margin-top:0.75rem">
        <div class="attack-step"><strong>1. Asset Inventory (SR-7.8)</strong> — Establish asset scope. You cannot assess what you haven't inventoried.</div>
        <div class="attack-step"><strong>2. Zone Risk Assessment (IEC 62443-3-2)</strong> — Define zones, assign SL-T. This satisfies NACSA s21.</div>
        <div class="attack-step"><strong>3. Gap Assessment (IEC 62443-3-3)</strong> — Measure SL-A per zone. SRs that are not met become remediation items. This is the NACSA s23 audit framework.</div>
        <div class="attack-step"><strong>4. Remediation Roadmap</strong> — Prioritise by SL gap size and consequence. Use this repo's controls library for implementation guidance.</div>
        <div class="attack-step"><strong>5. Monitoring &amp; Notification (SR-6.1, s26)</strong> — Deploy OT monitoring, test NACSA s26 notification procedure. 6-hour notification window starts from detection.</div>
      </div>
    </div>`;
}

async function renderFrameworkMitre() {
  let mitreData;
  try {
    mitreData = await load('cross-references/mitre-to-controls.json');
  } catch (e) {
    mitreData = null;
  }

  const techniques = await load('standards/mitre-attack-ics/techniques.json');
  const techs = techniques.techniques || [];

  const controls = await load('controls/library.json');
  const ctrlMap = {};
  (Array.isArray(controls) ? controls : []).forEach(c => { ctrlMap[c.slug] = c; });

  const mappings = mitreData ? (mitreData.mappings || []) : [];
  const mappingMap = {};
  mappings.forEach(m => { mappingMap[m.techniqueId] = m; });

  const tacticGroups = {};
  techs.forEach(t => {
    if (!tacticGroups[t.tactic]) tacticGroups[t.tactic] = [];
    tacticGroups[t.tactic].push(t);
  });

  const tacticLabels = {
    'TA0104': 'Initial Access', 'TA0108': 'Execution', 'TA0110': 'Persistence',
    'TA0111': 'Privilege Escalation', 'TA0103': 'Evasion', 'TA0102': 'Discovery',
    'TA0109': 'Lateral Movement', 'TA0100': 'Collection', 'TA0101': 'Command & Control',
    'TA0107': 'Inhibit Response Function', 'TA0106': 'Impair Process Control', 'TA0105': 'Impact',
  };

  const html = Object.entries(tacticGroups).map(([tactic, techList]) => {
    const techHtml = techList.map(t => {
      const m = mappingMap[t.id];
      const ctrlSlugs = m ? (m.controlSlugs || []) : [];
      const ctrlBadges = ctrlSlugs.slice(0, 2).map(s => {
        const c = ctrlMap[s];
        return c ? `<span class="tag" style="font-size:0.7rem">${escHtml(c.name)}</span>` : '';
      }).join('');
      return `
      <tr>
        <td><span class="tag" style="font-size:0.7rem;color:var(--danger)">${escHtml(t.id)}</span></td>
        <td style="font-size:0.8rem">${escHtml(t.name)}</td>
        <td style="font-size:0.75rem">${(t.iec62443SRs || []).map(s => `<span class="badge badge-sl2" style="margin:1px">${escHtml(s)}</span>`).join('')}</td>
        <td>${ctrlBadges || `<span style="color:var(--text-muted);font-size:0.75rem">—</span>`}</td>
      </tr>`;
    }).join('');
    return `
    <h3 style="margin-top:1.25rem">${escHtml(tacticLabels[tactic] || tactic)}</h3>
    <div class="table-wrap"><table>
      <thead><tr><th>Technique</th><th>Name</th><th>IEC 62443 SRs</th><th>Defensive Controls</th></tr></thead>
      <tbody>${techHtml}</tbody>
    </table></div>`;
  }).join('');

  return `
    <h2>MITRE ATT&amp;CK for ICS → Defensive Controls</h2>
    <p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:1rem">Maps ICS techniques to the IEC 62443 SRs and controls library entries that prevent or detect each technique. Use this to prioritise controls based on threat actor TTPs.</p>
    ${html}`;
}

// ─── RISK MANAGEMENT ─────────────────────────────────────────────────────────
async function renderRiskManagement(sub) {
  const tabs = [
    { id: 'methodology', label: 'Methodology' },
    { id: 'matrix',      label: 'Risk Matrix' },
    { id: 'register',    label: 'Risk Register' },
    { id: 'checklist',   label: 'Assessment Checklist' },
    { id: 'treatment',   label: 'Treatment Options' },
  ];
  const active = sub || 'methodology';

  const tabsHtml = `<div class="tabs">${tabs.map(t =>
    `<button class="tab-btn${t.id === active ? ' active' : ''}" onclick="navigate('risk-management','${t.id}')">${t.label}</button>`
  ).join('')}</div>`;

  let content = '';
  if (active === 'methodology')  content = await renderRMMethodology();
  else if (active === 'matrix')  content = await renderRMMatrix();
  else if (active === 'register') content = await renderRMRegister();
  else if (active === 'checklist') content = await renderRMChecklist();
  else if (active === 'treatment') content = await renderRMTreatment();

  setMain(`
    <div class="page-title">Risk Management</div>
    <div class="page-sub">OT/ICS-specific risk assessment methodology, 5x5 matrix, risk register, and treatment options</div>
    <div class="disclaimer"><strong>Safety Priority:</strong> In OT environments, risk must account for safety (human life), environmental damage, and process integrity — not just the IT-centric CIA triad. Safety-related risks cannot be accepted.</div>
    ${tabsHtml}
    ${content}
  `);
}

async function renderRMMethodology() {
  const data = await load('risk-management/methodology.json');
  const dims = data.impactDimensions?.dimensions || [];
  const factors = data.otSpecificRiskFactors?.factors || [];
  const steps = data.assessmentProcess?.steps || [];
  const impactLevels = data.impactScale?.levels || [];
  const likelihoodLevels = data.likelihoodScale?.levels || [];

  const dimsHtml = dims.map(d => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
        <span class="badge badge-sl${d.weight === 'Highest' ? '4' : d.weight === 'High' ? '3' : '2'}">${escHtml(d.weight)}</span>
        <span class="card-title" style="margin:0">${escHtml(d.name)}</span>
      </div>
      <div class="card-desc">${escHtml(d.description)}</div>
      ${d.examples ? `<div style="margin-top:0.5rem">${tagList(d.examples)}</div>` : ''}
    </div>`).join('');

  const factorsHtml = factors.map(f => `
    <div class="card">
      <div class="card-title">${escHtml(f.name)}</div>
      <div class="card-desc">${escHtml(f.description)}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem;border-top:1px solid var(--border);padding-top:0.5rem"><strong>Guidance:</strong> ${escHtml(f.guidance)}</div>
    </div>`).join('');

  const stepsHtml = steps.map(s => `
    <div class="attack-step"><strong>Step ${s.step}: ${escHtml(s.name)}</strong><br><span style="font-size:0.8rem">${escHtml(s.description)}</span></div>`).join('');

  const impactTableHtml = impactLevels.map(l => `
    <tr>
      <td><span class="badge badge-sl${l.level >= 4 ? '4' : l.level >= 3 ? '3' : l.level >= 2 ? '2' : '1'}">${l.level}</span></td>
      <td><strong>${escHtml(l.label)}</strong></td>
      <td style="font-size:0.75rem">${escHtml(l.safety)}</td>
      <td style="font-size:0.75rem">${escHtml(l.environmental)}</td>
      <td style="font-size:0.75rem">${escHtml(l.availability)}</td>
    </tr>`).join('');

  const likelihoodTableHtml = likelihoodLevels.map(l => `
    <tr>
      <td><strong>${l.level}</strong></td>
      <td><strong>${escHtml(l.label)}</strong></td>
      <td style="font-size:0.8rem">${escHtml(l.frequency)}</td>
      <td style="font-size:0.75rem">${escHtml(l.otContext)}</td>
    </tr>`).join('');

  return `
    <div class="disclaimer">${escHtml(data.verificationNote || '')}</div>
    <h2>${escHtml(data.title || 'Methodology')}</h2>
    <div class="detail-body" style="margin-bottom:1rem">${escHtml(data.description || '')}</div>
    <div class="card" style="border-left:3px solid var(--danger);margin-bottom:1.5rem">
      <div class="card-desc"><strong>Key Principle:</strong> ${escHtml(data.keyPrinciple || '')}</div>
    </div>

    <h2>Impact Dimensions (OT-Weighted)</h2>
    <div class="page-sub">${escHtml(data.impactDimensions?.description || '')}</div>
    <div class="two-col">${dimsHtml}</div>

    <h2>Impact Scale</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Level</th><th>Label</th><th>Safety</th><th>Environmental</th><th>Availability</th></tr></thead>
      <tbody>${impactTableHtml}</tbody>
    </table></div>

    <h2>Likelihood Scale</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Level</th><th>Label</th><th>Frequency</th><th>OT Context</th></tr></thead>
      <tbody>${likelihoodTableHtml}</tbody>
    </table></div>

    <h2>OT-Specific Risk Factors</h2>
    <div class="page-sub">${escHtml(data.otSpecificRiskFactors?.description || '')}</div>
    <div class="two-col">${factorsHtml}</div>

    <h2>Assessment Process (IEC 62443-3-2)</h2>
    <div class="attack-chain">${stepsHtml}</div>
  `;
}

async function renderRMMatrix() {
  const data = await load('risk-management/risk-matrix.json');
  const bands = data.bands || [];
  const matrix = data.matrix || [];
  const safetyOverride = data.safetyOverride || {};

  const bandColors = {};
  bands.forEach(b => { bandColors[b.band] = b.color; });

  // Build 5x5 grid
  let gridHtml = '<tr><th style="width:6rem"></th>';
  for (let i = 1; i <= 5; i++) {
    const imp = (data.axes?.impact?.scale || []).find(s => s.level === i);
    gridHtml += `<th style="text-align:center;font-size:0.7rem">${i}<br>${escHtml(imp?.label || '')}</th>`;
  }
  gridHtml += '</tr>';

  for (let l = 5; l >= 1; l--) {
    const lk = (data.axes?.likelihood?.scale || []).find(s => s.level === l);
    gridHtml += `<tr><td style="font-size:0.7rem;font-weight:600"><span style="display:inline-block;width:1.2rem">${l}</span> ${escHtml(lk?.label || '')}</td>`;
    for (let i = 1; i <= 5; i++) {
      const cell = matrix.find(m => m.likelihood === l && m.impact === i);
      const color = cell ? (bandColors[cell.band] || '#666') : '#666';
      gridHtml += `<td style="text-align:center;background:${color}20;border:1px solid ${color}40;font-weight:600;color:${color};font-size:0.8rem">${cell?.score || ''}<br><span style="font-size:0.65rem">${escHtml(cell?.band || '')}</span></td>`;
    }
    gridHtml += '</tr>';
  }

  const bandsHtml = bands.map(b => `
    <div class="card" style="border-left:4px solid ${b.color}">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
        <span class="badge" style="background:${b.color};color:white">${escHtml(b.band)}</span>
        <span style="font-size:0.75rem;color:var(--text-muted)">Score ${escHtml(b.scoreRange)}</span>
        <span style="font-size:0.75rem;color:var(--text-muted);margin-left:auto">Review: ${escHtml(b.reviewCadence)}</span>
      </div>
      <div class="card-desc">${escHtml(b.action)}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem"><strong>Escalation:</strong> ${escHtml(b.escalation)}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem"><strong>OT Note:</strong> ${escHtml(b.otNote)}</div>
    </div>`).join('');

  return `
    <h2>5x5 Risk Matrix</h2>
    <div class="page-sub">${escHtml(data.description || '')}</div>
    <div class="table-wrap"><table style="border-collapse:collapse">${gridHtml}</table></div>

    <div class="card" style="border-left:3px solid var(--danger);margin:1.5rem 0">
      <div class="card-title">Safety Override Rule</div>
      <div class="card-desc">${escHtml(safetyOverride.description || '')}</div>
      <div style="font-family:var(--mono);font-size:0.8rem;background:var(--bg-offset);padding:0.5rem;border-radius:4px;margin-top:0.5rem">${escHtml(safetyOverride.rule || '')}</div>
    </div>

    <h2>Band Actions</h2>
    ${bandsHtml}
  `;
}

async function renderRMRegister() {
  const data = await load('risk-management/risk-register.json');
  const risks = data.risks || [];
  const categories = [...new Set(risks.map(r => r.category))];

  const filterHtml = `<div class="tabs" style="flex-wrap:wrap;margin-bottom:1rem">
    <button class="tab-btn active" onclick="filterRisks('all')">All (${risks.length})</button>
    ${categories.map(c => `<button class="tab-btn" onclick="filterRisks('${c}')">${escHtml(c)} (${risks.filter(r=>r.category===c).length})</button>`).join('')}
  </div>`;

  const bandColor = b => b === 'Critical' ? '#EF4444' : b === 'High' ? '#F97316' : b === 'Medium' ? '#F59E0B' : '#22C55E';

  const risksHtml = risks.map(r => `
    <div class="card risk-item" data-category="${escHtml(r.category)}" style="margin-bottom:0.75rem">
      <div style="display:flex;align-items:flex-start;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.5rem">
        <span class="badge badge-sl2">${escHtml(r.id)}</span>
        <span class="card-title" style="margin:0;flex:1">${escHtml(r.title)}</span>
        ${r.safetyImpact ? '<span class="badge badge-critical">Safety</span>' : ''}
        <span class="badge" style="background:${bandColor(r.inherentRisk)};color:white">Inherent: ${escHtml(r.inherentRisk)}</span>
        <span class="badge" style="background:${bandColor(r.residualRisk)};color:white">Residual: ${escHtml(r.residualRisk)}</span>
      </div>
      <div class="card-desc">${escHtml(r.description)}</div>
      <div class="two-col" style="margin-top:0.75rem">
        <div class="detail-section">
          <h3>Existing Controls</h3>
          <ul style="font-size:0.8rem;padding-left:1.25rem">${(r.existingControls||[]).map(c => `<li>${escHtml(c)}</li>`).join('')}</ul>
        </div>
        <div class="detail-section">
          <h3>Treatment Plan (${escHtml(r.treatment)})</h3>
          <div style="font-size:0.8rem">${escHtml(r.treatmentPlan)}</div>
        </div>
      </div>
      <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-top:0.5rem;font-size:0.7rem;color:var(--text-muted);border-top:1px solid var(--border);padding-top:0.5rem">
        <span><strong>Category:</strong> ${escHtml(r.category)}</span>
        <span><strong>Owner:</strong> ${escHtml(r.owner)}</span>
        <span><strong>Review:</strong> ${escHtml(r.reviewDate)}</span>
        <span><strong>IEC 62443:</strong> ${(r.iec62443Ref||[]).map(s => `<span class="badge badge-sl2" style="margin:1px;font-size:0.6rem">${escHtml(s)}</span>`).join('')}</span>
        <span><strong>Scores:</strong> L${r.likelihood}xI${r.impact}=${r.likelihood*r.impact} → L${r.residualLikelihood}xI${r.residualImpact}=${r.residualLikelihood*r.residualImpact}</span>
      </div>
    </div>`).join('');

  return `
    <h2>OT/ICS Risk Register (${risks.length} Risks)</h2>
    <div class="page-sub">${escHtml(data.description || '')}</div>
    ${filterHtml}
    <div id="risk-list">${risksHtml}</div>
  `;
}

window.filterRisks = function(cat) {
  document.querySelectorAll('.risk-item').forEach(el => {
    el.style.display = (cat === 'all' || el.dataset.category === cat) ? '' : 'none';
  });
  const tabs = document.querySelectorAll('.tabs .tab-btn');
  tabs.forEach(t => {
    const isAll = cat === 'all' && t.textContent.startsWith('All');
    const isCat = t.textContent.startsWith(cat);
    t.classList.toggle('active', isAll || isCat);
  });
};

async function renderRMChecklist() {
  const data = await load('risk-management/checklist.json');
  const items = data.items || [];
  const categories = [...new Set(items.map(i => i.category))];

  const html = categories.map(cat => {
    const catItems = items.filter(i => i.category === cat);
    return `
      <h3 style="margin-top:1.25rem">${escHtml(cat)}</h3>
      ${catItems.map(item => `
        <div class="card" style="margin-bottom:0.5rem">
          <div style="display:flex;align-items:flex-start;gap:0.5rem;margin-bottom:0.5rem">
            <span class="badge badge-sl2">${escHtml(item.id)}</span>
            <span class="card-title" style="margin:0;flex:1">${escHtml(item.item)}</span>
            ${item.mandatory ? '<span class="badge badge-critical">Mandatory</span>' : '<span class="badge badge-minor">Advisory</span>'}
          </div>
          <div class="card-desc">${escHtml(item.guidance)}</div>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem;border-top:1px solid var(--border);padding-top:0.5rem"><strong>Evidence Required:</strong> ${escHtml(item.evidenceRequired)}</div>
        </div>`).join('')}`;
  }).join('');

  return `
    <h2>OT Risk Assessment Checklist (${items.length} Items)</h2>
    <div class="page-sub">${escHtml(data.description || '')}</div>
    <div class="detail-body" style="margin-bottom:1rem">${escHtml(data.usage || '')}</div>
    ${html}
  `;
}

async function renderRMTreatment() {
  const data = await load('risk-management/treatment-options.json');
  const strategies = data.strategies || [];
  const constraint = data.safetyConstraint || {};

  const strategiesHtml = strategies.map(s => `
    <div class="card" style="margin-bottom:1rem">
      <div class="card-title" style="font-size:1rem">${escHtml(s.name)}</div>
      <div class="card-desc">${escHtml(s.description)}</div>
      <div style="font-size:0.8rem;color:var(--accent);margin-top:0.5rem"><strong>When to use:</strong> ${escHtml(s.whenToUse)}</div>

      ${s.otExamples ? `
        <div style="margin-top:0.75rem">
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.35rem">OT Examples</div>
          ${s.otExamples.map(ex => `
            <div style="background:var(--bg-offset);padding:0.5rem 0.75rem;border-radius:4px;margin-bottom:0.35rem;font-size:0.8rem">
              <strong>${escHtml(ex.risk)}:</strong> ${escHtml(ex.mitigation || ex.transfer || ex.avoidance || ex.acceptance || '')}
              ${ex.residualRisk ? `<div style="color:var(--text-muted);font-size:0.75rem;margin-top:0.25rem">${escHtml(ex.residualRisk)}</div>` : ''}
              ${ex.limitation ? `<div style="color:var(--text-muted);font-size:0.75rem;margin-top:0.25rem">${escHtml(ex.limitation)}</div>` : ''}
              ${ex.tradeoff ? `<div style="color:var(--text-muted);font-size:0.75rem;margin-top:0.25rem">Trade-off: ${escHtml(ex.tradeoff)}</div>` : ''}
            </div>`).join('')}
        </div>` : ''}

      ${s.considerations ? `
        <div style="margin-top:0.75rem">
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.25rem">Considerations</div>
          <ul style="font-size:0.8rem;padding-left:1.25rem;color:var(--text-muted)">${s.considerations.map(c => `<li style="margin-bottom:0.25rem">${escHtml(c)}</li>`).join('')}</ul>
        </div>` : ''}

      ${s.constraints ? `
        <div style="margin-top:0.75rem">
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--danger);margin-bottom:0.25rem">Constraints</div>
          <ul style="font-size:0.8rem;padding-left:1.25rem;color:var(--danger)">${s.constraints.map(c => `<li style="margin-bottom:0.25rem">${escHtml(c)}</li>`).join('')}</ul>
        </div>` : ''}
    </div>`).join('');

  return `
    <div class="card" style="border-left:3px solid var(--danger);margin-bottom:1.5rem">
      <div class="card-title">Safety Constraint</div>
      <div class="card-desc">${escHtml(constraint.rule || '')}</div>
      <div style="font-size:0.8rem;color:var(--text-muted);margin-top:0.5rem">${escHtml(constraint.rationale || '')}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem"><strong>Regulatory:</strong> ${escHtml(constraint.regulatoryNote || '')}</div>
    </div>
    <h2>Treatment Strategies</h2>
    ${strategiesHtml}
  `;
}

// ─── Bootstrap ───────────────────────────────────────────────────────────────
window.navigate = navigate;

window.addEventListener('popstate', route);

document.addEventListener('DOMContentLoaded', () => {
  initSearch();

  // Accordion toggle handler
  document.addEventListener('click', (e) => {
    const accHeader = e.target.closest('[data-accordion]');
    if (accHeader) {
      const item = accHeader.closest('.accordion-item');
      if (item) item.classList.toggle('open');
      return;
    }
  });

  // Handle search query in URL
  const { view, sub } = parseHash();
  if (view === 'search' && sub) {
    const q = decodeURIComponent(sub);
    searchQuery = q;
    const input = document.getElementById('search-input');
    if (input) input.value = q;
  }
  route();
});
