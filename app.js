/* OT Security Framework — SPA
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
    case 'artifacts':       return renderArtifacts(sub);
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
  const levelsHtml = data.securityLevels ? data.securityLevels.map(sl => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
        ${slBadge(sl.level)} ${slDots(sl.level)}
        <span class="card-title" style="margin:0">${escHtml(sl.label)}</span>
      </div>
      <div class="card-desc">${escHtml(sl.description)}</div>
      <div class="detail-section" style="margin-top:0.75rem">
        <div style="font-size:0.75rem;color:var(--text-muted)"><strong>Threat Profile:</strong> ${escHtml(sl.threatProfile || '')}</div>
        <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem"><strong>Malaysia Context:</strong> ${escHtml(sl.malaysiaContext || '')}</div>
        <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem"><strong>Typical Applicability:</strong> ${escHtml(sl.typicalApplicability || '')}</div>
      </div>
      ${sl.controlCharacteristics ? `
        <div style="margin-top:0.75rem">
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.35rem">Control Characteristics</div>
          ${tagList(sl.controlCharacteristics)}
        </div>` : ''}
    </div>`).join('') : '';

  return `
    <h2>Security Level Definitions</h2>
    <div class="two-col">${levelsHtml}</div>
    ${data.slTargetingProcess ? `
      <h2>SL Targeting Process</h2>
      <div class="attack-chain">${data.slTargetingProcess.map((step, i) => `
        <div class="attack-step"><strong>Step ${i+1}:</strong> ${escHtml(step)}</div>`).join('')}
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
  if (!data.systemRequirements) return '<div class="empty-state">No data</div>';

  const frGroups = {};
  data.systemRequirements.forEach(sr => {
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
    <div class="page-sub">Click any SR for full SL 1–4 descriptions and mappings. ${data.systemRequirements.length} SRs across 7 FRs.</div>
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
          <div style="margin-top:0.25rem"><strong>Key Vulnerabilities:</strong> ${escHtml((l.securityCharacteristics.vulnerabilities || []).join(', '))}</div>
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
        ${d.primaryFRs ? d.primaryFRs.map(f => `<span class="badge badge-sl2">${escHtml(f)}</span>`).join('') : ''}
        ${d.nacsa ? d.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('') : ''}
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
          <div class="detail-body">${escHtml(r.legal.basis || '')}</div>
          <div class="card-tags" style="margin-top:0.35rem">
            ${r.legal.iec62443 ? r.legal.iec62443.map(s => `<span class="badge badge-sl2">${escHtml(s)}</span>`).join('') : ''}
            ${r.legal.nacsa ? r.legal.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('') : ''}
          </div>
        </div>` : ''}

      ${r.technical ? `
        <div class="detail-section">
          <h3>Technical Requirement</h3>
          <div class="detail-body">${escHtml(r.technical.requirement || '')}</div>
          ${r.technical.implementation ? `<div style="margin-top:0.35rem;font-size:0.8rem;color:var(--text-muted)">${r.technical.implementation}</div>` : ''}
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

      <div class="card-tags">
        ${r.mitreAttackIcs ? r.mitreAttackIcs.map(m => `<span class="tag" style="color:var(--danger)">${escHtml(m)}</span>`).join('') : ''}
        ${r.nacsa ? r.nacsa.map(n => `<span class="badge badge-malaysia">${escHtml(n)}</span>`).join('') : ''}
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
  const [controls, domains] = await Promise.all([
    load('controls/library.json'),
    load('controls/domains.json'),
  ]);

  const allControls = Array.isArray(controls) ? controls : [];

  if (sub) {
    const ctrl = allControls.find(c => c.slug === sub);
    if (ctrl) return renderControlDetail(ctrl, allControls);
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

function renderControlDetail(ctrl, allControls) {
  const backHtml = `<button class="back-link" onclick="navigate('controls',null)">← All Controls</button>`;

  const maturityHtml = ctrl.maturity ? Object.entries(ctrl.maturity).map(([lvl, desc]) => `
    <div class="card">
      <div class="card-title" style="text-transform:capitalize">${escHtml(lvl)}</div>
      <div class="card-desc">${escHtml(desc)}</div>
    </div>`).join('') : '';

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
  `);
}

// ─── EVIDENCE ─────────────────────────────────────────────────────────────────
async function renderEvidence(sub) {
  const data = await load('evidence/index.json');
  const byDomain = data.evidenceByDomain || {};

  const domains = Object.keys(byDomain);
  const active = sub && domains.includes(sub) ? sub : domains[0];

  const tabsHtml = `<div class="tabs">${domains.map(d =>
    `<button class="tab-btn${d === active ? ' active' : ''}" onclick="navigate('evidence','${d}')">${escHtml(byDomain[d]?.description ? d : d)}</button>`
  ).join('')}</div>`;

  const domainData = byDomain[active] || {};
  const items = domainData.evidenceItems || [];

  const itemsHtml = items.map(item => `
    <div class="card">
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
        <span class="badge badge-sl2">${escHtml(item.id)}</span>
        <span class="card-title" style="margin:0">${escHtml(item.name)}</span>
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
      <div class="attack-chain">${sector.regulatoryOverlap.map(r => `<div class="attack-step">${escHtml(r)}</div>`).join('')}</div>` : ''}
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
        <span class="card-title" style="margin:0">${escHtml(m.nacsaObligation)}</span>
      </div>
      <div class="card-desc">${escHtml(m.description || '')}</div>
      <div style="margin-top:0.75rem">
        <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.35rem">Related IEC 62443 SRs</div>
        ${tagList(m.iec62443SRs || [])}
      </div>
      ${m.domains ? `<div style="margin-top:0.35rem">${tagList(m.domains)}</div>` : ''}
    </div>`).join('');

  const slHtml = data.slToNacsaMapping ? `
    <h2 style="margin-top:1.5rem">Security Level → NACSA Obligation</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>SL</th><th>NACSA Minimum</th><th>Applicability</th></tr></thead>
      <tbody>${data.slToNacsaMapping.map(m => `
        <tr><td>${slBadge(m.sl)}</td><td>${escHtml(m.nacsaMinimum || '')}</td><td>${escHtml(m.applicability || '')}</td></tr>`).join('')}
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
      <tbody>${mappings.map(m => `
        <tr>
          <td><strong>${escHtml(m.iec62443SR)}</strong></td>
          <td>${escHtml(m.srName || '')}</td>
          <td style="font-size:0.75rem">${(m.nistCsfSubcategories || []).join(', ')}</td>
          <td><span class="badge ${m.similarity === 'High' ? 'badge-preventive' : m.similarity === 'Medium' ? 'badge-corrective' : 'badge-minor'}">${escHtml(m.similarity || '')}</span></td>
        </tr>`).join('')}
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

// ─── Bootstrap ───────────────────────────────────────────────────────────────
window.navigate = navigate;

window.addEventListener('popstate', route);

document.addEventListener('DOMContentLoaded', () => {
  initSearch();
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
