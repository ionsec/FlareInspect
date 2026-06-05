'use strict';
/* FlareInspect Dashboard v2 — design by Claude Design, wired to the live API.
   Render logic mirrors the design prototype; data is pulled from the server.
   The mock constants below are the offline fallback (e.g. served statically). */

// ─── Fallback / seed data (overwritten by live data when the API responds) ──
let ACCOUNT = { name: '—', id: '' };

let ZONES = [];

let SCORE = { overall: 0, grade: '—', breakdown: {} };

let SUMMARY = { totalChecks: 0, passedChecks: 0, failedChecks: 0,
  critical: 0, high: 0, medium: 0, low: 0, completedAt: null, duration: '—' };

let FINDINGS = [];

let HISTORY = [];

let TREND = [];

let COMPLIANCE = {
  cis:  { name: 'CIS Benchmark', ver: 'v8.0',    score: 0, total: 0, passed: 0, controls: 'AC, CM, SC, SI' },
  soc2: { name: 'SOC 2',         ver: 'CC6–CC8',  score: 0, total: 0, passed: 0, controls: 'CC6.1, CC6.7, CC7.2' },
  pci:  { name: 'PCI-DSS',       ver: 'v4.0',     score: 0, total: 0, passed: 0, controls: 'Req 6, 8, 10, 11' },
  nist: { name: 'NIST CSF',      ver: '2.0',      score: 0, total: 0, passed: 0, controls: 'PR.AC, DE.CM, RS.CO' },
};

let ATTACK_PATHS = [];

// Live-only structures
let GRAPH = null;            // { nodes, edges } from /api/posture/graph
let PATHS = [];              // attack paths from /api/posture/graph
let FINDINGS_BY_ID = {};     // finding id -> lightweight mapped finding (posture drawer)
let FINDINGS_FULL = {};      // finding id -> full raw finding (detail drawer)
let NODE_BY_ID = {};         // graph node id -> node (for attack-path labels)
let CURRENT_ASSESSMENT = null;
let ALLOW_REMEDIATION = false;

// Per-service Cloudflare documentation references (no per-check URLs exist in the
// engine; this maps a finding's service to the most relevant developer docs).
const CF_DOCS = {
  ssl: 'https://developers.cloudflare.com/ssl/', tls: 'https://developers.cloudflare.com/ssl/',
  waf: 'https://developers.cloudflare.com/waf/', 'account-waf': 'https://developers.cloudflare.com/waf/',
  dns: 'https://developers.cloudflare.com/dns/', 'dns-firewall': 'https://developers.cloudflare.com/dns/dns-firewall/',
  bot: 'https://developers.cloudflare.com/bots/', turnstile: 'https://developers.cloudflare.com/turnstile/',
  zerotrust: 'https://developers.cloudflare.com/cloudflare-one/', gateway: 'https://developers.cloudflare.com/cloudflare-one/policies/gateway/',
  tunnels: 'https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/', mtls: 'https://developers.cloudflare.com/ssl/client-certificates/',
  logpush: 'https://developers.cloudflare.com/logs/logpush/', notifications: 'https://developers.cloudflare.com/notifications/',
  email: 'https://developers.cloudflare.com/email-security/', securitytxt: 'https://developers.cloudflare.com/security-center/',
  workers: 'https://developers.cloudflare.com/workers/', pages: 'https://developers.cloudflare.com/pages/',
  performance: 'https://developers.cloudflare.com/speed/', cache: 'https://developers.cloudflare.com/cache/',
  api: 'https://developers.cloudflare.com/api-shield/', 'page-shield': 'https://developers.cloudflare.com/page-shield/',
  credentials: 'https://developers.cloudflare.com/waf/detections/leaked-credentials/', dlp: 'https://developers.cloudflare.com/cloudflare-one/policies/data-loss-prevention/',
  'ai-gateway': 'https://developers.cloudflare.com/ai-gateway/', zaraz: 'https://developers.cloudflare.com/zaraz/',
  snippets: 'https://developers.cloudflare.com/rules/snippets/', 'attack-surface': 'https://developers.cloudflare.com/security-center/',
  account: 'https://developers.cloudflare.com/fundamentals/account/', token: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/'
};
function cfDocLink(service) { return CF_DOCS[service] || 'https://developers.cloudflare.com/'; }
const SETTINGS_KEYS = ['slackWebhook', 'teamsWebhook', 'webhookUrl', 'webhookSecret', 'notifyThreshold',
  'aiProvider', 'aiModel', 'anthropicApiKey', 'openaiApiKey', 'ollamaHost',
  'esUrl', 'esApiKey', 'esUsername', 'esPassword', 'hecUrl', 'hecToken'];

// ─── State ──────────────────────────────────────────────────────────────────
let currentSection = 'overview';
let currentFilter = 'all';
let currentSearch = '';
let isDark = true;
let pmBound = false;
let showAttackPaths = false;
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const COMPLIANCE_FRAMEWORKS = ['cis', 'soc2', 'pci', 'nist'];

// ─── Utilities ────────────────────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function $(id) { return document.getElementById(id); }
function gradeColor(g) { return { A: 'var(--low)', B: 'var(--low)', C: 'var(--flare)', D: 'var(--high)', F: 'var(--crit)' }[g] || 'var(--fg-3)'; }
function scoreColor(v) {
  if (v >= 80) return 'oklch(72% 0.15 155)';
  if (v >= 65) return 'oklch(78% 0.14 85)';
  if (v >= 50) return 'oklch(72% 0.17 52)';
  return 'oklch(65% 0.21 25)';
}
function fmtUTC(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'; }
  catch { return '—'; }
}
function durationOf(a) {
  const start = a.startedAt ? Date.parse(a.startedAt) : NaN;
  const end = a.completedAt ? Date.parse(a.completedAt) : NaN;
  let ms = (Number.isFinite(start) && Number.isFinite(end)) ? end - start : null;
  if (ms == null && typeof a.executionTime === 'number') ms = a.executionTime;
  if (ms == null || ms < 0) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

// ─── Data layer ─────────────────────────────────────────────────────────────
async function apiGet(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `Request failed (${res.status})`);
  return res.json();
}
async function apiPost(path, body, method = 'POST') {
  const res = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function applyAssessment(a) {
  if (!a) return;
  CURRENT_ASSESSMENT = a;
  const zones = Array.isArray(a.zones) ? a.zones : [];
  const zonesById = {};
  zones.forEach(z => { zonesById[z.id] = z.name; });

  ACCOUNT = { name: a.account?.name || '—', id: a.account?.id || '' };
  ZONES = zones.map(z => ({ id: z.id, name: z.name, plan: z.plan || 'Free' }));

  const sc = a.score || {};
  SCORE = { overall: sc.overallScore ?? 0, grade: sc.grade || '—', breakdown: sc.breakdown || {} };

  const s = a.summary || {};
  SUMMARY = {
    totalChecks: s.totalChecks || 0,
    passedChecks: s.passedChecks || 0,
    failedChecks: s.failedChecks || 0,
    critical: s.criticalFindings || 0,
    high: s.highFindings || 0,
    medium: s.mediumFindings || 0,
    low: s.lowFindings || 0,
    completedAt: a.completedAt || a.startedAt || null,
    duration: durationOf(a),
  };

  FINDINGS_BY_ID = {};
  FINDINGS_FULL = {};
  FINDINGS = (a.findings || [])
    .filter(f => f.status !== 'PASS')
    .map(f => {
      if (f.id) FINDINGS_FULL[f.id] = f;
      let zone = '—';
      if (f.resourceType === 'account') zone = 'account';
      else if (zonesById[f.resourceId]) zone = zonesById[f.resourceId];
      else if (f.metadata?.resourceName) zone = f.metadata.resourceName;
      const mapped = {
        id: f.id,
        checkId: f.checkId || (f.id || '').slice(0, 8),
        checkTitle: f.checkTitle || f.title || f.checkId || 'Finding',
        service: f.service || f.category || '—',
        severity: f.severity || 'low',
        zone,
        desc: f.description || f.evidence?.summary || '',
      };
      if (f.id) FINDINGS_BY_ID[f.id] = mapped;
      return mapped;
    });
}

function applyHistory(list) {
  const sorted = [...(list || [])].sort((x, y) => new Date(y.startedAt || 0) - new Date(x.startedAt || 0));
  HISTORY = sorted.map(a => ({
    id: (a.id || '').slice(0, 8),
    fullId: a.id,
    date: a.startedAt ? new Date(a.startedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—',
    score: a.score ?? 0,
    grade: a.grade || '—',
    duration: '—',
    zones: a.zones ?? '',
    checks: a.checks ?? '',
  }));
  TREND = sorted.slice(0, 12).reverse().map(a => (typeof a.score === 'number' ? a.score : 0));
}

function applyCompliance(results) {
  results.forEach((res, i) => {
    const key = COMPLIANCE_FRAMEWORKS[i];
    const c = res && res.compliance;
    if (!COMPLIANCE[key]) return;
    if (c) {
      COMPLIANCE[key].score = c.overallScore || 0;
      COMPLIANCE[key].total = c.totalControls || 0;
      COMPLIANCE[key].passed = c.passedControls || 0;
    }
  });
}

function applyGraph(payload) {
  GRAPH = payload && payload.graph ? payload.graph : null;
  PATHS = (payload && Array.isArray(payload.paths)) ? payload.paths : [];
  NODE_BY_ID = {};
  if (GRAPH && Array.isArray(GRAPH.nodes)) GRAPH.nodes.forEach(n => { NODE_BY_ID[n.id] = n; });
  ATTACK_PATHS = PATHS.map(p => {
    const ids = Array.isArray(p.nodes) ? p.nodes : (Array.isArray(p.path) ? p.path : []);
    const hops = ids.map(id => (NODE_BY_ID[id]?.label) || id);
    return {
      sev: p.severity || 'high',
      title: p.title || p.name || p.label || p.kind || 'Attack path',
      hops: hops.length ? hops : ['Internet', '…', 'Origin'],
      ids: p.remediableCheckIds || p.checkIds || [],
    };
  });
}

async function loadAll({ navigate = false } = {}) {
  setFootStatus('busy', 'Loading…');
  let gotAssessment = false;
  try {
    const data = await apiGet('/api/assessment');
    if (data.assessment) { applyAssessment(data.assessment); gotAssessment = true; }
  } catch (_) { /* no assessment yet */ }

  // Secondary data — best effort, never blocks the main render.
  await Promise.all([
    apiGet('/api/assessments').then(d => applyHistory(Array.isArray(d) ? d : (d.assessments || []))).catch(() => {}),
    Promise.all(COMPLIANCE_FRAMEWORKS.map(fw => apiGet(`/api/compliance/${fw}`).catch(() => null)))
      .then(applyCompliance).catch(() => {}),
    apiGet('/api/posture/graph').then(applyGraph).catch(() => {}),
    apiGet('/api/health').then(d => { ALLOW_REMEDIATION = d.remediation === 'enabled'; }).catch(() => {}),
  ]);

  if (ACCOUNT.name && ACCOUNT.name !== '—') {
    if ($('account-name')) $('account-name').textContent = ACCOUNT.name;
    if ($('crumb-account')) $('crumb-account').textContent = ACCOUNT.name;
    if ($('brand-sub')) $('brand-sub').textContent = ACCOUNT.name;
  }
  setFootStatus(gotAssessment ? 'ready' : 'idle', gotAssessment ? (SUMMARY.critical ? 'Assessment ready' : 'All checks passing') : 'No assessment yet');

  pmBound = false; // rebuild posture map against fresh data on next visit
  renderSection(currentSection);
  if (navigate) navigateTo('overview');
}

function setFootStatus(state, text) {
  const dot = $('foot-dot');
  if (dot) { dot.classList.remove('busy', 'error'); if (state === 'busy') dot.classList.add('busy'); if (state === 'error') dot.classList.add('error'); }
  if ($('foot-status-text') && text) $('foot-status-text').textContent = text;
}

// ─── Score ring ───────────────────────────────────────────────────────────
function buildRingSVG(id) {
  return `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="${id}-g" x1="0" x2="1" y1="0" y2="1">
        <stop offset="0%" stop-color="oklch(72% 0.15 155)"/>
        <stop offset="60%" stop-color="oklch(78% 0.14 85)"/>
        <stop offset="100%" stop-color="oklch(72% 0.17 52)"/>
      </linearGradient>
    </defs>
    <circle cx="100" cy="100" r="80" fill="none" stroke="var(--bg-3)" stroke-width="12"/>
    <circle class="ring-fill" cx="100" cy="100" r="80" fill="none"
      stroke="url(#${id}-g)" stroke-width="12" stroke-linecap="round"
      transform="rotate(-90 100 100)"/>
  </svg>`;
}

function animateRing(el, score) {
  const circle = el.querySelector('.ring-fill');
  if (!circle) return;
  const C = 2 * Math.PI * 80;
  circle.style.strokeDasharray = C;
  circle.style.strokeDashoffset = C;
  setTimeout(() => {
    circle.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)';
    circle.style.strokeDashoffset = C * (1 - Math.max(0, Math.min(100, score)) / 100);
  }, 80);
}

function miniRing(score, color) {
  const r = 28, C = 2 * Math.PI * r, off = C * (1 - score / 100);
  return `<svg class="comp-mini-ring" viewBox="0 0 72 72" xmlns="http://www.w3.org/2000/svg">
    <circle cx="36" cy="36" r="${r}" fill="none" stroke="var(--bg-3)" stroke-width="6"/>
    <circle cx="36" cy="36" r="${r}" fill="none" stroke="${color}" stroke-width="6"
      stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" stroke-linecap="round"
      transform="rotate(-90 36 36)"/>
    <text x="36" y="40" text-anchor="middle" fill="var(--fg)" font-family="'Geist Mono',monospace"
      font-size="13" font-weight="700" font-variant-numeric="tabular-nums">${score}%</text>
  </svg>`;
}

// ─── Sparkline ────────────────────────────────────────────────────────────
function sparkline(data, w = 120, h = 28, color = 'var(--flare)') {
  if (!data || data.length < 2) return '<span style="color:var(--fg-4);font-family:var(--font-mono);font-size:11px">—</span>';
  const max = Math.max(...data), min = Math.min(...data), range = Math.max(1, max - min);
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - ((v - min) / range) * (h - 4) - 2]);
  const d = pts.map((p, i) => (i === 0 ? `M${p[0].toFixed(1)},${p[1].toFixed(1)}` : `L${p[0].toFixed(1)},${p[1].toFixed(1)}`)).join(' ');
  const area = d + ` L${w},${h} L0,${h} Z`;
  const last = pts[pts.length - 1];
  const gid = 'sg-' + w + '-' + Math.round(data[data.length - 1]);
  return `<svg width="${w}" height="${h}" style="display:block;overflow:visible">
    <defs><linearGradient id="${gid}" x1="0" x2="0" y1="0" y2="1">
      <stop offset="0%" stop-color="${color}" stop-opacity="0.3"/>
      <stop offset="100%" stop-color="${color}" stop-opacity="0"/>
    </linearGradient></defs>
    <path d="${area}" fill="url(#${gid})"/>
    <path d="${d}" stroke="${color}" stroke-width="1.5" fill="none"/>
    <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="2.5" fill="${color}"/>
  </svg>`;
}

// ─── Navigation ───────────────────────────────────────────────────────────
function renderSection(section) {
  if (section === 'overview')    renderOverview();
  if (section === 'findings')    renderFindings();
  if (section === 'compliance')  renderCompliancePage();
  if (section === 'history')     renderHistory();
  if (section === 'posture')     renderPostureMap();
  if (section === 'api')         renderHealth();
  if (section === 'remediate')   refreshRemediateGate();
  if (section === 'agents')      refreshAgentsGate();
  if (section === 'report')      refreshReport();
  if (section === 'settings')    renderSettings();
}

function navigateTo(section) {
  currentSection = section;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.navlink').forEach(l => l.classList.remove('active'));
  const page = $(`page-${section}`);
  if (page) page.classList.add('active');
  const link = document.querySelector(`.navlink[data-section="${section}"]`);
  if (link) link.classList.add('active');
  const scroll = document.querySelector('.page-scroll');
  if (scroll) scroll.scrollTop = 0;
  const titles = { overview: 'Overview', assess: 'Run assessment', findings: 'Findings',
    posture: 'Posture map', compliance: 'Compliance', history: 'History', remediate: 'Remediate',
    siem: 'SIEM streaming', notifications: 'Notifications', agents: 'Agents & MCP',
    export: 'Exports', report: 'Full report', api: 'API health', settings: 'Settings' };
  const cp = $('crumb-page'); if (cp) cp.textContent = titles[section] || section;
  renderSection(section);
  document.getElementById('sidebar')?.classList.remove('open');
  document.querySelector('.sidebar-overlay')?.classList.remove('open');
}

function bindNav() {
  document.querySelectorAll('[data-section]').forEach(el => {
    el.addEventListener('click', e => {
      if (el.tagName === 'A' && el.getAttribute('href') && el.getAttribute('href') !== '#') return;
      e.preventDefault(); navigateTo(el.dataset.section);
    });
  });
}

// ─── Theme ────────────────────────────────────────────────────────────────
function initTheme() { isDark = localStorage.getItem('fi-theme') !== 'light'; applyTheme(); }
function toggleTheme() { isDark = !isDark; localStorage.setItem('fi-theme', isDark ? 'dark' : 'light'); applyTheme(); }
function applyTheme() {
  document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  const btn = $('theme-toggle');
  if (btn) btn.innerHTML = isDark
    ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`
    : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>`;
}

// ─── Overview ─────────────────────────────────────────────────────────────
function renderOverview() {
  const ringEl = $('score-ring-svg');
  if (ringEl) { ringEl.innerHTML = buildRingSVG('main'); animateRing(ringEl, SCORE.overall); }
  if ($('score-num')) $('score-num').textContent = SCORE.overall || '—';
  if ($('score-grade')) { const g = $('score-grade'); g.textContent = SCORE.grade; g.style.color = gradeColor(SCORE.grade); }

  // Previous score + delta + trend from history
  const prev = HISTORY.find(h => h.fullId !== CURRENT_ASSESSMENT?.assessmentId && h.fullId !== CURRENT_ASSESSMENT?.id);
  if ($('kpi-prev')) $('kpi-prev').textContent = prev ? prev.score : '—';
  if ($('score-delta')) {
    if (prev && typeof prev.score === 'number') {
      const d = SCORE.overall - prev.score;
      $('score-delta').innerHTML = `<span class="${d >= 0 ? 'delta-up' : 'delta-dn'}">${d >= 0 ? '▲' : '▼'} ${d >= 0 ? '+' : ''}${d} vs previous</span>`;
    } else { $('score-delta').innerHTML = ''; }
  }
  if ($('kpi-sparkline')) $('kpi-sparkline').innerHTML = sparkline(TREND.length >= 2 ? TREND : [SCORE.overall, SCORE.overall]);
  if ($('kpi-passed')) $('kpi-passed').innerHTML = `${SUMMARY.passedChecks} <em>/ ${SUMMARY.totalChecks}</em>`;
  if ($('posture-sub')) $('posture-sub').innerHTML = SUMMARY.completedAt
    ? `Latest assessment &middot; <span class="mono">${esc(fmtUTC(SUMMARY.completedAt))}</span> &middot; ${esc(SUMMARY.duration)} &middot; ${SUMMARY.totalChecks} checks`
    : 'No assessment loaded — run one from “Run assessment”.';
  if ($('ci-chip')) $('ci-chip').innerHTML = SUMMARY.critical
    ? `<span class="badge bad">✗ ${SUMMARY.critical} critical</span>`
    : `<span class="badge ok">✓ No critical findings</span>`;

  // Breakdown
  const br = $('breakdown-rows');
  if (br) {
    const rows = Object.entries(SCORE.breakdown).sort((a, b) => (b[1].score || 0) - (a[1].score || 0));
    br.innerHTML = rows.length ? rows.map(([label, v]) => {
      const c = scoreColor(v.score || 0);
      return `<div class="bd-row"><div class="bd-label">${esc(label)}</div>
        <div class="bd-track"><div class="bd-fill" style="width:${v.score || 0}%;background:${c}"></div></div>
        <div class="bd-val" style="color:${c}">${v.score || 0}</div></div>`;
    }).join('') : '<div class="empty" style="padding:12px 0">No category breakdown.</div>';
  }

  // Sev strip
  const total = SUMMARY.critical + SUMMARY.high + SUMMARY.medium + SUMMARY.low;
  if ($('sev-sub')) $('sev-sub').textContent = `${total} open · ${SUMMARY.passedChecks} passed`;
  [['critical', SUMMARY.critical], ['high', SUMMARY.high], ['medium', SUMMARY.medium], ['low', SUMMARY.low]].forEach(([s, n]) => {
    const seg = document.querySelector(`.sev-seg[data-sev="${s}"]`); if (seg) seg.style.flex = String(n);
    const cnt = $(`sev-count-${s}`); if (cnt) cnt.textContent = n;
  });

  // Compliance rail
  const rail = $('compliance-rail');
  if (rail) rail.innerHTML = Object.entries(COMPLIANCE).map(([, f]) => {
    const c = scoreColor(f.score);
    return `<div class="comp-row"><div class="comp-name">${esc(f.name)}</div>
      <div style="display:flex;align-items:center;gap:8px">
        <div class="comp-track"><div class="comp-fill" style="width:${f.score}%;background:${c}"></div></div>
        <div class="comp-pct" style="color:${c}">${f.score}%</div>
      </div></div>`;
  }).join('');

  // Attack paths
  const apCard = $('attack-paths-card');
  const ap = $('attack-paths-strip');
  if (ATTACK_PATHS.length) {
    if (apCard) apCard.style.display = '';
    if ($('attack-paths-title')) $('attack-paths-title').textContent = `${ATTACK_PATHS.length} attack path${ATTACK_PATHS.length === 1 ? '' : 's'} detected`;
    if (ap) ap.innerHTML = ATTACK_PATHS.map(p => `
      <div class="ap-card">
        <div class="ap-sev">${esc(p.sev)}</div>
        <div class="ap-title">${esc(p.title)}</div>
        <div class="ap-hops">${p.hops.map(esc).join('<span class="ap-arrow"> → </span>')}</div>
      </div>`).join('');
  } else if (apCard) {
    apCard.style.display = 'none';
  }

  // Top findings
  const tf = $('top-findings');
  if (tf) {
    const sorted = [...FINDINGS].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)).slice(0, 6);
    if ($('top-findings-sub')) $('top-findings-sub').textContent = `Sorted by severity · showing ${sorted.length} of ${FINDINGS.length}`;
    tf.innerHTML = sorted.length
      ? `<table class="findings-table"><tbody>${sorted.map(findingRow).join('')}</tbody></table>`
      : '<div class="empty">No open findings.</div>';
    bindFindingRows(tf);
  }

  renderZones();
  const nb = $('nav-badge'); if (nb) nb.textContent = FINDINGS.length ? String(FINDINGS.length) : '—';
}

function findingRow(f) {
  return `<tr data-fid="${esc(f.id)}" tabindex="0" role="button" aria-label="View ${esc(f.checkTitle)}">
    <td style="width:105px"><span class="sev-badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
    <td><div class="finding-title">${esc(f.checkTitle)}</div>
        <div class="finding-meta">${esc(f.checkId)} · ${esc(f.service)}</div></td>
    <td style="font-size:12px;color:var(--fg-3)">${esc(f.zone)}</td>
    <td><span class="badge bad">FAIL</span><span class="row-chevron">›</span></td>
  </tr>`;
}

function bindFindingRows(container) {
  if (!container) return;
  container.querySelectorAll('tr[data-fid]').forEach(tr => {
    const open = () => openFindingDrawer(tr.dataset.fid);
    tr.onclick = open;
    tr.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } };
  });
}

function renderZones() {
  const el = $('zone-grid'); if (!el) return;
  if ($('zones-sub')) $('zones-sub').textContent = `Posture across ${ZONES.length} Cloudflare zone${ZONES.length === 1 ? '' : 's'}`;
  if (!ZONES.length) { el.innerHTML = '<div class="empty">No zones in this assessment.</div>'; return; }
  const byZone = {};
  FINDINGS.forEach(f => {
    if (!byZone[f.zone]) byZone[f.zone] = { critical: 0, high: 0, medium: 0, low: 0 };
    if (byZone[f.zone][f.severity] !== undefined) byZone[f.zone][f.severity]++;
  });
  el.innerHTML = ZONES.map(z => {
    const sev = byZone[z.name] || { critical: 0, high: 0, medium: 0, low: 0 };
    const score = Math.max(0, Math.min(100, Math.round(100 - sev.critical * 15 - sev.high * 6 - sev.medium * 2 - sev.low * 0.5)));
    const color = scoreColor(score);
    const chips = [];
    if (sev.critical > 0) chips.push(`<span class="zone-chip crit">${sev.critical}C</span>`);
    if (sev.high > 0)     chips.push(`<span class="zone-chip high">${sev.high}H</span>`);
    if (sev.medium > 0)   chips.push(`<span class="zone-chip med">${sev.medium}M</span>`);
    if (sev.low > 0)      chips.push(`<span class="zone-chip low">${sev.low}L</span>`);
    if (!chips.length)    chips.push(`<span class="zone-chip ok">clean</span>`);
    return `<div class="zone-card">
      <div class="zone-card-head"><div class="zone-name" title="${esc(z.name)}">${esc(z.name)}</div><div class="zone-plan">${esc(z.plan)}</div></div>
      <div class="zone-score-row"><span class="zone-scorenum" style="color:${color}">${score}</span><span class="zone-scoreout">/100</span></div>
      <div class="zone-bar"><div class="zone-bar-fill" style="width:${score}%;background:${color}"></div></div>
      <div class="zone-sev">${chips.join('')}</div>
    </div>`;
  }).join('');
}

// ─── Findings ─────────────────────────────────────────────────────────────
function renderFindings() {
  const el = $('all-findings'); if (!el) return;
  const q = currentSearch.toLowerCase();
  const filtered = FINDINGS.filter(f => {
    if (currentFilter !== 'all' && f.severity !== currentFilter) return false;
    if (q) return f.checkTitle.toLowerCase().includes(q) || f.checkId.toLowerCase().includes(q) || f.zone.toLowerCase().includes(q);
    return true;
  });
  const sorted = [...filtered].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const cnt = $('findings-count'); if (cnt) cnt.textContent = `${sorted.length} findings`;
  if (!sorted.length) { el.innerHTML = '<div class="empty">No findings match this filter.</div>'; return; }
  el.innerHTML = `<table class="findings-table">
    <thead><tr>
      <th style="width:110px">Severity</th><th>Check</th>
      <th style="width:160px">Zone</th><th style="width:70px">Status</th>
    </tr></thead>
    <tbody>${sorted.map(findingRow).join('')}</tbody>
  </table>`;
  bindFindingRows(el);
}

// ─── Finding detail drawer ──────────────────────────────────────────────────
function kvBlock(obj) {
  const entries = Object.entries(obj || {}).filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (!entries.length) return '';
  return entries.map(([k, v]) => `<div class="fd-oe"><span class="fd-oe-key">${esc(k)}</span><span class="fd-oe-val">${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</span></div>`).join('');
}

function openFindingDrawer(id) {
  const f = FINDINGS_FULL[id];
  const drawer = $('finding-drawer'), scrim = $('finding-scrim');
  if (!f || !drawer) return;
  const title = $('finding-drawer-title'); if (title) title.textContent = f.checkTitle || f.checkId || 'Finding';
  const sev = (f.severity || 'low');
  const ev = f.evidence || {};
  const resource = f.metadata?.resourceName || f.resourceName || f.resourceId || '—';
  const counts = ev.counts || {};
  const source = ev.source || {};
  const entities = Array.isArray(ev.affectedEntities) ? ev.affectedEntities : [];
  const compliance = Array.isArray(f.compliance) ? f.compliance : [];
  const sections = [];

  sections.push(`<div class="fd-meta">
    <span class="sev-badge ${esc(sev)}">${esc(sev)}</span>
    <span class="badge ${f.status === 'PASS' ? 'ok' : 'bad'}">${esc(f.status || 'FAIL')}</span>
    <span class="fd-mono">${esc(f.checkId || '')}</span>
  </div>
  <div class="fd-meta" style="margin-top:6px">
    <span class="fd-mono">${esc(f.service || '—')}</span><span class="crumb-sep">·</span>
    <span class="fd-mono" title="${esc(resource)}">${esc(resource)}</span>
  </div>`);

  if (f.description) sections.push(`<div class="fd-field"><div class="drawer-section">Description</div><div class="fd-value">${esc(f.description)}</div></div>`);

  const remediation = f.remediation || '';
  if (remediation) sections.push(`<div class="fd-field"><div class="drawer-section">Remediation</div><div class="fd-callout remediation">${esc(remediation)}</div></div>`);

  const oe = [];
  if (ev.observed != null && ev.observed !== '') oe.push(['Observed', ev.observed]);
  if (ev.expected != null && ev.expected !== '') oe.push(['Expected', ev.expected]);
  if (ev.summary || oe.length || ev.reviewGuidance) {
    sections.push(`<div class="fd-field"><div class="drawer-section">Evidence</div>
      ${ev.summary ? `<div class="fd-value" style="margin-bottom:8px">${esc(ev.summary)}</div>` : ''}
      ${oe.length ? `<div class="fd-oe">${oe.map(([k, v]) => `<span class="fd-oe-key">${esc(k)}</span><span class="fd-oe-val">${esc(v)}</span>`).join('')}</div>` : ''}
      ${ev.reviewGuidance ? `<div class="fd-value" style="margin-top:8px;color:var(--fg-3)"><strong style="color:var(--fg-2)">Review guidance:</strong> ${esc(ev.reviewGuidance)}</div>` : ''}
    </div>`);
  }

  const countsHtml = kvBlock(counts);
  if (countsHtml) sections.push(`<div class="fd-field"><div class="drawer-section">Decision data</div>${countsHtml}</div>`);

  const sourceHtml = kvBlock(source);
  if (sourceHtml) sections.push(`<div class="fd-field"><div class="drawer-section">Evidence source</div>${sourceHtml}</div>`);

  if (entities.length) {
    sections.push(`<div class="fd-field"><div class="drawer-section">Affected entities (${entities.length})</div>
      ${entities.slice(0, 12).map(e => {
        const primary = e.name || e.email || e.id || e.action || JSON.stringify(e);
        const secondary = [e.email && e.email !== primary ? e.email : null, Array.isArray(e.roles) ? e.roles.join(', ') : null, e.status].filter(Boolean).join(' · ');
        return `<div class="fd-entity"><strong>${esc(primary)}</strong>${secondary ? ` <span style="color:var(--fg-3)">${esc(secondary)}</span>` : ''}</div>`;
      }).join('')}</div>`);
  }

  if (compliance.length) {
    sections.push(`<div class="fd-field"><div class="drawer-section">Compliance</div>
      <div class="fd-chips">${compliance.map(c => `<span class="badge info">${esc(c)}</span>`).join('')}</div></div>`);
  }

  sections.push(`<div class="fd-field"><div class="drawer-section">Cloudflare reference</div>
    <a class="fd-doclink" href="${esc(cfDocLink(f.service))}" target="_blank" rel="noopener">developers.cloudflare.com — ${esc(f.service || 'docs')} ↗</a></div>`);

  const body = $('finding-drawer-body'); if (body) body.innerHTML = sections.join('');
  drawer.classList.add('open'); drawer.setAttribute('aria-hidden', 'false');
  if (scrim) scrim.classList.add('open');
}

function closeFindingDrawer() {
  $('finding-drawer')?.classList.remove('open');
  $('finding-drawer')?.setAttribute('aria-hidden', 'true');
  $('finding-scrim')?.classList.remove('open');
}

// ─── Compliance page ──────────────────────────────────────────────────────
function renderCompliancePage() {
  const el = $('compliance-cards'); if (!el) return;
  const iconMap = {
    cis:  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    soc2: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
    pci:  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg>`,
    nist: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M5 21V9l7-5 7 5v12"/></svg>`,
  };
  el.innerHTML = Object.entries(COMPLIANCE).map(([key, f]) => {
    const c = scoreColor(f.score);
    return `<div class="compliance-card">
      <div class="comp-card-head">
        <div class="comp-icon">${iconMap[key] || ''}</div>
        <div><div class="comp-card-name">${esc(f.name)}</div><div class="comp-card-ver">${esc(f.ver)}</div></div>
      </div>
      <div class="comp-score-wrap">
        ${miniRing(f.score, c)}
        <div class="comp-stats">
          <div class="comp-stat"><span>Controls passed</span><span class="comp-stat-val" style="color:${c}">${f.passed} / ${f.total}</span></div>
          <div class="comp-stat"><span>Coverage</span><span class="comp-stat-val">${f.score}%</span></div>
          <div class="comp-stat" style="font-size:11px;color:var(--fg-3)"><span>Key controls</span><span>${esc(f.controls)}</span></div>
        </div>
      </div>
      <a href="#" class="btn btn-ghost btn-sm" data-section="findings" style="just-content:center;width:100%">View findings →</a>
    </div>`;
  }).join('');
  // Newly-rendered nav links need binding
  el.querySelectorAll('[data-section]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); navigateTo(a.dataset.section); }));
}

// ─── History ──────────────────────────────────────────────────────────────
function renderHistory() {
  const el = $('history-list'); if (!el) return;
  if (!HISTORY.length) { el.innerHTML = '<div class="empty">No assessment history found.</div>'; return; }
  el.innerHTML = `<div class="history-row hdr">
    <span>Date</span><span>Score</span><span>Grade</span><span>Duration</span><span>Trend</span><span>Zones · Checks</span>
  </div>
  ${HISTORY.map((h, i) => {
    const c = gradeColor(h.grade);
    return `<div class="history-row" data-load-id="${esc(h.fullId)}" style="${i === 0 ? 'background:var(--flare-muted)' : ''}">
      <span class="history-date">${esc(h.date)}</span>
      <span class="history-score" style="color:${c}">${h.score}</span>
      <span class="history-score" style="font-size:13px;color:${c}">${h.grade}</span>
      <span class="muted mono" style="font-size:12px">${esc(h.duration)}</span>
      <span>${sparkline(TREND.length > i + 1 ? TREND.slice(0, TREND.length - i) : TREND, 80, 24)}</span>
      <span class="muted mono" style="font-size:12px">${h.zones !== '' ? h.zones + 'z' : '—'}${h.checks !== '' ? ' · ' + h.checks + 'c' : ''}</span>
    </div>`;
  }).join('')}`;
  el.querySelectorAll('[data-load-id]').forEach(row => row.addEventListener('click', () => loadAssessmentById(row.dataset.loadId)));
}

async function loadAssessmentById(id) {
  if (!id) return;
  try {
    const data = await apiGet(`/api/assessments/${id}`);
    applyAssessment(data.assessment);
    showToast('Assessment loaded.', 'success');
    pmBound = false;
    navigateTo('overview');
  } catch (err) { showToast(err.message, 'error'); }
}

// ─── Posture Map (driven by the live resource graph) ────────────────────────
function ns(tag) { return document.createElementNS('http://www.w3.org/2000/svg', tag); }

function buildFallbackGraph() {
  const nodes = [{ id: 'internet', type: 'internet', label: 'Internet', severity: 'pass' },
    { id: 'account', type: 'account', label: ACCOUNT.name || 'Account', severity: 'pass' }];
  const edges = [{ from: 'internet', to: 'account' }];
  ZONES.forEach((z, i) => { nodes.push({ id: 'z' + i, type: 'zone', label: z.name, severity: 'pass' }); edges.push({ from: 'account', to: 'z' + i }); });
  return { nodes, edges };
}

function nodeSeverity(n) {
  if (n.type === 'internet') return 'ok';
  let finds = [];
  if (n.type === 'zone') finds = FINDINGS.filter(f => f.zone === n.label);
  else if (n.type === 'account') finds = FINDINGS.filter(f => f.zone === 'account');
  else finds = (n.findingIds || []).map(id => FINDINGS_BY_ID[id]).filter(Boolean);
  if (finds.some(f => f.severity === 'critical')) return 'critical';
  if (finds.some(f => f.severity === 'high')) return 'high';
  if (finds.some(f => f.severity === 'medium')) return 'medium';
  if (finds.length) return 'low';
  return 'ok';
}

function renderPostureMap() {
  const svg = $('pm-svg'); if (!svg) return;
  const W = 1000, H = 580;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  const graph = (GRAPH && GRAPH.nodes && GRAPH.nodes.length) ? GRAPH : buildFallbackGraph();
  const rawNodes = graph.nodes;
  const rawEdges = graph.edges || [];

  // Layered layout by node type.
  const typeOrder = ['internet', 'account', 'zone'];
  const colsByType = {};
  const colOrder = [];
  rawNodes.forEach(n => { if (!(n.type in colsByType)) { colsByType[n.type] = []; } });
  Object.keys(colsByType).sort((a, b) => {
    const ia = typeOrder.indexOf(a), ib = typeOrder.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  }).forEach(t => colOrder.push(t));
  rawNodes.forEach(n => colsByType[n.type].push(n));

  const pos = {};
  const ncols = colOrder.length;
  colOrder.forEach((t, ci) => {
    const col = colsByType[t];
    const x = ncols === 1 ? W / 2 : 90 + ci * ((W - 180) / (ncols - 1));
    col.forEach((n, ri) => {
      const k = col.length;
      const y = k === 1 ? H / 2 : 55 + ri * ((H - 110) / (k - 1));
      pos[n.id] = { x, y, node: n };
    });
  });

  const sevColor = { critical: 'oklch(65% 0.21 25)', high: 'oklch(70% 0.19 40)', medium: 'oklch(80% 0.14 85)', low: 'oklch(72% 0.15 155)', ok: 'oklch(72% 0.15 155)' };
  const bezier = (a, b) => { const mx = (a.x + b.x) / 2; return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`; };

  const g = ns('g'); g.id = 'pm-root';
  const eG = ns('g'); eG.id = 'pm-edges';
  const apG = ns('g'); apG.id = 'pm-ap-edges'; apG.style.display = showAttackPaths ? '' : 'none';

  rawEdges.forEach(e => {
    const a = pos[e.from], b = pos[e.to]; if (!a || !b) return;
    const path = ns('path');
    path.setAttribute('d', bezier(a, b));
    path.setAttribute('stroke', 'var(--line-2)');
    path.setAttribute('stroke-width', '1.5');
    path.setAttribute('fill', 'none');
    eG.appendChild(path);
  });

  // Attack-path edges from real paths (consecutive node hops).
  PATHS.forEach(p => {
    const ids = Array.isArray(p.nodes) ? p.nodes : (Array.isArray(p.path) ? p.path : []);
    for (let i = 0; i < ids.length - 1; i++) {
      const a = pos[ids[i]], b = pos[ids[i + 1]]; if (!a || !b) continue;
      const path = ns('path');
      path.setAttribute('d', bezier(a, b));
      path.setAttribute('stroke', 'oklch(65% 0.21 25)');
      path.setAttribute('stroke-width', '2.5');
      path.setAttribute('fill', 'none');
      path.setAttribute('stroke-dasharray', '7 4');
      path.style.animation = 'pm-flow 1.5s linear infinite';
      apG.appendChild(path);
    }
  });

  g.appendChild(eG); g.appendChild(apG);

  const glyphs = { internet: 'I', account: 'A', zone: 'Z', service: 'S' };
  Object.values(pos).forEach(({ x, y, node }) => {
    const sev = nodeSeverity(node);
    const ng = ns('g'); ng.setAttribute('class', 'pm-node');
    ng.setAttribute('transform', `translate(${x},${y})`);
    ng.setAttribute('tabindex', '0'); ng.setAttribute('role', 'button'); ng.setAttribute('aria-label', node.label);

    const bg = ns('circle'); bg.setAttribute('r', '22'); bg.setAttribute('fill', 'var(--bg-2)');
    bg.setAttribute('stroke', 'var(--line-2)'); bg.setAttribute('stroke-width', '1'); ng.appendChild(bg);

    const ring = ns('circle'); ring.setAttribute('r', '25'); ring.setAttribute('fill', 'none');
    ring.setAttribute('stroke', sevColor[sev] || sevColor.ok); ring.setAttribute('stroke-width', '2.5'); ng.appendChild(ring);

    const txt = ns('text'); txt.setAttribute('text-anchor', 'middle'); txt.setAttribute('y', '5');
    txt.setAttribute('font-size', '12'); txt.setAttribute('fill', sevColor[sev] || 'var(--fg-3)');
    txt.setAttribute('font-family', "'Geist Mono',monospace"); txt.setAttribute('font-weight', '700');
    txt.textContent = glyphs[node.type] || (node.type ? node.type[0].toUpperCase() : '·'); ng.appendChild(txt);

    const lbl = ns('text'); lbl.setAttribute('y', '38'); lbl.setAttribute('text-anchor', 'middle');
    lbl.setAttribute('fill', 'var(--fg-2)'); lbl.setAttribute('font-family', "'Geist Mono',monospace");
    lbl.setAttribute('font-size', '10'); lbl.setAttribute('pointer-events', 'none');
    const short = node.label && node.label.length > 13 ? node.label.slice(0, 12) + '…' : (node.label || '');
    lbl.textContent = short; ng.appendChild(lbl);

    ng.addEventListener('click', () => openDrawer(node, sev));
    ng.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDrawer(node, sev); } });
    g.appendChild(ng);
  });

  svg.innerHTML = ''; svg.appendChild(g);

  // Pan/zoom
  let drag = false, lx = 0, ly = 0, tx = 0, ty = 0, sc = 0.88;
  const root = $('pm-root');
  const upT = () => { if (root) root.setAttribute('transform', `translate(${tx},${ty}) scale(${sc})`); };
  upT();
  if (!pmBound) {
    pmBound = true;
    svg.addEventListener('mousedown', e => { if (e.target.closest('.pm-node')) return; drag = true; lx = e.clientX; ly = e.clientY; });
    window.addEventListener('mousemove', e => { if (!drag) return; tx += e.clientX - lx; ty += e.clientY - ly; lx = e.clientX; ly = e.clientY; upT(); });
    window.addEventListener('mouseup', () => { drag = false; });
    svg.addEventListener('wheel', e => { e.preventDefault(); sc = Math.max(0.3, Math.min(2.5, sc * (e.deltaY < 0 ? 1.12 : 0.88))); upT(); }, { passive: false });
    $('pm-zoom-in')?.addEventListener('click', () => { sc = Math.min(2.5, sc * 1.2); upT(); });
    $('pm-zoom-out')?.addEventListener('click', () => { sc = Math.max(0.3, sc / 1.2); upT(); });
    $('pm-fit')?.addEventListener('click', () => { sc = 0.88; tx = 0; ty = 0; upT(); });
    $('pm-ap-toggle')?.addEventListener('click', () => {
      showAttackPaths = !showAttackPaths;
      const el = $('pm-ap-edges'); if (el) el.style.display = showAttackPaths ? '' : 'none';
      $('pm-ap-toggle')?.classList.toggle('btn-primary', showAttackPaths);
    });
  }
}

function openDrawer(node, sev) {
  const drawer = $('node-drawer'); if (!drawer) return;
  const title = drawer.querySelector('.drawer-title'); if (title) title.textContent = node.label;
  const body = drawer.querySelector('.drawer-body'); if (!body) return;
  let finds = [];
  if (node.type === 'zone') finds = FINDINGS.filter(f => f.zone === node.label);
  else if (node.type === 'account') finds = FINDINGS.filter(f => f.zone === 'account');
  else finds = (node.findingIds || []).map(id => FINDINGS_BY_ID[id]).filter(Boolean);
  const sc = { critical: 'oklch(65% 0.21 25)', high: 'oklch(70% 0.19 40)', medium: 'oklch(80% 0.14 85)', low: 'oklch(72% 0.15 155)', ok: 'oklch(72% 0.15 155)' };
  body.innerHTML = `
    <div>
      <div class="drawer-section">Resource</div>
      <div class="kv-pair"><span class="kv-key">Type</span><span class="kv-val">${esc(node.type)}</span></div>
      <div class="kv-pair"><span class="kv-key">Risk</span><span class="kv-val" style="color:${sc[sev] || 'var(--fg-3)'}">${esc(sev === 'ok' ? 'clean' : sev)}</span></div>
    </div>
    <div>
      <div class="drawer-section">Findings (${finds.length})</div>
      ${finds.length ? finds.slice(0, 8).map(f => `<div class="kv-pair">
        <span class="kv-key mono" style="font-size:11px">${esc(f.checkId)}</span>
        <span class="sev-badge ${esc(f.severity)}" style="font-size:10px">${esc(f.severity)}</span>
      </div>`).join('') : `<div class="muted" style="padding:8px 0;font-size:12px">No findings.</div>`}
    </div>`;
  drawer.classList.add('open');
}

// ─── API Health ───────────────────────────────────────────────────────────
async function renderHealth() {
  const el = $('health-grid'); if (!el) return;
  el.innerHTML = '<div class="health-row"><span class="health-key">Status</span><span class="health-val">Loading…</span></div>';
  try {
    const d = await apiGet('/api/health');
    if ($('api-status-badge')) {
      const b = $('api-status-badge');
      b.textContent = d.ok ? 'Healthy' : 'Degraded';
      b.className = `badge ${d.ok ? 'ok' : 'bad'}`;
    }
    const up = d.uptime ? (d.uptime > 3600 ? `${Math.floor(d.uptime / 3600)}h ${Math.floor((d.uptime % 3600) / 60)}m` : `${Math.floor(d.uptime / 60)}m ${Math.floor(d.uptime % 60)}s`) : '—';
    const rows = [
      ['Status', d.ok ? '✓ Healthy' : '✗ Degraded'],
      ['Server version', d.version || 'unknown'],
      ['Uptime', up],
      ['Authentication', d.auth === 'api-key' ? 'API key enabled' : 'None'],
      ['Storage', d.storage?.ready ? '✓ Ready' : '✗ ' + (d.storage?.error || 'error')],
      ['Last assessment', d.lastAssessmentAt ? fmtUTC(d.lastAssessmentAt) : 'None'],
      ['Remediation gate', d.remediation === 'enabled' ? 'ENABLED' : 'DISABLED — read-only'],
      ['MCP server', 'Ready (stdio)'],
    ];
    el.innerHTML = rows.map(([k, v]) => `<div class="health-row"><span class="health-key">${esc(k)}</span><span class="health-val">${esc(v)}</span></div>`).join('');
  } catch (err) {
    el.innerHTML = `<div class="health-row"><span class="health-key">Error</span><span class="health-val" style="color:var(--crit)">${esc(err.message)}</span></div>`;
  }
}

// ─── Run Assessment ───────────────────────────────────────────────────────
function initAssessForm() {
  const form = $('assess-form'); if (!form) return;
  form.addEventListener('submit', e => { e.preventDefault(); runAssessment(); });
  $('btn-load-latest')?.addEventListener('click', async () => {
    showToast('Loading latest assessment…', 'info');
    await loadAll({ navigate: true });
  });
}

let progressTimer = null;
function startProgress(stages) {
  const wrap = $('progress-wrap'), fill = $('progress-fill'), pctEl = $('progress-pct'), label = $('progress-label-text');
  if (!wrap) return;
  wrap.style.display = 'flex'; let pct = 0, si = 0;
  if (label) label.textContent = stages[0];
  if (progressTimer) clearInterval(progressTimer);
  progressTimer = setInterval(() => {
    pct = Math.min(pct + Math.random() * 4, 94);
    if (fill) fill.style.width = pct.toFixed(0) + '%';
    if (pctEl) pctEl.textContent = pct.toFixed(0) + '%';
    if (label && Math.random() > 0.7 && si < stages.length - 1) { si++; label.textContent = stages[si]; }
  }, 450);
}
function stopProgress(finalLabel) {
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
  const fill = $('progress-fill'), pctEl = $('progress-pct'), label = $('progress-label-text');
  if (fill) fill.style.width = '100%'; if (pctEl) pctEl.textContent = '100%';
  if (label && finalLabel) label.textContent = finalLabel;
  setTimeout(() => { const w = $('progress-wrap'); if (w) w.style.display = 'none'; }, 1200);
}

async function runAssessment() {
  const token = ($('assess-token')?.value || '').trim();
  const zones = ($('assess-zones')?.value || '').trim();
  if (token.length < 10) { showToast('Enter a valid Cloudflare API token.', 'error'); return; }
  const btn = $('assess-submit'); if (btn) btn.disabled = true;
  setFootStatus('busy', 'Assessment running');
  startProgress(['Authenticating…', 'Fetching zones…', 'Running DNS checks…', 'Running WAF checks…', 'Running SSL/TLS checks…', 'Detecting attack paths…', 'Calculating scores…']);
  try {
    const body = { token };
    if (zones) body.zones = zones;
    const data = await apiPost('/api/assess', body);
    applyAssessment(data.assessment);
    await Promise.all([
      apiGet('/api/assessments').then(d => applyHistory(Array.isArray(d) ? d : (d.assessments || []))).catch(() => {}),
      Promise.all(COMPLIANCE_FRAMEWORKS.map(fw => apiGet(`/api/compliance/${fw}`).catch(() => null))).then(applyCompliance).catch(() => {}),
      apiGet('/api/posture/graph').then(applyGraph).catch(() => {}),
    ]);
    pmBound = false;
    stopProgress('Assessment complete!');
    setFootStatus('ready', SUMMARY.critical ? 'Assessment ready' : 'All checks passing');
    showToast(`Assessment complete — Score: ${SCORE.overall} (${SCORE.grade})`, 'success');
    navigateTo('overview');
  } catch (err) {
    stopProgress('Assessment failed');
    setFootStatus('error', 'Error');
    showToast(err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ─── Full report ────────────────────────────────────────────────────────────
let reportLoaded = false;
async function refreshReport() {
  const frame = $('report-frame'), empty = $('report-empty');
  if (!frame) return;
  if (reportLoaded && !CURRENT_ASSESSMENT) return;
  if (empty) empty.textContent = 'Loading report…';
  try {
    const res = await fetch('/api/download/html');
    if (!res.ok) throw new Error('No assessment available yet.');
    const html = await res.text();
    if (!html || html.length < 100) throw new Error('Report is empty.');
    frame.srcdoc = html;
    frame.style.display = 'block';
    if (empty) empty.style.display = 'none';
    reportLoaded = true;
  } catch (err) {
    frame.style.display = 'none';
    if (empty) { empty.style.display = 'block'; empty.textContent = err.message; }
  }
}

// ─── Remediation ──────────────────────────────────────────────────────────
let remediatePlan = null;
const RISK_BADGE = { low: 'background:var(--low-soft);color:var(--low)', medium: 'background:var(--med-soft);color:var(--med)', high: 'background:var(--crit-soft);color:var(--crit)' };
function fmtVal(v) {
  if (v === null || v === undefined) return '∅';
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch { return String(v); } }
  return String(v);
}
function remAi() {
  const provider = $('rem-ai')?.value || 'none';
  const model = ($('rem-model')?.value || '').trim();
  const ai = { provider };
  if (model) ai.model = model;
  return ai;
}
async function refreshRemediateGate() {
  const badge = $('rem-gate-badge');
  if (badge) {
    badge.textContent = ALLOW_REMEDIATION ? 'Apply enabled' : 'Apply disabled (read-only)';
    badge.className = `badge ${ALLOW_REMEDIATION ? 'ok' : 'warn'}`;
  }
  syncApplyButton();
  loadRemediateBackups();
  // Default the AI planner controls from saved Settings (so a configured
  // provider/model is actually used unless the operator overrides here).
  try {
    const d = await apiGet('/api/settings');
    const p = d.settings?.aiProvider?.value, m = d.settings?.aiModel?.value;
    const sel = $('rem-ai');
    if (sel && p && !sel.dataset.touched && [...sel.options].some(o => o.value === p)) sel.value = p;
    const mi = $('rem-model');
    if (mi && m && !mi.value) mi.value = m;
  } catch (_) { /* settings optional */ }
}
function syncApplyButton() {
  const btn = $('rem-apply-btn'); if (!btn) return;
  const hasItems = remediatePlan && remediatePlan.items && remediatePlan.items.length > 0;
  btn.disabled = !(ALLOW_REMEDIATION && hasItems);
  btn.title = ALLOW_REMEDIATION ? '' : 'Set FLAREINSPECT_ALLOW_REMEDIATION=true on the server to enable apply.';
}
async function buildRemediatePlan() {
  const token = ($('rem-token')?.value || '').trim();
  if (token.length < 10) { showToast('Enter a valid Cloudflare API token.', 'error'); return; }
  const body = { token, zones: $('rem-zones')?.value || '', ai: remAi() };
  if (CURRENT_ASSESSMENT?.assessmentId) body.assessmentId = CURRENT_ASSESSMENT.assessmentId;
  const btn = $('rem-plan-btn'); if (btn) { btn.disabled = true; btn.textContent = 'Building plan…'; }
  try {
    const data = await apiPost('/api/remediate/plan', body);
    remediatePlan = data.plan; ALLOW_REMEDIATION = data.allowApply;
    renderRemediatePlan();
    showToast('Plan ready (dry-run — nothing changed).', 'success');
  } catch (err) { showToast(err.message, 'error'); }
  finally { if (btn) { btn.disabled = false; btn.textContent = 'Build plan (dry-run)'; } }
}
function renderRemediatePlan() {
  const card = $('rem-plan-card'), body = $('rem-plan-body'), sub = $('rem-plan-sub');
  const items = remediatePlan?.items || [];
  if (card) card.style.display = '';
  if (sub) sub.textContent = remediatePlan?.ai?.used ? `AI planner: ${remediatePlan.ai.provider}` : 'Rules-only ordering';
  if (body) body.innerHTML = items.length ? items.map((it, i) => `
    <label class="finding-row-rem" style="display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center;cursor:pointer;padding:10px 0;border-bottom:1px solid var(--line)">
      <input type="checkbox" class="rem-check" data-check="${esc(it.checkId)}" data-i="${i}" checked />
      <div>
        <div style="font-weight:600">${esc(it.checkId)} · ${esc(it.title || '')}</div>
        <div style="font-size:12px;color:var(--fg-3)">${esc(it.resourceName || it.resourceId || '')} · ${esc(it.setting)}: <code class="mono">${esc(fmtVal(it.valueBefore))}</code> → <code class="mono">${esc(fmtVal(it.valueProposed))}</code></div>
        ${it.aiRationale ? `<div style="font-size:12px;color:var(--fg-4);margin-top:2px">${esc(it.aiRationale)}</div>` : ''}
      </div>
      <span class="badge" style="${RISK_BADGE[it.risk] || ''}">${esc((it.risk || '').toUpperCase())}</span>
    </label>`).join('') : '<div class="empty">No automatically remediable findings.</div>';

  const manualCard = $('rem-manual-card'), manualBody = $('rem-manual-body');
  const manual = remediatePlan?.manualItems || [];
  if (manual.length && manualCard && manualBody) {
    manualCard.style.display = '';
    manualBody.innerHTML = manual.map(m => `<div style="padding:8px 0;border-bottom:1px solid var(--line)">
      <div><span class="sev-badge ${esc((m.severity || 'low'))}">${esc((m.severity || '').toUpperCase())}</span> <strong style="margin-left:6px">${esc(m.checkId)}</strong> ${esc(m.checkTitle || '')}</div>
      ${m.remediation ? `<div style="font-size:12px;color:var(--fg-3);margin-top:2px">${esc(m.remediation)}</div>` : ''}
    </div>`).join('');
  } else if (manualCard) { manualCard.style.display = 'none'; }
  syncApplyButton();
}
async function applyRemediation() {
  if (!ALLOW_REMEDIATION) { showToast('Apply is disabled on this server.', 'error'); return; }
  const token = ($('rem-token')?.value || '').trim();
  if (token.length < 10) { showToast('Enter a valid Cloudflare API token.', 'error'); return; }
  const checkIds = Array.from(new Set(Array.from(document.querySelectorAll('.rem-check:checked')).map(el => el.dataset.check)));
  if (!checkIds.length) { showToast('Select at least one change.', 'error'); return; }
  if (!confirm(`Apply ${checkIds.length} change type(s) to live Cloudflare config? A backup is written first.`)) return;
  const body = { token, checkIds, force: $('rem-force')?.checked || false, ai: remAi() };
  if (CURRENT_ASSESSMENT?.assessmentId) body.assessmentId = CURRENT_ASSESSMENT.assessmentId;
  const btn = $('rem-apply-btn'); if (btn) { btn.disabled = true; btn.textContent = 'Applying…'; }
  try {
    const data = await apiPost('/api/remediate/apply', body);
    const applied = data.applied || [];
    const failed = applied.filter(r => r.error).length;
    showToast(failed ? `Applied with ${failed} failure(s). Backup: ${data.bundleFile}` : `Applied ${applied.length} change(s). Backup: ${data.bundleFile}`, failed ? 'error' : 'success');
    loadRemediateBackups();
  } catch (err) { showToast(err.message, 'error'); }
  finally { if (btn) { btn.textContent = 'Apply selected'; } syncApplyButton(); }
}
async function loadRemediateBackups() {
  const body = $('rem-backups-body'); if (!body) return;
  try {
    const data = await apiGet('/api/remediate/backups');
    const backups = (data.backups || []).filter(b => b.phase === 'complete');
    if (!backups.length) { body.innerHTML = '<div class="empty">No backups yet. Build a plan and apply it to create a backup.</div>'; return; }
    body.innerHTML = backups.map(b => `<div style="display:grid;grid-template-columns:1fr auto;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)">
      <div><div style="font-weight:600">${esc(b.accountName || b.assessmentId || b.file)}</div>
      <div style="font-size:12px;color:var(--fg-3)">${esc(new Date(b.createdAt).toLocaleString())} · ${b.appliedCount}/${b.entryCount} applied</div></div>
      <button class="btn btn-sm" type="button" data-rollback="${esc(b.file)}">Rollback</button>
    </div>`).join('');
    body.querySelectorAll('[data-rollback]').forEach(btn => btn.addEventListener('click', () => rollbackRemediation(btn.dataset.rollback)));
  } catch { body.innerHTML = '<div class="empty" style="color:var(--crit)">Failed to load backups.</div>'; }
}
async function rollbackRemediation(bundleFile) {
  if (!ALLOW_REMEDIATION) { showToast('Rollback is disabled on this server.', 'error'); return; }
  const token = ($('rem-token')?.value || '').trim();
  if (token.length < 10) { showToast('Enter your Cloudflare API token above first.', 'error'); return; }
  if (!confirm(`Roll back all applied changes in ${bundleFile}?`)) return;
  try {
    const data = await apiPost('/api/remediate/rollback', { token, bundleFile });
    const failed = (data.results || []).filter(r => r.error).length;
    showToast(failed ? `Rollback completed with ${failed} failure(s).` : 'Rollback completed.', failed ? 'error' : 'success');
  } catch (err) { showToast(err.message, 'error'); }
}

// ─── SIEM ───────────────────────────────────────────────────────────────────
function integrationResult(el, data, { dryRun } = {}) {
  if (!el) return;
  const ok = data.ok !== false;
  const lines = [];
  const fmt = (label, r) => r ? `${label}: ${r.ok === false ? '✗' : '✓'} ${r.count != null ? r.count + ' docs' : ''}${r.error ? ' — ' + esc(r.error) : ''}` : null;
  if (data.elastic) lines.push(fmt('Elasticsearch', data.elastic));
  if (data.splunk) lines.push(fmt('Splunk', data.splunk));
  if (data.target === 'file' && data.dir) lines.push(`Files written to ${esc(data.dir)} (${data.counts?.ecs ?? 0} ECS, ${data.counts?.hec ?? 0} HEC)`);
  el.innerHTML = `<div style="margin-top:10px"><span class="badge ${ok ? 'ok' : 'bad'}">${ok ? (dryRun ? 'Dry run OK' : 'Shipped') : 'Failed'}</span>
    <div style="margin-top:8px;font-size:13px;color:var(--fg-2)">${lines.filter(Boolean).map(l => `<div>${l}</div>`).join('') || 'Done.'}</div></div>`;
}
async function shipSiem() {
  const target = $('siem-target')?.value || 'all';
  const dryRun = $('siem-dryrun')?.checked ?? true;
  const body = { target, dryRun };
  if (target === 'file') body.outDir = ($('siem-outdir')?.value || '').trim() || undefined;
  if (CURRENT_ASSESSMENT?.assessmentId) body.assessmentId = CURRENT_ASSESSMENT.assessmentId;
  const btn = $('siem-ship-btn'); if (btn) { btn.disabled = true; btn.textContent = 'Shipping…'; }
  try {
    const data = await apiPost('/api/integrations/ship', body);
    integrationResult($('siem-result'), data, { dryRun });
    showToast(dryRun ? 'Dry run complete.' : 'Findings shipped.', data.ok === false ? 'error' : 'success');
  } catch (err) {
    showToast(err.message, 'error');
    if ($('siem-result')) $('siem-result').innerHTML = `<div style="margin-top:10px"><span class="badge bad">Failed</span><div style="margin-top:8px;font-size:13px;color:var(--crit)">${esc(err.message)}</div></div>`;
  } finally { if (btn) { btn.disabled = false; btn.textContent = 'Ship now'; } }
}
async function downloadEcsTemplate() {
  try {
    const tpl = await apiGet('/api/integrations/template/elastic');
    const blob = new Blob([JSON.stringify(tpl, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'flareinspect-ecs-index-template.json';
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    showToast('ECS index template downloaded.', 'success');
  } catch (err) { showToast(err.message, 'error'); }
}

// ─── Notifications ────────────────────────────────────────────────────────
async function sendNotification() {
  const target = $('notify-target')?.value || 'all';
  const threshold = $('notify-threshold')?.value || undefined;
  const link = ($('notify-link')?.value || '').trim() || undefined;
  const dryRun = $('notify-dryrun')?.checked ?? true;
  const body = { target, threshold, link, dryRun };
  if (CURRENT_ASSESSMENT?.assessmentId) body.assessmentId = CURRENT_ASSESSMENT.assessmentId;
  const btn = $('notify-send-btn'); if (btn) { btn.disabled = true; btn.textContent = dryRun ? 'Previewing…' : 'Sending…'; }
  try {
    const data = await apiPost('/api/notify', body);
    const sent = (data.sent || []).join(', ') || '—';
    const skipped = (data.skipped || []).join(', ') || '—';
    const errs = (data.errors || []).map(e => typeof e === 'string' ? e : (e.channel ? `${e.channel}: ${e.error}` : JSON.stringify(e)));
    const noTargets = (data.skipped || []).some(s => s && s.reason === 'no-targets');
    const el = $('notify-result');
    if (el) {
      let html = `<div style="margin-top:10px"><span class="badge ${data.ok === false ? 'bad' : 'ok'}">${dryRun ? 'Preview' : (data.ok === false ? 'Errors' : 'Sent')}</span>
        <div style="margin-top:8px;font-size:13px;color:var(--fg-2)"><div>Sent: ${esc(sent)}</div><div>Skipped: ${esc(skipped)}</div>${errs.length ? `<div style="color:var(--crit)">Errors: ${esc(errs.join('; '))}</div>` : ''}</div>`;
      if (noTargets) html += `<div class="set-callout">No notification channels are configured. Add a Slack, Teams, or webhook URL in <a href="#" data-section="settings">Settings</a> (or set the matching <code class="mono">FLAREINSPECT_*_WEBHOOK</code> env var).</div>`;
      if (dryRun && data.payloads && Object.keys(data.payloads).length) html += `<div class="code-block" style="margin-top:8px;max-height:320px;overflow:auto">${esc(JSON.stringify(data.payloads, null, 2))}</div>`;
      html += '</div>';
      el.innerHTML = html;
      el.querySelector('[data-section]')?.addEventListener('click', e => { e.preventDefault(); navigateTo('settings'); });
    }
    if (noTargets) showToast('No channels configured — add one in Settings.', 'error');
    else showToast(dryRun ? 'Payload preview ready.' : 'Notification dispatched.', data.ok === false ? 'error' : 'success');
  } catch (err) { showToast(err.message, 'error'); }
  finally { if (btn) { btn.disabled = false; btn.textContent = 'Send'; } }
}

// ─── Agents & MCP ───────────────────────────────────────────────────────────
function refreshAgentsGate() {
  const badge = $('agents-gate-badge'), note = $('agents-gate-note'), remNote = $('agents-rem-note');
  const apply = $('agents-tool-apply'), rollback = $('agents-tool-rollback');
  updateRemediationBadges(ALLOW_REMEDIATION);
  if (badge) { badge.textContent = ALLOW_REMEDIATION ? 'Remediation: ENABLED' : 'Remediation: DISABLED'; badge.className = `badge ${ALLOW_REMEDIATION ? 'ok' : 'warn'}`; }
  [apply, rollback].forEach(b => { if (b) { b.textContent = ALLOW_REMEDIATION ? 'available' : 'gate: off'; b.className = `badge ${ALLOW_REMEDIATION ? 'ok' : 'warn'}`; } });
  if (note) note.textContent = ALLOW_REMEDIATION
    ? 'apply_remediation and rollback are ENABLED on this server (FLAREINSPECT_ALLOW_REMEDIATION=true). Agents can mutate Cloudflare with an edit-scoped token.'
    : 'A Model Context Protocol server exposes FlareInspect as tools so any MCP-aware agent (Claude Code, Hermes, OpenClaw) can connect over stdio. apply_remediation and rollback are gated off until FLAREINSPECT_ALLOW_REMEDIATION=true.';
  if (remNote) remNote.textContent = ALLOW_REMEDIATION
    ? 'apply_remediation and rollback are ENABLED. Each apply writes a reversible backup bundle first.'
    : 'apply_remediation and rollback are gated off. They require the server to be started with the gate enabled and an edit-scoped token.';
}

// ─── Settings ───────────────────────────────────────────────────────────────
const SECRET_KEYS = new Set(['slackWebhook', 'teamsWebhook', 'webhookUrl', 'webhookSecret',
  'anthropicApiKey', 'openaiApiKey', 'esApiKey', 'esPassword', 'hecToken']);

function updateRemediationBadges(enabled) {
  ALLOW_REMEDIATION = !!enabled;
  [['settings-rem-badge', enabled ? 'ENABLED' : 'DISABLED'], ['agents-rem-badge', enabled ? 'ENABLED' : 'DISABLED']].forEach(([id, txt]) => {
    const b = $(id); if (b) { b.textContent = txt; b.className = `badge ${enabled ? 'ok' : 'warn'}`; }
  });
}

async function renderSettings() {
  try {
    const data = await apiGet('/api/settings');
    const s = data.settings || {};
    updateRemediationBadges(data.remediation === 'enabled');
    SETTINGS_KEYS.forEach(key => {
      const entry = s[key] || { source: 'none', configured: false };
      const input = $(`set-${key}`);
      const status = $(`status-${key}`);
      if (status) {
        const src = entry.source || 'none';
        status.className = `set-status ${src}`;
        status.textContent = src === 'settings' ? 'saved' : (src === 'env' ? 'from .env' : 'not set');
      }
      if (!input) return;
      if (SECRET_KEYS.has(key)) {
        input.value = '';
        input.placeholder = entry.configured && entry.hint ? `${entry.hint} — leave blank to keep` : input.placeholder;
      } else {
        input.value = entry.value || '';
      }
    });
  } catch (err) { showToast(err.message, 'error'); }
}

async function saveSettingsForm(formId) {
  const form = $(formId); if (!form) return;
  const patch = {};
  form.querySelectorAll('[data-key]').forEach(input => {
    const key = input.dataset.key;
    const val = (input.value || '').trim();
    if (SECRET_KEYS.has(key)) { if (val !== '') patch[key] = val; }   // blank secret = keep existing
    else { patch[key] = val; }                                        // blank non-secret = clear (env fallback)
  });
  try {
    await apiPost('/api/settings', patch, 'PUT');
    showToast('Settings saved.', 'success');
    const badge = $('settings-saved-badge'); if (badge) { badge.style.display = ''; setTimeout(() => { badge.style.display = 'none'; }, 2000); }
    renderSettings();
  } catch (err) { showToast(err.message, 'error'); }
}

// ─── Toasts ───────────────────────────────────────────────────────────────
function showToast(msg, type = 'info', dur = 4000) {
  const c = $('toast-container'); if (!c) return;
  const t = document.createElement('div'); t.className = `toast ${type}`; t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => { t.classList.add('removing'); t.addEventListener('animationend', () => t.remove(), { once: true }); }, dur);
}

// ─── Init ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  bindNav();
  initAssessForm();

  $('theme-toggle')?.addEventListener('click', toggleTheme);

  // Findings filters
  document.querySelectorAll('[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      currentFilter = btn.dataset.filter;
      document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('btn-primary'));
      btn.classList.add('btn-primary');
      renderFindings();
    });
  });

  // Findings search
  $('findings-search-input')?.addEventListener('input', e => { currentSearch = e.target.value; renderFindings(); });

  // Global search
  const gs = $('global-search');
  if (gs) {
    gs.addEventListener('input', e => { currentSearch = e.target.value; if (currentSection === 'findings') renderFindings(); });
    document.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); gs.focus(); } });
  }

  $('drawer-close')?.addEventListener('click', () => $('node-drawer')?.classList.remove('open'));

  $('hamburger')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('open');
    document.querySelector('.sidebar-overlay')?.classList.toggle('open');
  });
  document.querySelector('.sidebar-overlay')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.remove('open');
    document.querySelector('.sidebar-overlay')?.classList.remove('open');
  });

  // Integration forms
  $('rem-form')?.addEventListener('submit', e => { e.preventDefault(); buildRemediatePlan(); });
  $('rem-apply-btn')?.addEventListener('click', applyRemediation);
  $('rem-refresh-backups')?.addEventListener('click', loadRemediateBackups);
  $('siem-ship-btn')?.addEventListener('click', shipSiem);
  $('siem-template-btn')?.addEventListener('click', downloadEcsTemplate);
  $('notify-send-btn')?.addEventListener('click', sendNotification);
  $('report-refresh')?.addEventListener('click', () => { reportLoaded = false; refreshReport(); });
  $('agents-copy-btn')?.addEventListener('click', () => {
    const cfg = $('agents-config')?.textContent || '';
    navigator.clipboard?.writeText(cfg).then(() => showToast('MCP config copied.', 'success'), () => showToast('Copy failed — select manually.', 'error'));
  });

  // Settings forms
  ['settings-notify-form', 'settings-ai-form', 'settings-siem-form'].forEach(id => {
    $(id)?.addEventListener('submit', e => { e.preventDefault(); saveSettingsForm(id); });
  });
  $('rem-ai')?.addEventListener('change', e => { e.target.dataset.touched = '1'; });

  // Finding detail drawer close affordances
  $('finding-drawer-close')?.addEventListener('click', closeFindingDrawer);
  $('finding-scrim')?.addEventListener('click', closeFindingDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeFindingDrawer(); });

  navigateTo('overview');
  loadAll();
});
