'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let currentAssessment = null;
let currentFilter = 'all';
let isRunning = false;
let historyCache = null;

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

const TOPBAR_TITLES = {
  overview:   'Overview',
  assess:     'Run assessment',
  findings:   'Findings',
  export:     'Exports',
  compliance: 'Compliance',
  report:     'Full report',
  history:    'History',
  api:        'API health',
};

// ── Utilities ──────────────────────────────────────────────────────────────
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function barColor(v) {
  if (v >= 80) return 'oklch(72% 0.15 155)';
  if (v >= 65) return 'oklch(78% 0.14 85)';
  if (v >= 50) return 'oklch(72% 0.17 52)';
  return 'oklch(65% 0.21 25)';
}

function $(id) { return document.getElementById(id); }

// ── Navigation ─────────────────────────────────────────────────────────────
function navigateTo(section) {
  document.querySelectorAll('.v1-page').forEach(p => { p.style.display = 'none'; });
  document.querySelectorAll('.v1-navlink').forEach(l => l.classList.remove('active'));

  const page = $(`page-${section}`);
  if (page) page.style.display = 'flex';

  const link = document.querySelector(`.v1-navlink[data-section="${section}"]`);
  if (link) link.classList.add('active');

  const crumb = $('crumb-page');
  if (crumb) crumb.textContent = TOPBAR_TITLES[section] || section;

  if (section === 'history')    loadHistory();
  if (section === 'api')        loadHealth();
  if (section === 'export')     updateExportState();
  if (section === 'findings')   renderFindings();
  if (section === 'report')     refreshReport();
  if (section === 'compliance') renderComplianceCards();

  $('sidebar')?.classList.remove('open');
  $('sidebar-overlay')?.classList.remove('open');
}

function bindSectionButtons() {
  document.querySelectorAll('[data-section]').forEach(el => {
    if (el.tagName === 'A' && el.getAttribute('href') && el.getAttribute('href') !== '#') return;
    el.addEventListener('click', (e) => {
      if (el.tagName === 'A') e.preventDefault();
      navigateTo(el.dataset.section);
    });
  });
}

$('hamburger')?.addEventListener('click', () => {
  $('sidebar')?.classList.toggle('open');
  $('sidebar-overlay')?.classList.toggle('open');
});
$('sidebar-overlay')?.addEventListener('click', () => {
  $('sidebar')?.classList.remove('open');
  $('sidebar-overlay')?.classList.remove('open');
});

// ── Toasts ─────────────────────────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
  const container = $('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `v1-toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('removing');
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
  }, duration);
}

// ── Progress ───────────────────────────────────────────────────────────────
let progressTimer = null;

function startProgress(label) {
  const wrap = $('progress-wrap');
  const fill = $('progress-fill');
  const text = $('progress-text');
  const pct  = $('progress-pct');
  if (!wrap) return;
  wrap.style.display = 'flex';
  if (text) text.textContent = label || 'Running assessment…';
  if (fill) fill.style.width = '0%';
  if (pct)  pct.textContent  = '0%';

  let progress = 0;
  if (progressTimer) clearInterval(progressTimer);
  progressTimer = setInterval(() => {
    progress = Math.min(progress + Math.random() * 3, 94);
    if (fill) fill.style.width = progress.toFixed(0) + '%';
    if (pct)  pct.textContent  = progress.toFixed(0) + '%';
  }, 500);
}

function stopProgress(finalLabel) {
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
  const fill = $('progress-fill');
  const pct  = $('progress-pct');
  if (fill) fill.style.width = '100%';
  if (pct)  pct.textContent  = '100%';
  const text = $('progress-text');
  if (text && finalLabel) text.textContent = finalLabel;
  setTimeout(() => { const w = $('progress-wrap'); if (w) w.style.display = 'none'; }, 1200);
}

// ── Score ring ────────────────────────────────────────────────────────────
function animateScoreRing(score) {
  const fill = $('score-ring-fill');
  if (!fill) return;
  const C = 2 * Math.PI * 62;
  fill.style.strokeDasharray = String(C);
  fill.style.strokeDashoffset = String(C);
  const target = C * (1 - Math.max(0, Math.min(100, score)) / 100);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      fill.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)';
      fill.style.strokeDashoffset = String(target);
    });
  });
}

// ── Sparkline ──────────────────────────────────────────────────────────────
function renderSparkline(container, data, { width = 140, height = 28, color = 'var(--flare)' } = {}) {
  if (!container) return;
  if (!data || data.length < 2) {
    container.innerHTML = '<span style="color:var(--fg-4);font-family:var(--font-mono);font-size:11px">—</span>';
    return;
  }
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = Math.max(1, max - min);
  const pts = data.map((v, i) => [
    (i / (data.length - 1)) * width,
    height - ((v - min) / range) * (height - 4) - 2,
  ]);
  const d = pts.map((p, i) => (i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`)).join(' ');
  const area = d + ` L${width},${height} L0,${height} Z`;
  const last = pts[pts.length - 1];
  container.innerHTML = `
    <svg width="${width}" height="${height}" style="display:block">
      <defs>
        <linearGradient id="spark-grad" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stop-color="${color}" stop-opacity="0.35"/>
          <stop offset="100%" stop-color="${color}" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <path d="${area}" fill="url(#spark-grad)"/>
      <path d="${d}" stroke="${color}" stroke-width="1.5" fill="none"/>
      <circle cx="${last[0]}" cy="${last[1]}" r="2.5" fill="${color}"/>
    </svg>`;
}

// ── Assessment rendering ──────────────────────────────────────────────────
function updateWithAssessment(assessment) {
  currentAssessment = assessment;
  if (!assessment) return;

  const score = assessment.score || {};
  const summary = assessment.summary || {};
  const meta = assessment.metadata || {};
  const account = assessment.account || {};

  $('idle-hero').style.display = 'none';
  $('score-hero').style.display = 'flex';

  // Account / crumb
  const accountName = account.name || '—';
  if ($('account-name')) $('account-name').textContent = accountName;
  if ($('crumb-account')) $('crumb-account').textContent = accountName;
  if ($('brand-sub') && account.name) $('brand-sub').textContent = account.name;

  // Meta / posture subtitle
  const completed = assessment.completedAt || assessment.startedAt;
  const completedStr = completed ? new Date(completed).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '—';
  const duration = assessment.duration ? formatDuration(assessment.duration) : (meta.duration || '—');
  const zoneCount = Array.isArray(assessment.zones) ? assessment.zones.length : 0;
  const checksRun = summary.totalChecks || 0;
  if ($('posture-sub')) $('posture-sub').innerHTML =
    `Latest assessment · <span class="v1-mono">${escHtml(completedStr)}</span> · ${escHtml(duration)} · ${checksRun} checks`;

  if ($('chip-zones')) $('chip-zones').textContent = `Zones · ${zoneCount}`;

  // CI gate chip — green when no critical findings
  const critical = summary.criticalFindings || 0;
  const ciDot = $('ci-dot');
  const ciLabel = $('ci-label');
  if (critical === 0) {
    if (ciDot) ciDot.style.background = 'var(--low)';
    if (ciLabel) ciLabel.textContent = 'CI gate: passing';
  } else {
    if (ciDot) ciDot.style.background = 'var(--crit)';
    if (ciLabel) ciLabel.textContent = `CI gate: ${critical} critical`;
  }

  // Score ring + number + grade
  const overall = score.overallScore != null ? score.overallScore : 0;
  if ($('score-num')) $('score-num').textContent = score.overallScore != null ? score.overallScore : '—';
  if ($('score-grade')) $('score-grade').textContent = score.grade || '—';
  animateScoreRing(overall);

  // Passed checks
  const passed = summary.passedChecks || 0;
  const total = summary.totalChecks || 0;
  if ($('score-passed')) $('score-passed').innerHTML = `${passed} <em>/ ${total}</em>`;

  // Breakdown (assessment.score.breakdown is { [category]: {score, total, passed, failed} })
  renderBreakdown(score.breakdown || {});

  // Severity strip
  renderSeverityStrip(summary, zoneCount);

  // Findings badge
  const openFindings = (summary.criticalFindings || 0) + (summary.highFindings || 0) + (summary.mediumFindings || 0) + (summary.lowFindings || 0);
  if ($('nav-badge-findings')) $('nav-badge-findings').textContent = openFindings > 0 ? String(openFindings) : '—';

  // Footer status
  if ($('foot-status-text')) $('foot-status-text').textContent = openFindings === 0 ? 'All checks passing' : 'Assessment ready';

  // Top findings
  renderRecentFindings(assessment.findings || []);

  // Zone matrix
  renderZoneMatrix(assessment);

  // Compliance rail (fetch all four frameworks)
  renderComplianceRail();

  // JSON preview + exports
  updateExportState();

  // Score delta & trend — from history
  updateScoreDelta(overall);

  // If the findings page is visible, re-render
  if ($('page-findings')?.style.display !== 'none') renderFindings();
}

function formatDuration(ms) {
  if (!ms || typeof ms !== 'number') return String(ms || '—');
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}m ${rem}s`;
}

function renderBreakdown(breakdown) {
  const container = $('breakdown-rows');
  if (!container) return;

  const rows = Object.entries(breakdown || {});
  if (rows.length === 0) {
    container.innerHTML = '<div class="v1-empty" style="padding:12px 0">No category breakdown available.</div>';
    return;
  }

  // Sort: highest score first
  rows.sort((a, b) => (b[1].score || 0) - (a[1].score || 0));

  container.innerHTML = rows.map(([label, v]) => {
    const val = v.score || 0;
    const weight = v.total || 0;
    return `
      <div class="v1-bd-row">
        <div class="v1-bd-label">${escHtml(label)}</div>
        <div class="v1-bd-bar"><div class="v1-bd-fill" style="width:${val}%;background:${barColor(val)}"></div></div>
        <div class="v1-bd-val">${val}</div>
        <div class="v1-bd-wt">${weight ? `n${weight}` : ''}</div>
      </div>
    `;
  }).join('');
}

function renderSeverityStrip(summary, zoneCount) {
  const counts = {
    critical: summary.criticalFindings || 0,
    high:     summary.highFindings || 0,
    medium:   summary.mediumFindings || 0,
    low:      summary.lowFindings || 0,
  };
  const total = counts.critical + counts.high + counts.medium + counts.low;
  const passed = summary.passedChecks || 0;

  const sub = $('sevstrip-sub');
  if (sub) sub.textContent = `${total} open across ${zoneCount} zones · ${passed} checks passed`;

  document.querySelectorAll('.v1-sevseg').forEach(seg => {
    const sev = seg.dataset.sev;
    seg.style.flex = String(counts[sev] || 0);
  });
  if ($('sev-critical')) $('sev-critical').textContent = counts.critical;
  if ($('sev-high'))     $('sev-high').textContent     = counts.high;
  if ($('sev-medium'))   $('sev-medium').textContent   = counts.medium;
  if ($('sev-low'))      $('sev-low').textContent      = counts.low;
}

function buildFindingMarkup(f) {
  const sev = f.severity || 'low';
  const title = f.checkTitle || f.title || f.checkId || 'Unknown finding';
  const id = f.checkId || (f.id || '').slice(0, 8);
  const category = f.service || f.category || '—';
  let zoneName = '—';
  if (f.resourceType === 'zone' && currentAssessment?.zones) {
    const z = currentAssessment.zones.find(z => z.id === f.resourceId);
    if (z) zoneName = z.name;
  } else if (f.resourceType === 'account') {
    zoneName = 'account';
  }
  const evidence = f.metadata?.evidence || f.description || '';
  const evidenceShort = evidence && evidence.length > 80 ? evidence.slice(0, 80) + '…' : evidence;
  const status = f.metadata?.status || 'existing';

  return `
    <div class="v1-finding">
      <div class="v1-finding-sev ${escHtml(sev)}">
        <span class="v1-sevdot" style="background:currentColor"></span>
        <span>${escHtml(sev)}</span>
      </div>
      <div class="v1-finding-main">
        <div class="v1-finding-title">${escHtml(title)}</div>
        <div class="v1-finding-meta">
          <span class="v1-finding-id">${escHtml(id)}</span>
          <span class="v1-finding-sep">·</span>
          <span>${escHtml(category)}</span>
          <span class="v1-finding-sep">·</span>
          <span class="v1-finding-zone">${escHtml(zoneName)}</span>
        </div>
      </div>
      <div class="v1-finding-evidence">${escHtml(evidenceShort)}</div>
      <div class="v1-finding-status ${escHtml(status)}">${escHtml(status)}</div>
      <button class="v1-finding-cta" type="button" aria-label="Open">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
      </button>
    </div>
  `;
}

function getFailingFindings() {
  const all = currentAssessment?.findings || [];
  return all.filter(f => f.status !== 'PASS');
}

function renderRecentFindings() {
  const list = $('recent-findings');
  const sub = $('top-findings-sub');
  if (!list) return;
  const findings = getFailingFindings();
  const sorted = [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  const top = sorted.slice(0, 6);
  if (sub) sub.textContent = `Sorted by severity · showing ${top.length} of ${findings.length}`;
  if (top.length === 0) {
    list.innerHTML = '<div class="v1-finding" style="padding:20px;grid-template-columns:1fr"><div class="v1-empty" style="padding:0">No open findings.</div></div>';
    return;
  }
  list.innerHTML = top.map(buildFindingMarkup).join('');
}

function renderFindings() {
  const container = $('all-findings');
  if (!container) return;
  const findings = getFailingFindings();
  const filtered = currentFilter === 'all' ? findings : findings.filter(f => f.severity === currentFilter);

  const subEl = $('findings-sub');
  if (subEl) subEl.textContent = `${filtered.length} of ${findings.length} findings · filter: ${currentFilter}`;

  if (filtered.length === 0) {
    container.innerHTML = '<div class="v1-empty">No findings match this filter.</div>';
    return;
  }
  const sorted = [...filtered].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  container.innerHTML = sorted.map(buildFindingMarkup).join('');
}

// Findings filter
document.querySelectorAll('#findings-filter [data-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    currentFilter = btn.dataset.filter;
    document.querySelectorAll('#findings-filter [data-filter]').forEach(b => b.classList.remove('v1-btn-primary'));
    btn.classList.add('v1-btn-primary');
    renderFindings();
  });
});

// ── Zone matrix ────────────────────────────────────────────────────────────
function renderZoneMatrix(assessment) {
  const grid = $('zone-grid');
  const sub = $('zones-sub');
  if (!grid) return;

  const zones = Array.isArray(assessment.zones) ? assessment.zones : [];
  if (zones.length === 0) {
    grid.innerHTML = '<div class="v1-empty">No zones in this assessment.</div>';
    if (sub) sub.textContent = '—';
    return;
  }

  // Group failing findings by zone id
  const failing = (assessment.findings || []).filter(f => f.status === 'FAIL' && f.resourceType === 'zone');
  const byZone = {};
  for (const f of failing) {
    const id = f.resourceId;
    if (!byZone[id]) byZone[id] = { critical: 0, high: 0, medium: 0, low: 0 };
    if (byZone[id][f.severity] != null) byZone[id][f.severity]++;
  }

  if (sub) sub.textContent = `Posture across ${zones.length} Cloudflare zone${zones.length === 1 ? '' : 's'}`;

  grid.innerHTML = zones.map(z => {
    const sev = byZone[z.id] || { critical: 0, high: 0, medium: 0, low: 0 };
    // Posture score: 100 - penalties, clamp [0,100]
    const score = Math.max(0, Math.min(100, Math.round(100 - sev.critical * 15 - sev.high * 6 - sev.medium * 2 - sev.low * 0.5)));
    const color = barColor(score);
    const plan = (z.plan || 'Free').toLowerCase();
    const chips = [];
    if (sev.critical > 0) chips.push(`<span class="v1-zone-chip crit">${sev.critical} C</span>`);
    if (sev.high > 0)     chips.push(`<span class="v1-zone-chip high">${sev.high} H</span>`);
    if (sev.medium > 0)   chips.push(`<span class="v1-zone-chip med">${sev.medium} M</span>`);
    if (sev.low > 0)      chips.push(`<span class="v1-zone-chip low">${sev.low} L</span>`);
    if (chips.length === 0) chips.push('<span class="v1-zone-chip ok">clean</span>');

    return `
      <div class="v1-zone">
        <div class="v1-zone-head">
          <div class="v1-zone-name" title="${escHtml(z.name)}">${escHtml(z.name)}</div>
          <div class="v1-zone-plan plan-${escHtml(plan)}">${escHtml(z.plan || 'Free')}</div>
        </div>
        <div class="v1-zone-score">
          <span class="v1-zone-scorenum" style="color:${color}">${score}</span>
          <span class="v1-zone-scoreout">/100</span>
        </div>
        <div class="v1-zone-bar"><div style="width:${score}%;background:${color}"></div></div>
        <div class="v1-zone-sev">${chips.join('')}</div>
      </div>
    `;
  }).join('');
}

// ── Compliance ─────────────────────────────────────────────────────────────
const COMPLIANCE_FRAMEWORKS = ['cis', 'soc2', 'pci', 'nist'];

async function renderComplianceRail() {
  const container = $('compliance-rows');
  if (!container) return;
  if (!currentAssessment) {
    container.innerHTML = '<div class="v1-empty" style="padding:8px 0">No assessment loaded.</div>';
    return;
  }

  const results = await Promise.all(COMPLIANCE_FRAMEWORKS.map(fw =>
    fetch(`/api/compliance/${fw}`).then(r => r.ok ? r.json() : null).catch(() => null)
  ));

  const rows = results.map((res, i) => {
    const fw = COMPLIANCE_FRAMEWORKS[i];
    if (!res || !res.compliance) {
      return { name: fw.toUpperCase(), score: 0, pass: 0, total: 0, available: false };
    }
    const c = res.compliance;
    return {
      name: fw.toUpperCase(),
      score: c.overallScore || 0,
      pass: c.passedControls || 0,
      total: c.totalControls || 0,
      available: true,
    };
  });

  container.innerHTML = rows.map(r => {
    const color = barColor(r.score);
    return `
      <div class="v1-comp-row">
        <div class="v1-comp-name">${escHtml(r.name)}</div>
        <div class="v1-comp-bar"><div style="width:${r.score}%;background:${color}"></div></div>
        <div class="v1-comp-score">${r.available ? r.score : '—'}</div>
        <div class="v1-comp-sub">${r.available ? `${r.pass}/${r.total}` : '—'}</div>
      </div>
    `;
  }).join('');
}

function renderComplianceCards() { /* static markup */ }

// ── Score delta from history ──────────────────────────────────────────────
async function updateScoreDelta(currentScore) {
  try {
    const res = await fetch('/api/assessments');
    const data = await res.json();
    const list = Array.isArray(data) ? data : (data.assessments || []);
    historyCache = list;
    const sorted = [...list].sort((a, b) => new Date(b.startedAt || 0) - new Date(a.startedAt || 0));
    const scores = sorted.slice(0, 12).reverse().map(a => a.score ?? 0).filter(s => typeof s === 'number');
    const sparkEl = $('score-sparkline');
    if (scores.length >= 2) {
      renderSparkline(sparkEl, scores, { color: 'oklch(72% 0.17 52)' });
    } else if (sparkEl) {
      sparkEl.innerHTML = '<span style="color:var(--fg-4);font-family:var(--font-mono);font-size:11px">First run</span>';
    }

    // previous & delta
    // Find the previous run (older than current)
    const previous = sorted.find(a => a.id !== currentAssessment?.assessmentId && a.id !== currentAssessment?.id);
    const prevEl = $('score-prev');
    const deltaEl = $('score-delta');
    if (previous && typeof previous.score === 'number') {
      if (prevEl) prevEl.textContent = previous.score;
      const delta = currentScore - previous.score;
      if (deltaEl) {
        deltaEl.style.display = 'block';
        deltaEl.className = 'v1-score-delta ' + (delta >= 0 ? 'up' : 'down');
        deltaEl.textContent = `${delta >= 0 ? '▲' : '▼'} ${Math.abs(delta)} vs last`;
      }
    } else {
      if (prevEl) prevEl.textContent = '—';
      if (deltaEl) deltaEl.style.display = 'none';
    }
  } catch {
    const sparkEl = $('score-sparkline');
    if (sparkEl) sparkEl.innerHTML = '';
  }
}

// ── Export state ──────────────────────────────────────────────────────────
function updateExportState() {
  const hasData = currentAssessment != null;
  ['exp-json','exp-html','exp-sarif','exp-csv','exp-md','exp-asff'].forEach(id => {
    const el = $(id);
    if (el) el.setAttribute('aria-disabled', String(!hasData));
  });
  const preview = $('json-preview');
  if (preview) {
    if (hasData) {
      const json = JSON.stringify(currentAssessment, null, 2);
      preview.textContent = json.length > 5000 ? json.slice(0, 5000) + '\n\n... (download JSON for full output)' : json;
    } else {
      preview.textContent = 'Run an assessment to see the JSON output here.';
    }
  }
}

// ── Status helpers ─────────────────────────────────────────────────────────
function setStatus(state, message) {
  const card = $('status-card');
  const chip = $('status-chip');
  const label = $('status-label');
  const spinner = $('status-spinner');
  const msgEl = $('status-msg');

  if (card) card.style.display = 'flex';
  if (chip) chip.className = `v1-status-chip ${state}`;
  if (spinner) spinner.style.display = state === 'running' ? 'inline-block' : 'none';
  if (label) label.textContent = state.charAt(0).toUpperCase() + state.slice(1);
  if (msgEl) msgEl.textContent = message || '';

  // Footer dot
  const dot = document.querySelector('.v1-foot-dot');
  const statusText = $('foot-status-text');
  if (dot && statusText) {
    dot.classList.remove('busy', 'error');
    if (state === 'running') { dot.classList.add('busy'); statusText.textContent = 'Assessment running'; }
    else if (state === 'error') { dot.classList.add('error'); statusText.textContent = 'Error'; }
  }
}

// ── Assessment actions ─────────────────────────────────────────────────────
async function runAssessment(token, zones) {
  isRunning = true;
  setStatus('running', 'Assessment in progress. This can take a few minutes…');
  startProgress('Running assessment across zones…');
  setRunBtnDisabled(true);

  try {
    const body = { token };
    if (zones) body.zones = zones;

    const response = await fetch('/api/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Assessment failed.');

    stopProgress('Assessment complete');
    updateWithAssessment(data.assessment);
    setStatus('done', `Complete. Score: ${data.assessment.score?.overallScore ?? '—'}/100`);
    showToast('Assessment completed successfully.', 'success');
    navigateTo('overview');
  } catch (err) {
    stopProgress('Assessment failed');
    setStatus('error', err.message);
    showToast(err.message, 'error');
  } finally {
    isRunning = false;
    setRunBtnDisabled(false);
  }
}

async function loadLatest() {
  try {
    setStatus('running', 'Loading latest assessment…');
    const response = await fetch('/api/assessment');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'No assessment available.');
    updateWithAssessment(data.assessment);
    setStatus('done', 'Latest assessment loaded.');
    showToast('Latest assessment loaded.', 'success');
    navigateTo('overview');
  } catch (err) {
    setStatus('error', err.message);
    showToast(err.message, 'error');
  }
}

function setRunBtnDisabled(disabled) {
  const btn = $('btn-run');
  if (btn) btn.disabled = disabled;
}

$('assess-form')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const token = $('token')?.value.trim();
  const zones = $('zones')?.value.trim();
  if (!token) { showToast('API token is required.', 'warning'); return; }
  runAssessment(token, zones);
});

$('btn-latest')?.addEventListener('click', loadLatest);

// ── Report ─────────────────────────────────────────────────────────────────
async function refreshReport() {
  const frame = $('report-frame');
  const status = $('report-status');
  if (!frame) return;

  if (!currentAssessment) {
    if (status) status.textContent = 'No assessment data. Run an assessment first.';
    return;
  }
  if (status) status.textContent = 'Loading report…';
  try {
    const res = await fetch('/api/download/html');
    if (!res.ok) throw new Error('Failed to load report.');
    const html = await res.text();
    if (!html || html.length < 100) throw new Error('Report is empty.');
    frame.srcdoc = html;
    if (status) status.textContent = 'Report loaded.';
  } catch (err) {
    if (status) status.textContent = err.message;
  }
}

$('btn-refresh-report')?.addEventListener('click', refreshReport);

// ── History ────────────────────────────────────────────────────────────────
async function loadHistory() {
  const container = $('history-list');
  if (!container) return;
  try {
    const res = await fetch('/api/assessments');
    const data = await res.json();
    const list = Array.isArray(data) ? data : (data.assessments || []);
    if (!Array.isArray(list) || list.length === 0) {
      container.innerHTML = '<div class="v1-empty">No assessment history found.</div>';
      return;
    }
    container.innerHTML = list
      .sort((a, b) => new Date(b.startedAt || 0) - new Date(a.startedAt || 0))
      .map(a => {
        const when = a.startedAt ? new Date(a.startedAt).toLocaleString() : 'Unknown';
        const score = a.score ?? '—';
        const grade = a.grade ?? '—';
        const findings = a.findings != null ? a.findings : '';
        return `
          <div class="v1-history-row">
            <div>
              <div class="v1-history-name">${escHtml(a.accountName || a.id || 'Assessment')}</div>
              <div class="v1-history-meta">${escHtml(when)}${findings !== '' ? ` · ${findings} findings` : ''}</div>
            </div>
            <div class="v1-history-trigger">${escHtml(a.trigger || 'manual')}</div>
            <div class="v1-history-score">${escHtml(String(score))}</div>
            <div class="v1-history-grade">${escHtml(String(grade))}</div>
            <button class="v1-btn v1-btn-sm" type="button" data-load-id="${escHtml(a.id)}">Load</button>
          </div>
        `;
      }).join('');
    container.querySelectorAll('[data-load-id]').forEach(btn => {
      btn.addEventListener('click', () => loadAssessmentById(btn.dataset.loadId));
    });
  } catch {
    container.innerHTML = '<div class="v1-empty" style="color:var(--crit)">Failed to load history.</div>';
  }
}

async function loadAssessmentById(id) {
  try {
    const res = await fetch(`/api/assessments/${id}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load assessment.');
    updateWithAssessment(data.assessment);
    showToast('Assessment loaded.', 'success');
    navigateTo('overview');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── API health ─────────────────────────────────────────────────────────────
async function loadHealth() {
  const info = $('health-info');
  if (!info) return;
  info.innerHTML = '<div class="v1-empty">Loading…</div>';
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    const rows = [
      { label: 'Status',          value: data.ok ? '✓ Online' : '✗ Offline', cls: data.ok ? 'ok' : 'bad' },
      { label: 'Version',         value: data.version || 'unknown' },
      { label: 'Uptime',          value: data.uptime ? data.uptime.toFixed(0) + 's' : '—' },
      { label: 'Auth',            value: data.auth === 'api-key' ? 'API key enabled' : 'No auth' },
      { label: 'Storage',         value: data.storage?.ready ? '✓ Ready' : '✗ ' + (data.storage?.error || 'error'), cls: data.storage?.ready ? 'ok' : 'bad' },
      { label: 'Last assessment', value: data.lastAssessmentAt ? new Date(data.lastAssessmentAt).toLocaleString() : 'None' },
    ];
    info.innerHTML = rows.map(r => `
      <div class="v1-health-row">
        <span class="v1-health-label">${escHtml(r.label)}</span>
        <span class="v1-health-value ${r.cls || ''}">${escHtml(r.value)}</span>
      </div>
    `).join('');
  } catch {
    info.innerHTML = '<div class="v1-empty" style="color:var(--crit)">Failed to load health info.</div>';
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
(async function init() {
  bindSectionButtons();
  try {
    const res = await fetch('/api/assessment');
    if (res.ok) {
      const data = await res.json();
      if (data.assessment) updateWithAssessment(data.assessment);
    }
  } catch (_) {
    /* no assessment yet — idle state */
  }
  navigateTo('overview');
})();
