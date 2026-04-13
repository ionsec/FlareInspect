'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let currentAssessment = null;
let currentFilter = 'all';
let isRunning = false;

// ── Navigation ─────────────────────────────────────────────────────────────
const TOPBAR_TITLES = {
  overview:    'Overview',
  assess:      'Run Assessment',
  findings:    'Findings',
  export:      'Export Reports',
  compliance:  'Compliance',
  report:      'Full Report',
  history:     'Assessment History',
  api:         'API Health'
};

function navigateTo(section) {
  document.querySelectorAll('.page').forEach(p => { p.style.display = 'none'; });
  document.querySelectorAll('.nav-link').forEach(l => { l.classList.remove('active'); });

  const page = document.getElementById(`page-${section}`);
  if (page) page.style.display = 'block';

  const link = document.querySelector(`.nav-link[data-section="${section}"]`);
  if (link) link.classList.add('active');

  const topbarTitle = document.getElementById('topbar-title');
  if (topbarTitle) topbarTitle.textContent = TOPBAR_TITLES[section] || section;

  // Run section-specific init
  if (section === 'history')  loadHistory();
  if (section === 'api')      loadHealth();
  if (section === 'export')   updateExportState();
  if (section === 'findings') renderFindings();
  if (section === 'report')   refreshReport();

  // Mobile: close sidebar
  document.getElementById('sidebar')?.classList.remove('open');
  document.getElementById('sidebar-overlay')?.classList.remove('open');
}

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', () => {
    const section = link.dataset.section;
    if (section) navigateTo(section);
  });
});

document.getElementById('hamburger')?.addEventListener('click', () => {
  document.getElementById('sidebar')?.classList.toggle('open');
  document.getElementById('sidebar-overlay')?.classList.toggle('open');
});

document.getElementById('sidebar-overlay')?.addEventListener('click', () => {
  document.getElementById('sidebar')?.classList.remove('open');
  document.getElementById('sidebar-overlay')?.classList.remove('open');
});

// ── Toast ──────────────────────────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('removing');
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
  }, duration);
}

// ── Progress ──────────────────────────────────────────────────────────────
let progressTimer = null;

function startProgress(label) {
  const wrap  = document.getElementById('progress-wrap');
  const fill  = document.getElementById('progress-fill');
  const text  = document.getElementById('progress-text');
  const pct   = document.getElementById('progress-pct');
  if (!wrap) return;
  wrap.style.display = 'block';
  if (text) text.textContent = label || 'Running assessment...';
  if (fill) fill.style.width = '0%';
  if (pct)  pct.textContent  = '0%';

  let progress = 0;
  if (progressTimer) clearInterval(progressTimer);
  progressTimer = setInterval(() => {
    // Simulate progress (actual progress comes from server)
    progress = Math.min(progress + Math.random() * 3, 94);
    if (fill) fill.style.width = progress.toFixed(0) + '%';
    if (pct)  pct.textContent  = progress.toFixed(0) + '%';
  }, 500);
}

function stopProgress(finalLabel) {
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
  const fill = document.getElementById('progress-fill');
  const pct  = document.getElementById('progress-pct');
  if (fill) fill.style.width = '100%';
  if (pct)  pct.textContent  = '100%';
  const text = document.getElementById('progress-text');
  if (text && finalLabel) text.textContent = finalLabel;
  setTimeout(() => {
    const wrap = document.getElementById('progress-wrap');
    if (wrap) wrap.style.display = 'none';
  }, 1200);
}

// ── Score Ring ─────────────────────────────────────────────────────────────
function animateScoreRing(score) {
  const fill  = document.getElementById('score-ring-fill');
  if (!fill) return;
  const max   = 339.3; // circumference = 2 * PI * 54
  const offset = max - (score / 100) * max;
  // trigger transition
  fill.style.strokeDashoffset = max;
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      fill.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)';
      fill.style.strokeDashoffset = offset;
    });
  });
}

// ── Update UI with assessment data ───────────────────────────────────────
function updateWithAssessment(assessment) {
  currentAssessment = assessment;
  const score    = assessment.score    || {};
  const summary  = assessment.summary  || {};

  // Score hero
  const scoreHero = document.getElementById('score-hero');
  const idleHero  = document.getElementById('idle-hero');
  if (scoreHero) scoreHero.style.display = 'block';
  if (idleHero)  idleHero.style.display  = 'none';

  const scoreNum = document.getElementById('overview-score-num');
  const gradeEl  = document.getElementById('overview-grade');
  if (scoreNum) scoreNum.textContent = score.overallScore != null ? score.overallScore : '--';
  if (gradeEl)  gradeEl.textContent   = score.grade || '--';
  animateScoreRing(score.overallScore || 0);

  const titleEl = document.getElementById('overview-title');
  const descEl  = document.getElementById('overview-desc');
  if (titleEl) {
    const grade  = score.grade || '--';
    const title  = grade === 'A' ? 'Excellent Security Posture'
                 : grade === 'B' ? 'Good Security Posture'
                 : grade === 'C' ? 'Needs Improvement'
                 : grade === 'D' ? 'Significant Gaps Detected'
                 : 'Critical Issues Found';
    titleEl.textContent = title;
  }
  if (descEl) {
    descEl.textContent = `Latest assessment completed ${assessment.completedAt ? new Date(assessment.completedAt).toLocaleString() : 'recently'} with an overall score of ${score.overallScore ?? '--'}/100.`;
  }

  // Severity counts
  const severities = [
    { id: 'sev-critical', key: 'criticalFindings' },
    { id: 'sev-high',     key: 'highFindings' },
    { id: 'sev-medium',   key: 'mediumFindings' },
    { id: 'sev-low',      key: 'lowFindings' }
  ];
  severities.forEach(({ id, key }) => {
    const el = document.getElementById(id);
    if (el) el.textContent = summary[key] != null ? summary[key] : 0;
  });

  // Recent findings on overview
  renderRecentFindings(assessment.findings || []);

  // JSON preview
  updateExportState();

  // History section if visible
  if (document.getElementById('page-history')?.style.display !== 'none') {
    loadHistory();
  }

  // Findings page
  if (document.getElementById('page-findings')?.style.display !== 'none') {
    renderFindings();
  }
}

function renderRecentFindings(findings) {
  const section = document.getElementById('findings-section');
  const list    = document.getElementById('recent-findings');
  if (!section || !list) return;

  const top = findings
    .sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
    })
    .slice(0, 5);

  if (top.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  list.innerHTML = top.map(f => `
    <div class="finding-item">
      <div class="finding-severity-dot ${f.severity || 'low'}"></div>
      <div>
        <div class="finding-title">${escHtml(f.title || f.checkId || 'Unknown finding')}</div>
        <div class="finding-category">${escHtml(f.category || '')} · ${escHtml(f.severity || '').toUpperCase()}</div>
      </div>
    </div>
  `).join('');
}

function renderFindings() {
  const container = document.getElementById('all-findings');
  if (!container) return;

  const findings = currentAssessment?.findings || [];

  const filtered = currentFilter === 'all'
    ? findings
    : findings.filter(f => f.severity === currentFilter);

  if (filtered.length === 0) {
    container.innerHTML = `<p style="color:var(--text-dim);font-size:0.85rem;text-align:center;padding:30px">No findings match this filter.</p>`;
    return;
  }

  const sorted = [...filtered].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
  });

  container.innerHTML = sorted.map(f => `
    <div class="finding-item">
      <div class="finding-severity-dot ${f.severity || 'low'}"></div>
      <div style="flex:1">
        <div class="finding-title">${escHtml(f.title || f.checkId || 'Unknown finding')}</div>
        <div class="finding-category">${escHtml(f.category || '')} · ${(f.severity || '').toUpperCase()} · ${escHtml(f.checkId || '')}</div>
        ${f.description ? `<p style="margin-top:6px;font-size:0.82rem;color:var(--text-muted);line-height:1.5">${escHtml(f.description)}</p>` : ''}
        ${f.remediation ? `<p style="margin-top:4px;font-size:0.8rem;color:var(--green)">✓ ${escHtml(f.remediation)}</p>` : ''}
      </div>
    </div>
  `).join('');
}

// Findings filter buttons
document.querySelectorAll('[data-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    currentFilter = btn.dataset.filter;
    document.querySelectorAll('[data-filter]').forEach(b => {
      b.classList.remove('btn-primary');
      b.classList.add('btn-ghost');
    });
    btn.classList.remove('btn-ghost');
    btn.classList.add('btn-primary');
    renderFindings();
  });
});

// ── Export state ───────────────────────────────────────────────────────────
function updateExportState() {
  const hasData = currentAssessment != null;
  ['exp-json','exp-html','exp-sarif','exp-csv','exp-md','exp-asff'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.setAttribute('aria-disabled', String(!hasData));
  });

  const preview = document.getElementById('json-preview');
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
  const chip   = document.getElementById('status-chip');
  const label  = document.getElementById('status-label');
  const spinner = document.getElementById('status-spinner');
  const msgEl  = document.getElementById('status-msg');

  if (chip) {
    chip.className = `status-chip ${state}`;
    if (spinner) spinner.style.display = state === 'running' ? 'block' : 'none';
  }
  if (label) label.textContent = state.charAt(0).toUpperCase() + state.slice(1);
  if (msgEl) msgEl.textContent = message || '';
}

// ── Assessment actions ─────────────────────────────────────────────────────
async function runAssessment(token, zones) {
  isRunning = true;
  setStatus('running', 'Assessment in progress. This can take a few minutes...');
  startProgress('Running assessment across zones...');
  enableExports(false);
  setRunBtnDisabled(true);

  try {
    const body = { token };
    if (zones) body.zones = zones;

    const response = await fetch('/api/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Assessment failed.');

    stopProgress('Assessment complete!');
    updateWithAssessment(data.assessment);
    setStatus('done', `Assessment complete. Score: ${data.assessment.score?.overallScore ?? '--'}/100`);
    showToast('Assessment completed successfully!', 'success');
    enableExports(true);
    navigateTo('overview');
  } catch (err) {
    stopProgress('Assessment failed');
    setStatus('error', err.message);
    showToast(err.message, 'error');
    enableExports(false);
  } finally {
    isRunning = false;
    setRunBtnDisabled(false);
  }
}

async function loadLatest() {
  try {
    setStatus('running', 'Loading latest assessment...');
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

function enableExports(enabled) {
  ['exp-json','exp-html','exp-sarif','exp-csv','exp-md','exp-asff'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.setAttribute('aria-disabled', String(!enabled));
  });
}

function setRunBtnDisabled(disabled) {
  const btn = document.getElementById('btn-run');
  if (btn) btn.disabled = disabled;
}

// ── Form submit ────────────────────────────────────────────────────────────
document.getElementById('assess-form')?.addEventListener('submit', (e) => {
  e.preventDefault();
  const token = document.getElementById('token')?.value.trim();
  const zones = document.getElementById('zones')?.value.trim();
  if (!token) { showToast('API token is required.', 'warning'); return; }
  runAssessment(token, zones);
});

document.getElementById('btn-latest')?.addEventListener('click', loadLatest);

// ── Report ─────────────────────────────────────────────────────────────────
async function refreshReport() {
  const frame   = document.getElementById('report-frame');
  const status  = document.getElementById('report-status');
  if (!frame) return;

  if (!currentAssessment) {
    if (status) status.textContent = 'No assessment data. Run an assessment first.';
    return;
  }

  if (status) status.textContent = 'Loading report...';
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

document.getElementById('btn-refresh-report')?.addEventListener('click', refreshReport);

// ── History ─────────────────────────────────────────────────────────────────
async function loadHistory() {
  const container = document.getElementById('history-list');
  if (!container) return;

  try {
    const res  = await fetch('/api/assessments');
    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) {
      container.innerHTML = `<p style="color:var(--text-dim);font-size:0.85rem;text-align:center;padding:30px">No assessment history found.</p>`;
      return;
    }

    container.innerHTML = data
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
      .map(a => `
        <div class="finding-item">
          <div style="flex:1">
            <div class="finding-title">${escHtml(a.accountName)}</div>
            <div class="finding-category">
              ${a.startedAt ? new Date(a.startedAt).toLocaleString() : 'Unknown'} ·
              Score: ${a.score ?? '--'} ·
              Grade: <strong style="color:var(--orange)">${a.grade ?? '--'}</strong>
            </div>
          </div>
          <button class="btn btn-ghost btn-sm" onclick="loadAssessmentById('${a.id}')">Load</button>
        </div>
      `).join('');
  } catch {
    container.innerHTML = `<p style="color:var(--red);font-size:0.85rem;text-align:center;padding:30px">Failed to load history.</p>`;
  }
}

async function loadAssessmentById(id) {
  try {
    const res  = await fetch(`/api/assessments/${id}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load assessment.');
    updateWithAssessment(data.assessment);
    showToast('Assessment loaded.', 'success');
    navigateTo('overview');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── API Health ──────────────────────────────────────────────────────────────
async function loadHealth() {
  const info = document.getElementById('health-info');
  if (!info) return;

  info.innerHTML = `<p style="color:var(--text-dim);font-size:0.85rem">Loading...</p>`;
  try {
    const res  = await fetch('/api/health');
    const data = await res.json();
    const rows = [
      { label: 'Status',        value: data.ok ? '✓ Online' : '✗ Offline', color: data.ok ? 'var(--green)' : 'var(--red)' },
      { label: 'Version',        value: data.version || 'unknown' },
      { label: 'Uptime',         value: data.uptime ? data.uptime.toFixed(0) + 's' : '--' },
      { label: 'Auth',           value: data.auth === 'api-key' ? 'API Key enabled' : 'No auth' },
      { label: 'Storage',        value: data.storage?.ready ? '✓ Ready' : '✗ Error: ' + (data.storage?.error || 'unknown'), color: data.storage?.ready ? 'var(--green)' : 'var(--red)' },
      { label: 'Last Assessment',value: data.lastAssessmentAt ? new Date(data.lastAssessmentAt).toLocaleString() : 'None' }
    ];

    info.innerHTML = rows.map(r => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--navy-border)">
        <span style="font-size:0.85rem;color:var(--text-muted)">${r.label}</span>
        <span style="font-size:0.85rem;font-weight:600;color:${r.color || 'var(--text)'}">${r.value}</span>
      </div>
    `).join('');
  } catch {
    info.innerHTML = `<p style="color:var(--red);font-size:0.85rem">Failed to load health info.</p>`;
  }
}

// ── Utilities ──────────────────────────────────────────────────────────────
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Init ────────────────────────────────────────────────────────────────────
(async function init() {
  // Load latest on startup and show overview
  try {
    const res  = await fetch('/api/assessment');
    const data = await res.json();
    if (res.ok && data.assessment) {
      updateWithAssessment(data.assessment);
    }
  } catch (_) {
    // No assessment yet — show idle state
  }

  navigateTo('overview');
})();
