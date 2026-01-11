const form = document.getElementById('assess-form');
const statusChip = document.getElementById('status-chip');
const statusMessage = document.getElementById('status-message');
const jsonPreview = document.getElementById('json-preview');
const downloadJson = document.getElementById('download-json');
const downloadHtml = document.getElementById('download-html');
const loadLatest = document.getElementById('load-latest');
const refreshReport = document.getElementById('refresh-report');
const reportFrame = document.getElementById('report-frame');
const reportStatus = document.getElementById('report-status');

const overallScore = document.getElementById('overall-score');
const overallGrade = document.getElementById('overall-grade');
const statCritical = document.getElementById('stat-critical');
const statHigh = document.getElementById('stat-high');
const statMedium = document.getElementById('stat-medium');
const statLow = document.getElementById('stat-low');

const tokenField = document.getElementById('token');
const noteField = document.getElementById('zone-note');

function setStatus(state, message) {
  statusChip.className = `status-chip ${state}`;
  statusChip.textContent = state.charAt(0).toUpperCase() + state.slice(1);
  statusMessage.textContent = message;
}

function enableDownloads(enabled) {
  downloadJson.setAttribute('aria-disabled', String(!enabled));
  downloadHtml.setAttribute('aria-disabled', String(!enabled));
  refreshReport.disabled = !enabled;
}

function updateStats(assessment) {
  const score = assessment.score || {};
  const summary = assessment.summary || {};

  overallScore.textContent = score.overallScore != null ? score.overallScore : '--';
  overallGrade.textContent = score.grade || '--';
  statCritical.textContent = summary.criticalFindings || 0;
  statHigh.textContent = summary.highFindings || 0;
  statMedium.textContent = summary.mediumFindings || 0;
  statLow.textContent = summary.lowFindings || 0;
}

function previewJson(assessment) {
  const json = JSON.stringify(assessment, null, 2);
  const limit = 4000;
  jsonPreview.textContent = json.length > limit ? `${json.slice(0, limit)}\n...` : json;
}

async function refreshEmbeddedReport() {
  reportStatus.textContent = 'Loading report...';
  reportFrame.removeAttribute('src');
  reportFrame.srcdoc = '';

  const response = await fetch('/api/download/html');
  if (!response.ok) {
    let message = 'Failed to load HTML report.';
    try {
      const data = await response.json();
      message = data.error || message;
    } catch (error) {
      const text = await response.text();
      if (text) {
        message = text;
      }
    }
    throw new Error(message);
  }

  const html = await response.text();
  if (!html || html.length < 50) {
    throw new Error('HTML report is empty.');
  }

  reportFrame.srcdoc = html;
  reportStatus.textContent = 'Report loaded.';
}

async function runAssessment(token, note) {
  setStatus('running', 'Assessment in progress. This can take a few minutes.');
  enableDownloads(false);
  jsonPreview.textContent = 'Running assessment...';

  const response = await fetch('/api/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, note })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Failed to run assessment.');
  }

  return data.assessment;
}

async function loadLatestAssessment() {
  const response = await fetch('/api/assessment');
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'No assessment available.');
  }

  return data.assessment;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const token = tokenField.value.trim();
  const note = noteField.value.trim();

  if (!token) {
    setStatus('error', 'Token is required.');
    return;
  }

  try {
    const assessment = await runAssessment(token, note);
    updateStats(assessment);
    previewJson(assessment);
    await refreshEmbeddedReport();
    setStatus('done', 'Assessment completed successfully.');
    enableDownloads(true);
  } catch (error) {
    setStatus('error', error.message);
    jsonPreview.textContent = error.message;
    reportStatus.textContent = error.message;
  }
});

loadLatest.addEventListener('click', async () => {
  try {
    setStatus('running', 'Loading latest assessment...');
    const assessment = await loadLatestAssessment();
    updateStats(assessment);
    previewJson(assessment);
    await refreshEmbeddedReport();
    setStatus('done', 'Loaded latest assessment.');
    enableDownloads(true);
  } catch (error) {
    setStatus('error', error.message);
    jsonPreview.textContent = error.message;
    reportStatus.textContent = error.message;
  }
});

refreshReport.addEventListener('click', async () => {
  try {
    await refreshEmbeddedReport();
  } catch (error) {
    reportStatus.textContent = error.message;
  }
});

enableDownloads(false);
