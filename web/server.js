const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const AssessmentService = require('../src/core/services/assessmentService');
const HTMLExporter = require('../src/exporters/html');

const app = express();
const host = process.env.HOST || '127.0.0.1';
const envPort = Number.parseInt(process.env.PORT, 10);
const port = Number.isFinite(envPort) ? envPort : 0;
const dataDir = path.join(__dirname, 'data', 'assessments');
const latestPath = path.join(dataDir, 'latest.json');
const storageState = {
  ready: false,
  lastError: null
};

let lastAssessment = null;

async function ensureStorageDir() {
  try {
    await fs.promises.mkdir(dataDir, { recursive: true });
    storageState.ready = true;
    storageState.lastError = null;
  } catch (error) {
    storageState.ready = false;
    storageState.lastError = error.message;
  }
}

function getRequestId() {
  return crypto.randomUUID();
}

function setSecurityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'self'; base-uri 'self'; form-action 'self'"
  );
  next();
}

function createRateLimiter({ windowMs, max }) {
  const hits = new Map();

  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || 'unknown';
    const entry = hits.get(key);
    if (!entry || now - entry.start > windowMs) {
      hits.set(key, { start: now, count: 1 });
      return next();
    }

    entry.count += 1;
    if (entry.count > max) {
      return res.status(429).json({
        error: 'Rate limit exceeded. Try again later.',
        requestId: req.requestId
      });
    }

    return next();
  };
}

async function persistAssessment(assessment) {
  await ensureStorageDir();
  if (!storageState.ready) {
    return null;
  }

  const payload = JSON.stringify(assessment, null, 2);
  const filePath = path.join(dataDir, `${assessment.assessmentId}.json`);
  await fs.promises.writeFile(filePath, payload);
  await fs.promises.writeFile(latestPath, payload);
  return filePath;
}

async function loadLatestAssessmentFromDisk() {
  try {
    const content = await fs.promises.readFile(latestPath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    return null;
  }
}

async function loadAssessmentById(assessmentId) {
  try {
    const filePath = path.join(dataDir, `${assessmentId}.json`);
    const content = await fs.promises.readFile(filePath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    return null;
  }
}

async function listAssessments() {
  try {
    await ensureStorageDir();
    if (!storageState.ready) {
      return [];
    }
    const files = await fs.promises.readdir(dataDir);
    const entries = await Promise.all(
      files
        .filter(name => name.endsWith('.json') && name !== 'latest.json')
        .map(async name => {
          try {
            const content = await fs.promises.readFile(path.join(dataDir, name), 'utf8');
            const assessment = JSON.parse(content);
            return {
              id: assessment.assessmentId,
              status: assessment.status,
              startedAt: assessment.startedAt,
              completedAt: assessment.completedAt,
              accountName: assessment.account?.name || 'Unknown',
              score: assessment.score?.overallScore || 0,
              grade: assessment.score?.grade || 'F'
            };
          } catch (error) {
            return null;
          }
        })
    );
    return entries.filter(Boolean);
  } catch (error) {
    return [];
  }
}

function sendError(res, status, message, req) {
  return res.status(status).json({ error: message, requestId: req.requestId });
}

ensureStorageDir();

app.use(express.json({ limit: '2mb' }));
app.set('trust proxy', true);
app.use((req, res, next) => {
  req.requestId = getRequestId();
  res.setHeader('X-Request-Id', req.requestId);
  next();
});
app.use(setSecurityHeaders);
app.use('/api', createRateLimiter({ windowMs: 60 * 1000, max: 60 }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/assess', async (req, res) => {
  const token = (req.body && req.body.token) || '';
  const note = (req.body && req.body.note) || '';

  if (!token || token.length < 10) {
    return sendError(res, 400, 'Invalid Cloudflare API token.', req);
  }

  try {
    const assessmentService = new AssessmentService({ useSpinner: false });
    const assessment = await assessmentService.runAssessment({ apiToken: token }, { note });

    if (assessment.status === 'failed') {
      return sendError(res, 500, assessment.error || 'Assessment failed.', req);
    }

    lastAssessment = assessment;
    await persistAssessment(assessment);
    return res.json({ assessment });
  } catch (error) {
    return sendError(res, 500, error.message || 'Unexpected error.', req);
  }
});

app.get('/api/assessment', (req, res) => {
  if (lastAssessment) {
    return res.json({ assessment: lastAssessment });
  }

  loadLatestAssessmentFromDisk()
    .then(latest => {
      if (!latest) {
        return sendError(res, 404, 'No assessment available yet.', req);
      }
      lastAssessment = latest;
      return res.json({ assessment: latest });
    })
    .catch(() => sendError(res, 500, 'Failed to load assessment.', req));
});

app.get('/api/assessments', async (req, res) => {
  const entries = await listAssessments();
  return res.json({ assessments: entries });
});

app.get('/api/assessments/:id', async (req, res) => {
  const assessment = await loadAssessmentById(req.params.id);
  if (!assessment) {
    return sendError(res, 404, 'Assessment not found.', req);
  }
  return res.json({ assessment });
});

app.get('/api/download/json', (req, res) => {
  const respond = (assessment) => {
    if (!assessment) {
      return sendError(res, 404, 'No assessment available yet.', req);
    }
    const filename = 'flareinspect-assessment.json';
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(JSON.stringify(assessment, null, 2));
  };

  if (lastAssessment) {
    return respond(lastAssessment);
  }

  return loadLatestAssessmentFromDisk()
    .then(latest => {
      if (latest) {
        lastAssessment = latest;
      }
      return respond(latest);
    })
    .catch(() => sendError(res, 500, 'Failed to load assessment.', req));
});

app.get('/api/download/html', async (req, res) => {
  if (!lastAssessment) {
    lastAssessment = await loadLatestAssessmentFromDisk();
  }

  if (!lastAssessment) {
    return sendError(res, 404, 'No assessment available yet.', req);
  }

  try {
    const exporter = new HTMLExporter();
    const html = await exporter.export(lastAssessment);
    const filename = 'flareinspect-report.html';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(html);
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to generate HTML report.', req);
  }
});

app.get('/report', async (req, res) => {
  if (!lastAssessment) {
    lastAssessment = await loadLatestAssessmentFromDisk();
  }

  if (!lastAssessment) {
    return res.status(404).send('<h2>No assessment available yet.</h2>');
  }

  try {
    const exporter = new HTMLExporter();
    const html = await exporter.export(lastAssessment);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(html);
  } catch (error) {
    return res.status(500).send('<h2>Failed to generate HTML report.</h2>');
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    version: process.env.npm_package_version || 'unknown',
    lastAssessmentAt: lastAssessment?.completedAt || null,
    storage: {
      ready: storageState.ready,
      error: storageState.lastError
    }
  });
});

const server = app.listen(port, host, () => {
  const address = server.address();
  const actualPort = address && typeof address === 'object' ? address.port : port;
  console.log(`FlareInspect web app running on http://${host}:${actualPort}`);
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  return sendError(res, 500, err.message || 'Unexpected error.', req);
});
