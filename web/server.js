const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const AssessmentService = require('../src/core/services/assessmentService');
const ComplianceEngine = require('../src/core/services/complianceEngine');
const DiffService = require('../src/core/services/diffService');
const HTMLExporter = require('../src/exporters/html');
const SARIFExporter = require('../src/exporters/sarif');
const MarkdownExporter = require('../src/exporters/markdown');
const CSVExporter = require('../src/exporters/csv');
const ASFFExporter = require('../src/exporters/asff');
const CloudflareClient = require('../src/core/services/cloudflareClient');
const remediationEngine = require('../src/core/remediation/remediationEngine');
const backupManager = require('../src/core/remediation/backupManager');
const { createPlanner } = require('../src/core/ai/remediationPlanner');
const { buildResourceGraph } = require('../src/core/graph/resourceGraph');
const { findAttackPaths, RULES } = require('../src/core/graph/attackPaths');
const { SEVERITY_ORDER } = require('../src/core/graph/severity');
const notificationService = require('../src/core/integrations/notify/notificationService');
const { shipFindings: shipElastic, buildIndexTemplate: buildEsTemplate } = require('../src/core/integrations/siem/elastic');
const { shipFindings: shipSplunk } = require('../src/core/integrations/siem/splunk');
const EcsExporter = require('../src/exporters/ecs');
const SplunkHecExporter = require('../src/exporters/splunkHec');
const logger = require('../src/core/utils/logger');
const runtimeSettings = require('../src/core/config/runtimeSettings');
const pkg = require('../package.json');

// Swagger UI assets are bundled (offline-capable). Loaded lazily/softly so the
// server still boots if the optional dependency is absent.
let swaggerUiAssetPath = null;
try { swaggerUiAssetPath = require('swagger-ui-dist').getAbsoluteFSPath(); } catch (_) { swaggerUiAssetPath = null; }
const openapiPath = path.join(__dirname, 'openapi.json');
const ASSESSMENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_NOTE_LENGTH = 2000;
const MAX_ZONE_FILTERS = 100;
const MAX_CONCURRENCY = 10;
const ALLOWED_FRAMEWORKS = new Set(['cis', 'cis-benchmark', 'soc2', 'soc-2', 'pci', 'pci-dss', 'nist', 'nist-csf']);

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

const API_KEY = process.env.FLAREINSPECT_API_KEY || null;
// Remediation writes to live Cloudflare config and is OFF unless explicitly allowed.
const ALLOW_REMEDIATION = process.env.FLAREINSPECT_ALLOW_REMEDIATION === 'true';
const remediationDir = path.join(__dirname, 'data', 'remediation');
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

function authenticateApiKey(req, res, next) {
  if (!API_KEY) return next();
  const providedValue = req.headers['x-api-key'] || '';
  const provided = String(Array.isArray(providedValue) ? providedValue[0] : providedValue);
  const expectedBuffer = Buffer.from(API_KEY);
  const providedBuffer = Buffer.from(provided);
  if (providedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(providedBuffer, expectedBuffer)) {
    return res.status(401).json({ error: 'Unauthorized. Provide X-API-Key header.', requestId: req.requestId });
  }
  next();
}

function setSecurityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
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
  if (!isValidAssessmentId(assessmentId)) {
    return null;
  }
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

function sendUnexpectedError(res, error, req, context) {
  logger.error('Web request failed', {
    context,
    requestId: req.requestId,
    error: error?.message
  });
  return sendError(res, 500, 'Unexpected error.', req);
}

function isValidAssessmentId(value) {
  return typeof value === 'string' && ASSESSMENT_ID_PATTERN.test(value);
}

function parseCsvList(value, { maxItems = MAX_ZONE_FILTERS } = {}) {
  if (typeof value !== 'string') {
    return [];
  }

  const items = value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);

  if (items.length > maxItems) {
    throw new Error(`Too many items supplied. Maximum allowed is ${maxItems}.`);
  }

  return items;
}

function parseOptionalConcurrency(value) {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }

  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_CONCURRENCY) {
    throw new Error(`Concurrency must be an integer between 1 and ${MAX_CONCURRENCY}.`);
  }

  return parsed;
}

function parseOptionalNote(value) {
  if (value === undefined || value === null || value === '') {
    return '';
  }

  const note = String(value);
  if (note.length > MAX_NOTE_LENGTH) {
    throw new Error(`Note must be ${MAX_NOTE_LENGTH} characters or fewer.`);
  }

  return note;
}

function parseOptionalFramework(value) {
  if (value === undefined || value === null || value === '') {
    return null;
  }

  const framework = String(value).trim().toLowerCase();
  if (!ALLOWED_FRAMEWORKS.has(framework)) {
    throw new Error('Unknown compliance framework.');
  }

  return framework;
}

function parseAssessmentRequest(body = {}) {
  const token = typeof body.token === 'string' ? body.token.trim() : '';
  if (token.length < 10 || token.length > 512) {
    throw new Error('Invalid Cloudflare API token.');
  }

  return {
    token,
    note: parseOptionalNote(body.note),
    zones: parseCsvList(body.zones),
    concurrency: parseOptionalConcurrency(body.concurrency),
    compliance: parseOptionalFramework(body.compliance)
  };
}

function parseDiffRequest(body = {}) {
  const baselineId = typeof body.baselineId === 'string' ? body.baselineId.trim() : '';
  const currentId = typeof body.currentId === 'string' ? body.currentId.trim() : '';

  if (!isValidAssessmentId(baselineId) || !isValidAssessmentId(currentId)) {
    throw new Error('baselineId and currentId must be valid assessment IDs.');
  }

  return { baselineId, currentId };
}

ensureStorageDir();

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));
app.use(express.json({ limit: '2mb' }));
app.set('trust proxy', true);
app.use((req, res, next) => {
  req.requestId = getRequestId();
  res.setHeader('X-Request-Id', req.requestId);
  next();
});
app.use(setSecurityHeaders);
app.use('/api', authenticateApiKey, createRateLimiter({ windowMs: 60 * 1000, max: 60 }));
app.use(express.static(path.join(__dirname, 'public')));

// Assessment endpoint
app.post('/api/assess', async (req, res) => {
  try {
    const request = parseAssessmentRequest(req.body);
    const assessmentService = new AssessmentService({ useSpinner: false });
    const assessOptions = { note: request.note };

    if (request.zones.length > 0) {
      assessOptions.zones = request.zones;
    }
    if (request.concurrency !== undefined) {
      assessOptions.concurrency = request.concurrency;
    }

    const assessment = await assessmentService.runAssessment({ apiToken: request.token }, assessOptions);

    if (request.compliance) {
      const complianceEngine = new ComplianceEngine();
      assessment.complianceReport = complianceEngine.getComplianceReport(assessment.findings || []);
    }

    if (assessment.status === 'failed') {
      return sendError(res, 500, assessment.error || 'Assessment failed.', req);
    }

    lastAssessment = assessment;
    await persistAssessment(assessment);
    return res.json({ assessment });
  } catch (error) {
    if (error.message && (
      error.message.startsWith('Invalid Cloudflare API token') ||
      error.message.startsWith('Too many items supplied') ||
      error.message.startsWith('Concurrency must') ||
      error.message.startsWith('Note must') ||
      error.message.startsWith('Unknown compliance framework')
    )) {
      return sendError(res, 400, error.message, req);
    }
    return sendUnexpectedError(res, error, req, 'assess');
  }
});

// Get latest assessment
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
    .catch(error => sendUnexpectedError(res, error, req, 'latest-assessment'));
});

// List all assessments
app.get('/api/assessments', async (req, res) => {
  const entries = await listAssessments();
  return res.json({ assessments: entries });
});

// Get specific assessment
app.get('/api/assessments/:id', async (req, res) => {
  const assessment = await loadAssessmentById(req.params.id);
  if (!assessment) {
    return sendError(res, 404, 'Assessment not found.', req);
  }
  return res.json({ assessment });
});

// Resource graph + attack paths (Foundation phase — single source of truth
// shared by the Posture map UI, the SIEM exporters, and the MCP server).
app.get('/api/posture/graph', async (req, res) => {
  try {
    const assessmentId = req.query.assessmentId ? String(req.query.assessmentId) : null;
    if (assessmentId && !isValidAssessmentId(assessmentId)) {
      return sendError(res, 400, 'Invalid assessmentId.', req);
    }
    const assessment = assessmentId
      ? await loadAssessmentById(assessmentId)
      : (lastAssessment || await loadLatestAssessmentFromDisk());
    if (!assessment) {
      return sendError(res, 404, 'No assessment available yet.', req);
    }
    if (assessmentId) lastAssessment = assessment;

    const graph = buildResourceGraph(assessment);
    const paths = findAttackPaths(graph, assessment);
    return res.json({
      meta: {
        assessmentId: assessment.assessmentId,
        generatedAt: new Date().toISOString(),
        rules: RULES.map(kind => ({ kind })),
        severityOrder: SEVERITY_ORDER
      },
      graph,
      paths
    });
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'posture-graph');
  }
});

// Notification endpoint — POST /api/notify
// Body: { assessment: { ... } | assessmentId?, target?: 'all'|'slack'|'teams'|'webhook',
//                      threshold?, link?, dryRun? }
// Secrets come from env (FLAREINSPECT_*_WEBHOOK) — never from the request body.
app.post('/api/notify', async (req, res) => {
  try {
    const body = req.body || {};
    let assessment = body.assessment;
    if (!assessment && body.assessmentId) {
      if (!isValidAssessmentId(body.assessmentId)) return sendError(res, 400, 'Invalid assessmentId.', req);
      assessment = await loadAssessmentById(body.assessmentId);
      if (!assessment) return sendError(res, 404, 'Assessment not found.', req);
    }
    if (!assessment) {
      assessment = lastAssessment || await loadLatestAssessmentFromDisk();
    }
    if (!assessment) return sendError(res, 400, 'Provide an assessment, assessmentId, or run /api/assess first.', req);

    // Channel URLs/secret resolve from the runtime settings overlay first, then env.
    const cfgTargets = {
      slack:   runtimeSettings.resolve('slackWebhook'),
      teams:   runtimeSettings.resolve('teamsWebhook'),
      webhook: runtimeSettings.resolve('webhookUrl'),
      secret:  runtimeSettings.resolve('webhookSecret'),
      threshold: runtimeSettings.resolve('notifyThreshold')
    };
    const target = String(body.target || 'all').toLowerCase();
    const want = (k) => target === 'all' || target === k;
    const targets = {
      slack:   want('slack')   ? cfgTargets.slack   : null,
      teams:   want('teams')   ? cfgTargets.teams   : null,
      webhook: want('webhook') ? cfgTargets.webhook : null,
      secret:  cfgTargets.secret,
      threshold: body.threshold || cfgTargets.threshold,
      dryRun: !!body.dryRun
    };

    const summary = notificationService.buildSummary(assessment, {
      link: body.link || null,
      attackPathCount: body.attackPathCount
    });
    const result = await notificationService.dispatch(summary, targets);
    if (body.dryRun) {
      return res.json({ ok: result.ok, sent: result.sent, skipped: result.skipped, errors: result.errors, payloads: result.payloads });
    }
    return res.json({ ok: result.ok, sent: result.sent, skipped: result.skipped, errors: result.errors });
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'notify');
  }
});

// SIEM ship endpoint — POST /api/integrations/ship
// Body: { assessment?, assessmentId?, target: 'elastic'|'splunk'|'all'|'file',
//         esUrl?, esApiKey?, esUsername?, esPassword?, hecUrl?, hecToken?,
//         indexName?, splunkIndex?, outDir?, dryRun? }
// Secrets are read from request body OR env (FLAREINSPECT_ES_URL/_ES_APIKEY, etc.).
app.post('/api/integrations/ship', async (req, res) => {
  try {
    const body = req.body || {};
    let assessment = body.assessment;
    if (!assessment && body.assessmentId) {
      if (!isValidAssessmentId(body.assessmentId)) return sendError(res, 400, 'Invalid assessmentId.', req);
      assessment = await loadAssessmentById(body.assessmentId);
      if (!assessment) return sendError(res, 404, 'Assessment not found.', req);
    }
    if (!assessment) {
      assessment = lastAssessment || await loadLatestAssessmentFromDisk();
    }
    if (!assessment) return sendError(res, 400, 'Provide an assessment, assessmentId, or run /api/assess first.', req);

    const target = String(body.target || 'all').toLowerCase();
    const want = (k) => target === 'all' || target === k;

    // File export branch — no live HTTP, just NDJSON to disk.
    if (target === 'file' || body.outDir) {
      const dir = body.outDir || `./out-${Date.now()}`;
      const ecs = new EcsExporter({ indexName: body.indexName || 'flareinspect-findings' });
      const hec = new SplunkHecExporter();
      const ecsR = await ecs.exportToFile(assessment, dir);
      const hecR = await hec.exportToFile(assessment, dir);
      return res.json({ ok: true, target: 'file', dir, files: { ecs: ecsR.file, hec: ecsR.file }, counts: { ecs: ecsR.count, hec: hecR.count } });
    }

    const result = { ok: true, target, elastic: null, splunk: null };

    if (want('elastic')) {
      const esUrl    = body.esUrl    || runtimeSettings.resolve('esUrl');
      const apiKey   = body.esApiKey || runtimeSettings.resolve('esApiKey');
      const username = body.esUsername || runtimeSettings.resolve('esUsername');
      const password = body.esPassword || runtimeSettings.resolve('esPassword');
      if (!esUrl) return sendError(res, 400, 'Missing esUrl (or FLAREINSPECT_ES_URL env).', req);
      if (!apiKey && !(username && password)) {
        return sendError(res, 400, 'Missing credentials: provide esApiKey OR (esUsername + esPassword).', req);
      }
      result.elastic = await shipElastic({
        esUrl, apiKey, username, password, assessment,
        indexName: body.indexName || 'flareinspect-findings',
        dryRun: !!body.dryRun
      });
      if (!result.elastic.ok) result.ok = false;
    }

    if (want('splunk')) {
      const hecUrl   = body.hecUrl   || runtimeSettings.resolve('hecUrl');
      const hecToken = body.hecToken || runtimeSettings.resolve('hecToken');
      if (!hecUrl)   return sendError(res, 400, 'Missing hecUrl (or FLAREINSPECT_SPLUNK_HEC_URL env).', req);
      if (!hecToken) return sendError(res, 400, 'Missing hecToken (or FLAREINSPECT_SPLUNK_HEC_TOKEN env).', req);
      result.splunk = await shipSplunk({ hecUrl, hecToken, assessment, dryRun: !!body.dryRun });
      if (!result.splunk.ok) result.ok = false;
    }

    // Echo the index template (so dashboards can be wired off the same response).
    if (body.includeTemplate) {
      result.indexTemplate = buildEsTemplate();
    }
    return res.json(result);
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'ship');
  }
});

// GET /api/integrations/template/elastic — returns the recommended ES index template
app.get('/api/integrations/template/elastic', (req, res) => {
  res.json(buildEsTemplate());
});

// ---------------------------------------------------------------------------
// Runtime settings — an overlay on top of .env so notifications, the AI planner,
// and SIEM credentials can be configured from the dashboard without a restart.
// Secrets are write-only: GET never returns a raw secret (masked view only).
// The remediation kill-switch / edit-scope stay env-only by design.
// ---------------------------------------------------------------------------
app.get('/api/settings', (req, res) => {
  try {
    return res.json({ settings: runtimeSettings.maskedView(), remediation: ALLOW_REMEDIATION ? 'enabled' : 'disabled' });
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'settings-get');
  }
});

app.put('/api/settings', (req, res) => {
  try {
    runtimeSettings.saveSettings(req.body || {});
    return res.json({ ok: true, settings: runtimeSettings.maskedView() });
  } catch (error) {
    if (/^(Settings payload must be|Invalid value for)/.test(error.message || '')) {
      return sendError(res, 400, error.message, req);
    }
    return sendUnexpectedError(res, error, req, 'settings-put');
  }
});

// ---------------------------------------------------------------------------
// API documentation — bundled Swagger UI (offline) + the raw OpenAPI 3 spec.
// Served outside the /api prefix so the docs render even when an API key is set.
// ---------------------------------------------------------------------------
app.get('/api-docs/openapi.json', (req, res) => {
  res.sendFile(openapiPath, err => {
    if (err && !res.headersSent) res.status(404).json({ error: 'OpenAPI spec not found.' });
  });
});

if (swaggerUiAssetPath) {
  app.use('/api-docs/assets', express.static(swaggerUiAssetPath));
}

app.get('/api-docs', (req, res) => {
  if (!swaggerUiAssetPath) {
    return res
      .type('html')
      .send('<!doctype html><meta charset="utf-8"><title>FlareInspect API</title>'
        + '<body style="font-family:sans-serif;max-width:640px;margin:60px auto;padding:0 20px">'
        + '<h1>API documentation</h1>'
        + '<p>The bundled Swagger UI is not installed. Run <code>npm install</code> to add '
        + '<code>swagger-ui-dist</code>, or view the raw spec:</p>'
        + '<p><a href="/api-docs/openapi.json">/api-docs/openapi.json</a></p></body>');
  }
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>FlareInspect API — Swagger UI</title>
  <link rel="icon" type="image/svg+xml" href="/flare-inspect-glyph.svg" />
  <link rel="stylesheet" href="/api-docs/assets/swagger-ui.css" />
  <style>body{margin:0;background:#0e0e14}.topbar{display:none}</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/api-docs/assets/swagger-ui-bundle.js"></script>
  <script src="/api-docs/assets/swagger-ui-standalone-preset.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: '/api-docs/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
      layout: 'BaseLayout'
    });
  </script>
</body>
</html>`);
});

// Compliance endpoint
app.get('/api/compliance/:framework', (req, res) => {
  const respondWithCompliance = (assessment) => {
    if (!assessment) {
      return sendError(res, 404, 'No assessment available yet.', req);
    }

    try {
      const complianceEngine = new ComplianceEngine();
      return res.json({
        compliance: complianceEngine.mapFindingsToFramework(
          assessment.findings || [],
          req.params.framework
        )
      });
    } catch (error) {
      return sendError(res, 400, error.message, req);
    }
  };

  if (lastAssessment) {
    return respondWithCompliance(lastAssessment);
  }

  return loadLatestAssessmentFromDisk()
    .then(latest => {
      if (latest) {
        lastAssessment = latest;
      }
      return respondWithCompliance(latest);
    })
    .catch(error => sendUnexpectedError(res, error, req, 'compliance'));
});

// Diff endpoint
app.post('/api/diff', async (req, res) => {
  try {
    const { baselineId, currentId } = parseDiffRequest(req.body);

    const [baseline, current] = await Promise.all([
      loadAssessmentById(baselineId),
      loadAssessmentById(currentId)
    ]);

    if (!baseline) return sendError(res, 404, 'Baseline assessment not found.', req);
    if (!current) return sendError(res, 404, 'Current assessment not found.', req);

    const diffService = new DiffService();
    const diff = diffService.compare(baseline, current);
    return res.json({ diff });
  } catch (error) {
    if (error.message === 'baselineId and currentId must be valid assessment IDs.') {
      return sendError(res, 400, error.message, req);
    }
    return sendUnexpectedError(res, error, req, 'diff');
  }
});

// ---------------------------------------------------------------------------
// Remediation endpoints
// ---------------------------------------------------------------------------
function parseRemediationToken(body = {}) {
  const token = typeof body.token === 'string' ? body.token.trim() : '';
  if (token.length < 10 || token.length > 512) {
    throw new Error('Invalid Cloudflare API token.');
  }
  return token;
}

async function resolveAssessment(body = {}) {
  if (body.assessmentId && isValidAssessmentId(String(body.assessmentId))) {
    return loadAssessmentById(String(body.assessmentId));
  }
  return lastAssessment || (await loadLatestAssessmentFromDisk());
}

function plannerFromBody(body = {}) {
  // Provider/model may be supplied per-request; otherwise fall back to the
  // runtime settings overlay (then env). API keys/base URL come from the
  // settings overlay or env — never from the request body.
  const ai = body.ai || {};
  const provider = (ai.provider || runtimeSettings.resolve('aiProvider') || 'none').toLowerCase();
  const model = ai.model || runtimeSettings.resolve('aiModel') || undefined;
  const apiKey = provider === 'anthropic'
    ? runtimeSettings.resolve('anthropicApiKey')
    : (provider === 'openai' ? runtimeSettings.resolve('openaiApiKey') : undefined);
  const baseUrl = (provider === 'ollama' || provider === 'local')
    ? runtimeSettings.resolve('ollamaHost') || undefined
    : undefined;
  return createPlanner({ provider, model, apiKey: apiKey || undefined, baseUrl });
}

// Dry-run plan — read-only, no remediation gate required (still needs API key).
app.post('/api/remediate/plan', async (req, res) => {
  try {
    const token = parseRemediationToken(req.body);
    const assessment = await resolveAssessment(req.body);
    if (!assessment) return sendError(res, 404, 'No assessment available to plan against.', req);

    const client = new CloudflareClient(token);
    const planner = plannerFromBody(req.body);
    const plan = await remediationEngine.buildPlan(assessment, {
      client, planner,
      checks: parseCsvList(req.body.checks, { maxItems: 200 }),
      zones: parseCsvList(req.body.zones),
      excludeZones: parseCsvList(req.body.excludeZones)
    });
    return res.json({ plan, allowApply: ALLOW_REMEDIATION });
  } catch (error) {
    if (error.message === 'Invalid Cloudflare API token.') {
      return sendError(res, 400, error.message, req);
    }
    return sendUnexpectedError(res, error, req, 'remediate-plan');
  }
});

// Apply — gated behind FLAREINSPECT_ALLOW_REMEDIATION.
app.post('/api/remediate/apply', async (req, res) => {
  if (!ALLOW_REMEDIATION) {
    return sendError(res, 403, 'Remediation is disabled. Set FLAREINSPECT_ALLOW_REMEDIATION=true to enable.', req);
  }
  try {
    const token = parseRemediationToken(req.body);
    const assessment = await resolveAssessment(req.body);
    if (!assessment) return sendError(res, 404, 'No assessment available to remediate.', req);

    const client = new CloudflareClient(token);
    const planner = plannerFromBody(req.body);
    const plan = await remediationEngine.buildPlan(assessment, {
      client, planner,
      checks: parseCsvList(req.body.checks, { maxItems: 200 }),
      zones: parseCsvList(req.body.zones),
      excludeZones: parseCsvList(req.body.excludeZones)
    });

    // Approve only the checkIds the client explicitly selected; high-risk needs force.
    const selected = Array.isArray(req.body.checkIds) ? new Set(req.body.checkIds.map(String)) : null;
    const force = req.body.force === true;
    const approved = plan.items.filter(item => {
      if (selected && !selected.has(item.checkId)) return false;
      if (item.risk === 'high' && !force) return false;
      return true;
    });

    if (!approved.length) {
      return res.json({ applied: [], bundleFile: null, message: 'No changes approved.' });
    }

    const result = await remediationEngine.apply(approved, {
      client, backupDir: remediationDir, assessment
    });
    return res.json({
      applied: result.results,
      bundleFile: result.bundlePath ? path.basename(result.bundlePath) : null
    });
  } catch (error) {
    if (error.message === 'Invalid Cloudflare API token.') {
      return sendError(res, 400, error.message, req);
    }
    return sendUnexpectedError(res, error, req, 'remediate-apply');
  }
});

// List backup bundles.
app.get('/api/remediate/backups', (req, res) => {
  try {
    return res.json({ backups: backupManager.listBundles(remediationDir) });
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'remediate-backups');
  }
});

// Rollback — gated behind FLAREINSPECT_ALLOW_REMEDIATION.
app.post('/api/remediate/rollback', async (req, res) => {
  if (!ALLOW_REMEDIATION) {
    return sendError(res, 403, 'Remediation is disabled. Set FLAREINSPECT_ALLOW_REMEDIATION=true to enable.', req);
  }
  try {
    const token = parseRemediationToken(req.body);
    const file = typeof req.body.bundleFile === 'string' ? path.basename(req.body.bundleFile) : '';
    if (!file.endsWith('.backup.json')) {
      return sendError(res, 400, 'bundleFile must be a .backup.json file.', req);
    }
    const bundlePath = path.join(remediationDir, file);
    if (!fs.existsSync(bundlePath)) {
      return sendError(res, 404, 'Backup bundle not found.', req);
    }

    const bundle = backupManager.loadBundle(bundlePath); // validates checksum
    const client = new CloudflareClient(token);
    const result = await remediationEngine.rollback(bundle, { client, backupDir: remediationDir });
    return res.json({
      results: result.results,
      reportFile: result.reportPath ? path.basename(result.reportPath) : null
    });
  } catch (error) {
    if (error.message === 'Invalid Cloudflare API token.') {
      return sendError(res, 400, error.message, req);
    }
    return sendUnexpectedError(res, error, req, 'remediate-rollback');
  }
});

// Download endpoints
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
    .catch(error => sendUnexpectedError(res, error, req, 'download-json'));
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
    return sendUnexpectedError(res, error, req, 'download-html');
  }
});

app.get('/api/download/sarif', async (req, res) => {
  if (!lastAssessment) {
    lastAssessment = await loadLatestAssessmentFromDisk();
  }
  if (!lastAssessment) {
    return sendError(res, 404, 'No assessment available yet.', req);
  }

  try {
    const exporter = new SARIFExporter();
    const data = await exporter.export(lastAssessment);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="flareinspect-findings.sarif"');
    return res.send(JSON.stringify(data, null, 2));
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'download-sarif');
  }
});

app.get('/api/download/markdown', async (req, res) => {
  if (!lastAssessment) {
    lastAssessment = await loadLatestAssessmentFromDisk();
  }
  if (!lastAssessment) {
    return sendError(res, 404, 'No assessment available yet.', req);
  }

  try {
    const exporter = new MarkdownExporter();
    const data = await exporter.export(lastAssessment);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="flareinspect-report.md"');
    return res.send(data);
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'download-markdown');
  }
});

app.get('/api/download/csv', async (req, res) => {
  if (!lastAssessment) {
    lastAssessment = await loadLatestAssessmentFromDisk();
  }
  if (!lastAssessment) {
    return sendError(res, 404, 'No assessment available yet.', req);
  }

  try {
    const exporter = new CSVExporter();
    const data = await exporter.export(lastAssessment);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="flareinspect-findings.csv"');
    return res.send(data);
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'download-csv');
  }
});

app.get('/api/download/asff', async (req, res) => {
  if (!lastAssessment) {
    lastAssessment = await loadLatestAssessmentFromDisk();
  }
  if (!lastAssessment) {
    return sendError(res, 404, 'No assessment available yet.', req);
  }

  try {
    const exporter = new ASFFExporter();
    const data = await exporter.export(lastAssessment);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="flareinspect-findings.asff.json"');
    return res.send(JSON.stringify(data, null, 2));
  } catch (error) {
    return sendUnexpectedError(res, error, req, 'download-asff');
  }
});

// Report viewer
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

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    version: pkg.version || process.env.npm_package_version || 'unknown',
    lastAssessmentAt: lastAssessment?.completedAt || null,
    storage: {
      ready: storageState.ready,
      error: storageState.lastError
    },
    auth: API_KEY ? 'api-key' : 'none',
    remediation: ALLOW_REMEDIATION ? 'enabled' : 'disabled'
  });
});

// Only start listening when this file is the process entry point. When
// `require()`'d (e.g. from tests), we expose `app` for an in-process
// `supertest`/raw-http test harness without auto-binding a port.
if (require.main === module) {
  const server = app.listen(port, host, () => {
    const address = server.address();
    const actualPort = address && typeof address === 'object' ? address.port : port;
    console.log(`FlareInspect web app running on http://${host}:${actualPort}`);
    if (API_KEY) {
      console.log('API key authentication enabled');
    }
  });
}

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  return sendUnexpectedError(res, err, req, 'middleware');
});

module.exports = { app };
