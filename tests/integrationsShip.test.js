/**
 * Tests for POST /api/integrations/ship and GET /api/integrations/template/elastic
 *
 * Strategy: import the Express `app` from web/server.js (no auto-listen when
 * required), bind it to a random port, exercise the endpoints with raw http.
 * Mock https so live ship is captured, not actually POSTed.
 * Mock fs.promises.readFile for the in-memory assessment input.
 */

'use strict';

const http = require('http');
const fs   = require('fs').promises;
const path = require('path');
const os   = require('os');

let server;
let baseUrl;
let tmpDir;

jest.mock('p-limit', () => ({ default: (n) => (fn) => fn() }));

jest.mock('https', () => {
  const handlers = new Map();
  function setHandler(host, h) { handlers.set(host, h); }
  function request(opts, cb) {
    const h = handlers.get(opts.hostname) || defaultHandler;
    return h(opts, cb);
  }
  function defaultHandler() {
    return { on() {}, write() {}, end() {}, destroy() {} };
  }
  // agentkeepalive (a transitive dep of cloudflare) needs https.Agent;
  // export a minimal stub so the require chain doesn't blow up.
  class Agent {
    createConnection(opts, cb) { return null; }
  }
  return { request, Agent, __setHandler: setHandler, __clear: () => handlers.clear() };
});

const https = require('https');
const { __setHandler, __clear } = https;

function captureHandler({ status = 200, body = '{}' } = {}) {
  const state = { req: null, body: null, headers: null };
  const h = (opts, cb) => {
    state.req = opts;
    state.headers = opts.headers;
    return {
      on() {},
      write(b) { state.body = b; },
      end() {
        setImmediate(() => {
          const res = { statusCode: status, on(e, c) { if (e === 'data') c(body); if (e === 'end') c(); } };
          if (cb) cb(res);
        });
      },
      destroy() {}
    };
  };
  h.state = state;
  return h;
}

const assessment = {
  assessmentId: 'ast-api-1',
  account: { id: 'acct-1', name: 'Acme' },
  zones: [{ id: 'z1', name: 'x.test' }],
  configuration: { zones: { 'x.test': { dns: { records: [
    { id: 'r1', name: 'a.x.test', type: 'A', content: '203.0.113.1', proxied: false }
  ] } } } },
  findings: [
    { id: 'f1', checkId: 'CFL-INSIGHT-005', severity: 'high', status: 'failed',
      title: 'Exposed origin', resource: { type: 'dns_record', zoneId: 'z1', id: 'r1', name: 'a.x.test' } }
  ]
};

function httpRequest(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = {
      method,
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      headers: { 'content-type': 'application/json' }
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: data, json: data ? JSON.parse(data) : null }); }
        catch (_) { resolve({ status: res.statusCode, body: data, json: null }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

const originalReadFile = fs.readFile;

beforeAll(async () => {
  const { app } = require('../web/server');
  server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  if (server) await new Promise((r) => server.close(r));
});

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'flareinspect-api-'));
  __clear();
  jest.spyOn(fs, 'readFile').mockImplementation(async (p, ...rest) => {
    if (typeof p === 'string' && (p === 'ast.json' || p.endsWith('ast.json'))) {
      return JSON.stringify(assessment);
    }
    return originalReadFile.call(fs, p, ...rest);
  });
});

afterEach(async () => {
  jest.restoreAllMocks();
  if (tmpDir) await fs.rm(tmpDir, { recursive: true, force: true });
});

describe('GET /api/integrations/template/elastic', () => {
  test('returns the index template', async () => {
    const r = await httpRequest('GET', `${baseUrl}/api/integrations/template/elastic`);
    expect(r.status).toBe(200);
    expect(r.json.index_patterns).toEqual(['flareinspect-*']);
    expect(r.json.template.mappings.properties).toBeDefined();
  });
});

describe('POST /api/integrations/ship', () => {
  test('dry-run elastic returns body', async () => {
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'elastic',
      esUrl: 'https://e',
      esApiKey: 'K',
      assessment,
      dryRun: true
    });
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(r.json.elastic.count).toBe(1);
    expect(r.json.elastic.dryRun).toBe(true);
  });

  test('dry-run splunk returns events', async () => {
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'splunk',
      hecUrl: 'https://h',
      hecToken: 'T',
      assessment,
      dryRun: true
    });
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(r.json.splunk.count).toBe(1);
    expect(r.json.splunk.events).toHaveLength(1);
  });

  test('live elastic: posts to /_bulk with ApiKey', async () => {
    const h = captureHandler({ status: 200, body: JSON.stringify({ items: [{}] }) });
    __setHandler('es.example.com', h);
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'elastic',
      esUrl: 'https://es.example.com',
      esApiKey: 'KEY',
      assessment
    });
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(r.json.elastic.status).toBe(200);
    expect(h.state.headers.authorization).toBe('ApiKey KEY');
    expect(h.state.req.path).toBe('/_bulk');
  });

  test('live splunk: posts to HEC', async () => {
    const h = captureHandler({ status: 200, body: '{"ackId":1}' });
    __setHandler('splunk.example.com', h);
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'splunk',
      hecUrl: 'https://splunk.example.com:8088',
      hecToken: 'TOK',
      assessment
    });
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(r.json.splunk.sent).toBe(1);
    expect(h.state.headers.authorization).toBe('Splunk TOK');
  });

  test('missing esUrl -> 400', async () => {
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'elastic', esApiKey: 'K', assessment
    });
    expect(r.status).toBe(400);
  });

  test('missing creds -> 400', async () => {
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'elastic', esUrl: 'https://e', assessment
    });
    expect(r.status).toBe(400);
  });

  test('file mode writes to outDir', async () => {
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'file', outDir: tmpDir, assessment
    });
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(r.json.dir).toBe(tmpDir);
    const dir = await fs.readdir(tmpDir);
    expect(dir.length).toBeGreaterThanOrEqual(2);
  });

  test('includeTemplate echoes the index template', async () => {
    const r = await httpRequest('POST', `${baseUrl}/api/integrations/ship`, {
      target: 'elastic',
      esUrl: 'https://e', esApiKey: 'K', assessment,
      dryRun: true,
      includeTemplate: true
    });
    expect(r.status).toBe(200);
    expect(r.json.indexTemplate).toBeDefined();
    expect(r.json.indexTemplate.index_patterns).toEqual(['flareinspect-*']);
  });
});
