/**
 * Unit tests for src/cli/commands/ship.js
 *
 * Phase 2b — `flareinspect ship` CLI. The module wraps the engine-level
 * shipFindings and adds:
 *   - target dispatch (elastic | splunk | all | file)
 *   - arg + env merging for both vendors
 *   - dry-run support (no HTTP / no file write)
 *   - file mode (writes NDJSON via the file exporters)
 *   - error aggregation across multiple targets
 *
 * Tests mock `https` (so live path doesn't reach out) and `fs.promises`
 * (so file mode doesn't write to disk).
 */

'use strict';

const fs = require('fs').promises;
const os   = require('os');
const path = require('path');
const { EventEmitter } = require('events');

// Mock https so live ship doesn't actually open a socket.
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
  return { request, __setHandler: setHandler, __clear: () => handlers.clear() };
});

const https = require('https');
const { __setHandler, __clear } = https;

let tmpDir;

function makeHandler({ status = 200, body = '{}' } = {}) {
  const state = { req: null, body: null, headers: null };
  const handler = (opts, cb) => {
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
  handler.state = state;
  return handler;
}

const assessment = {
  assessmentId: 'ast-ship-1',
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

// Mock fs.promises.readFile for the in-memory assessment input.
const originalReadFile = fs.readFile;
beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'flareinspect-ship-'));
  __clear();
  jest.spyOn(fs, 'readFile').mockImplementation(async (p, ...rest) => {
    if (typeof p === 'string' && p === 'ast.json') return JSON.stringify(assessment);
    return originalReadFile.call(fs, p, ...rest);
  });
});
afterEach(async () => {
  jest.restoreAllMocks();
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe('ship.pickEsTargets / pickSplunkTargets', () => {
  const ship = require('../src/cli/commands/ship');

  test('picks CLI args over env', () => {
    const t = ship.pickEsTargets({ esUrl: 'https://cli', esApiKey: 'CLI' });
    expect(t.esUrl).toBe('https://cli');
    expect(t.apiKey).toBe('CLI');
  });

  test('falls back to env when CLI args missing', () => {
    const oldUrl = process.env.FLAREINSPECT_ES_URL;
    const oldKey = process.env.FLAREINSPECT_ES_APIKEY;
    process.env.FLAREINSPECT_ES_URL = 'https://env';
    process.env.FLAREINSPECT_ES_APIKEY = 'ENV';
    try {
      const t = ship.pickEsTargets({});
      expect(t.esUrl).toBe('https://env');
      expect(t.apiKey).toBe('ENV');
    } finally {
      if (oldUrl == null) delete process.env.FLAREINSPECT_ES_URL;
      else process.env.FLAREINSPECT_ES_URL = oldUrl;
      if (oldKey == null) delete process.env.FLAREINSPECT_ES_APIKEY;
      else process.env.FLAREINSPECT_ES_APIKEY = oldKey;
    }
  });

  test('splunk picks hecUrl/hecToken from CLI or env', () => {
    const oldUrl = process.env.FLAREINSPECT_SPLUNK_HEC_URL;
    process.env.FLAREINSPECT_SPLUNK_HEC_URL = 'https://env-splunk';
    try {
      const t = ship.pickSplunkTargets({ hecToken: 'TOK' });
      expect(t.hecUrl).toBe('https://env-splunk');
      expect(t.hecToken).toBe('TOK');
    } finally {
      if (oldUrl == null) delete process.env.FLAREINSPECT_SPLUNK_HEC_URL;
      else process.env.FLAREINSPECT_SPLUNK_HEC_URL = oldUrl;
    }
  });
});

describe('ship.shipToElastic', () => {
  const ship = require('../src/cli/commands/ship');

  test('dry-run returns body without HTTP', async () => {
    const r = await ship.shipToElastic(assessment, { esUrl: 'https://e', esApiKey: 'K', dryRun: true });
    expect(r.ok).toBe(true);
    expect(r.dryRun).toBe(true);
    expect(r.count).toBe(1);
    expect(r.body).toContain('vulnerability.id');
  });

  test('live ship uses ApiKey', async () => {
    const h = makeHandler({ status: 200, body: JSON.stringify({ items: [{}] }) });
    __setHandler('es.example.com', h);
    const r = await ship.shipToElastic(assessment, { esUrl: 'https://es.example.com', esApiKey: 'K' });
    expect(r.ok).toBe(true);
    expect(h.state.headers.authorization).toBe('ApiKey K');
    expect(h.state.req.path).toBe('/_bulk');
  });

  test('throws when URL missing', async () => {
    await expect(ship.shipToElastic(assessment, { esApiKey: 'K' })).rejects.toThrow(/es-url/i);
  });

  test('throws when auth missing', async () => {
    await expect(ship.shipToElastic(assessment, { esUrl: 'https://e' })).rejects.toThrow(/api-?key|username|password/i);
  });
});

describe('ship.shipToSplunk', () => {
  const ship = require('../src/cli/commands/ship');

  test('dry-run returns events without HTTP', async () => {
    const r = await ship.shipToSplunk(assessment, { hecUrl: 'https://h', hecToken: 'T', dryRun: true });
    expect(r.ok).toBe(true);
    expect(r.dryRun).toBe(true);
    expect(r.events).toHaveLength(1);
  });

  test('live ship posts to HEC', async () => {
    const h = makeHandler({ status: 200, body: '{"ackId":7}' });
    __setHandler('splunk.example.com', h);
    const r = await ship.shipToSplunk(assessment, { hecUrl: 'https://splunk.example.com:8088', hecToken: 'T' });
    expect(r.ok).toBe(true);
    expect(r.sent).toBe(1);
    expect(h.state.headers.authorization).toBe('Splunk T');
  });

  test('throws when URL or token missing', async () => {
    await expect(ship.shipToSplunk(assessment, { hecToken: 'T' })).rejects.toThrow(/hec-url/i);
    await expect(ship.shipToSplunk(assessment, { hecUrl: 'https://h' })).rejects.toThrow(/hec-token/i);
  });
});

describe('ship.exportToFiles', () => {
  const ship = require('../src/cli/commands/ship');

  test('writes ECS + HEC NDJSON to outDir', async () => {
    const r = await ship.exportToFiles(assessment, { outDir: tmpDir });
    expect(r.dir).toBe(tmpDir);
    expect(r.counts.ecs).toBe(1);
    expect(r.counts.hec).toBe(1);
    // Default index name is flareinspect-findings
    expect(r.files.ecs).toMatch(/flareinspect-findings-\d+\.ndjson$/);
    expect(r.files.hec).toMatch(/flareinspect-hec-\d+\.ndjson$/);
    const hec = await fs.readFile(r.files.hec, 'utf8');
    expect(hec).toContain('cloudflare:flareinspect:finding');
  });
});

describe('ship.execute (CLI entry)', () => {
  const ship = require('../src/cli/commands/ship');

  // process.exit shim — we don't want a failed test to kill the runner.
  const realExit = process.exit;
  let exitCode = null;
  beforeEach(() => { exitCode = null; process.exit = (c) => { exitCode = c; throw new Error('EXIT_' + c); }; });
  afterEach(() => { process.exit = realExit; });

  test('file mode writes both NDJSON files and exits 0', async () => {
    await ship.execute({ input: 'ast.json', outDir: tmpDir, target: 'file' });
    const dir = await fs.readdir(tmpDir);
    expect(dir.some(f => f.includes('flareinspect-findings'))).toBe(true);
    expect(dir.some(f => f.startsWith('flareinspect-hec-'))).toBe(true);
    expect(exitCode).toBeNull();
  });

  test('elastic target: missing creds -> exits 1', async () => {
    await expect(ship.execute({ input: 'ast.json', target: 'elastic' })).rejects.toThrow('EXIT_1');
    expect(exitCode).toBe(1);
  });

  test('elastic target: dry-run', async () => {
    let logged = '';
    const realLog = console.log;
    console.log = (...a) => { logged += a.join(' ') + '\n'; };
    try {
      await ship.execute({ input: 'ast.json', target: 'elastic', esUrl: 'https://e', esApiKey: 'K', dryRun: true });
    } finally { console.log = realLog; }
    expect(logged).toMatch(/Elastic dry-run/);
  });

  test('splunk target: dry-run', async () => {
    let logged = '';
    const realLog = console.log;
    console.log = (...a) => { logged += a.join(' ') + '\n'; };
    try {
      await ship.execute({ input: 'ast.json', target: 'splunk', hecUrl: 'https://h', hecToken: 'T', dryRun: true });
    } finally { console.log = realLog; }
    expect(logged).toMatch(/Splunk dry-run/);
  });

  test('all target: missing BOTH creds -> exits 1 (caught at first)', async () => {
    await expect(ship.execute({ input: 'ast.json', target: 'all' })).rejects.toThrow('EXIT_1');
  });

  test('invalid input file -> exits 1', async () => {
    await expect(ship.execute({ input: 'missing.json' })).rejects.toThrow('EXIT_1');
  });
});
