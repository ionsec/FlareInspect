/**
 * Unit tests for src/core/integrations/siem/elastic.js
 *
 * Coverage:
 *   - toEcsDoc mapping (severity, threat.enrichments, cloud, labels, related)
 *   - buildBulkBody: 2 lines per doc (action + doc), NDJSON, count
 *   - shipFindings: dryRun returns body without HTTP; live path posts with
 *     proper headers and ApiKey; errors are surfaced
 *   - buildIndexTemplate: shape includes all indexed fields
 */

'use strict';

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
const { toEcsDoc, buildBulkBody, shipFindings, buildIndexTemplate } = require('../src/core/integrations/siem/elastic');
const { buildEnrichmentIndex } = require('../src/core/integrations/siem/enrichment');

const { __setHandler, __clear } = https;

/**
 * Make a fake handler that records the request options, body, and headers
 * and emits a fake response when `end()` is called.
 */
function makeHandler({ status = 200, body = '{}' } = {}) {
  const state = { req: null, body: null, headers: null, responseListener: null };
  const handler = (opts, cb) => {
    state.req = opts;
    state.headers = opts.headers;
    state.responseListener = cb;
    return {
      on() {},
      write(b) { state.body = b; },
      end() {
        // emit the response
        setImmediate(() => {
          const res = {
            statusCode: status,
            on(e, c) { if (e === 'data') c(body); if (e === 'end') c(); }
          };
          if (state.responseListener) state.responseListener(res);
        });
      },
      destroy() {}
    };
  };
  handler.state = state;
  return handler;
}

const assessment = {
  assessmentId: 'ast-1',
  account: { id: 'acct-1', name: 'Acme' },
  zones: [{ id: 'z1', name: 'x.test' }],
  configuration: { zones: { 'x.test': { dns: { records: [
    { id: 'r1', name: 'a.x.test', type: 'A', content: '203.0.113.1', proxied: false }
  ] } } } },
  findings: [
    { id: 'f1', checkId: 'CFL-INSIGHT-005', severity: 'high', status: 'failed',
      title: 'Exposed origin', description: 'Origin IP is reachable directly',
      remediation: 'Enable proxy', recipe: 'dnsProxify',
      resource: { type: 'dns_record', zoneId: 'z1', id: 'r1', name: 'a.x.test' } },
    { id: 'f2', checkId: 'CFL-DNS-100', severity: 'low', status: 'passed',
      title: 'Other thing',
      resource: { type: 'dns_record', zoneId: 'z1', id: 'r1', name: 'a.x.test' } }
  ]
};

beforeEach(() => { __clear(); });

describe('elastic.toEcsDoc', () => {
  test('emits a fully-shaped ECS doc with threat enrichments', () => {
    const idx = buildEnrichmentIndex(assessment);
    const doc = toEcsDoc(assessment.findings[0], idx, assessment);
    expect(doc['@timestamp']).toBeDefined();
    expect(doc['event.kind']).toBe('alert');
    expect(doc['event.category']).toEqual(['vulnerability']);
    expect(doc['cloud.provider']).toBe('cloudflare');
    expect(doc['cloud.account.id']).toBe('acct-1');
    expect(doc['vulnerability.id']).toBe('f1');
    expect(doc['vulnerability.classification']).toBe('CFL-INSIGHT-005');
    expect(doc['vulnerability.severity']).toBe('HIGH');
    expect(doc['host.name']).toBe('x.test');
    expect(doc['url.full']).toBe('a.x.test');
    expect(doc['labels'].check_id).toBe('CFL-INSIGHT-005');
    expect(doc['labels'].remediable).toBe('true');
    expect(doc['labels'].path_count).toMatch(/^[0-9]+$/);
    expect(Array.isArray(doc['threat.enrichments'])).toBe(true);
    // related.entity is nodeId + path ids; must be an array (may be empty)
    expect(Array.isArray(doc['related.entity'])).toBe(true);
    expect(doc['flareinspect.node_id']).toMatch(/^dns:/);
  });

  test('maps severity -> ECS score', () => {
    const idx = buildEnrichmentIndex(assessment);
    expect(toEcsDoc(assessment.findings[0], idx, assessment)['vulnerability.score']).toBe(75);
    const low = { ...assessment.findings[1], severity: 'low' };
    expect(toEcsDoc(low, idx, assessment)['vulnerability.score']).toBe(25);
    const crit = { ...assessment.findings[0], severity: 'critical' };
    expect(toEcsDoc(crit, idx, assessment)['vulnerability.score']).toBe(95);
  });
});

describe('elastic.buildBulkBody', () => {
  test('produces 2 lines per doc, NDJSON-terminated, correct count', () => {
    const out = buildBulkBody(assessment, 'flare-x');
    expect(out.count).toBe(2);
    const lines = out.body.trim().split('\n');
    expect(lines).toHaveLength(out.count * 2);
    const a0 = JSON.parse(lines[0]);
    expect(a0.index._index).toBe('flare-x');
    expect(a0.index._id).toBe('f1');
    const d0 = JSON.parse(lines[1]);
    expect(d0['vulnerability.id']).toBe('f1');
    const a1 = JSON.parse(lines[2]);
    expect(a1.index._id).toBe('f2');
    const d1 = JSON.parse(lines[3]);
    expect(d1['vulnerability.id']).toBe('f2');
    expect(out.body.endsWith('\n')).toBe(true);
  });
});

describe('elastic.shipFindings', () => {
  test('dryRun returns body without making HTTP', async () => {
    const r = await shipFindings({ esUrl: 'https://es.example.com', assessment, dryRun: true });
    expect(r.ok).toBe(true);
    expect(r.count).toBe(2);
    expect(r.dryRun).toBe(true);
    expect(r.body.split('\n').filter(Boolean)).toHaveLength(4);
    expect(r.docs).toBeDefined();
  });

  test('live: posts to /_bulk with ApiKey header and returns itemsCount', async () => {
    const h = makeHandler({ status: 200, body: JSON.stringify({ took: 5, errors: false, items: [{}, {}] }) });
    __setHandler('es.example.com', h);
    const r = await shipFindings({ esUrl: 'https://es.example.com', apiKey: 'KEY123', assessment });
    expect(r.ok).toBe(true);
    expect(r.status).toBe(200);
    expect(r.itemsCount).toBe(2);
    expect(h.state.headers.authorization).toBe('ApiKey KEY123');
    expect(h.state.headers['content-type']).toBe('application/x-ndjson');
    expect(h.state.req.path).toBe('/_bulk');
    expect(h.state.req.method).toBe('POST');
  });

  test('live: uses Basic auth when no apiKey', async () => {
    const h = makeHandler({ status: 200, body: JSON.stringify({ items: [{}] }) });
    __setHandler('es.example.com', h);
    await shipFindings({ esUrl: 'https://es.example.com', username: 'u', password: 'p', assessment });
    const auth = h.state.headers.authorization;
    expect(auth).toMatch(/^Basic /);
    expect(Buffer.from(auth.replace('Basic ', ''), 'base64').toString()).toBe('u:p');
  });

  test('returns error on non-2xx', async () => {
    __setHandler('es.example.com', makeHandler({ status: 403, body: '{"error":"forbidden"}' }));
    const r = await shipFindings({ esUrl: 'https://es.example.com', apiKey: 'K', assessment });
    expect(r.ok).toBe(false);
    expect(r.status).toBe(403);
  });

  test('rejects missing esUrl / assessment', async () => {
    expect((await shipFindings({ assessment })).ok).toBe(false);
    expect((await shipFindings({ esUrl: 'https://e' })).ok).toBe(false);
  });
});

describe('elastic.buildIndexTemplate', () => {
  test('has expected mappings and index_patterns', () => {
    const tpl = buildIndexTemplate();
    expect(tpl.index_patterns).toEqual(['flareinspect-*']);
    const props = tpl.template.mappings.properties;
    expect(Object.keys(props)).toContain('@timestamp');
    expect(Object.keys(props)).toContain('vulnerability.id');
    expect(Object.keys(props)).toContain('labels.check_id');
    expect(Object.keys(props)).toContain('threat.enrichments');
  });
});
