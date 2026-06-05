/**
 * Unit tests for src/core/integrations/siem/splunk.js
 *
 * Coverage:
 *   - toSplunkEvent maps finding -> CIM-shaped HEC envelope
 *   - buildHecPayload produces one envelope per finding
 *   - shipFindings (live): posts to /services/collector/event with Splunk token
 *     header; sent/failed counts are correct; errors are surfaced
 *   - shipFindings (dryRun): returns events without HTTP
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
const { toSplunkEvent, buildHecPayload, shipFindings, SOURCETYPE } = require('../src/core/integrations/siem/splunk');
const { buildEnrichmentIndex } = require('../src/core/integrations/siem/enrichment');

const { __setHandler, __clear } = https;

/**
 * Make a fake handler that records per-call state and emits a fake response.
 * Use `state.calls.push(...)` to inspect each request. Pass `statusForCall`
 * to vary status per call index.
 */
function makeHandler({ status = 200, body = '{"ackId":1}' } = {}) {
  const state = { calls: [] };
  const handler = (opts, cb) => {
    const call = { req: opts, headers: opts.headers, body: null };
    state.calls.push(call);
    return {
      on() {},
      write(b) { call.body = b; },
      end() {
        setImmediate(() => {
          const res = {
            statusCode: status,
            on(e, c) { if (e === 'data') c(body); if (e === 'end') c(); }
          };
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
      title: 'Other', resource: { type: 'dns_record', zoneId: 'z1', id: 'r1', name: 'a.x.test' } }
  ]
};

beforeEach(() => { __clear(); });

describe('splunk.toSplunkEvent', () => {
  test('emits a CIM-shaped envelope with required fields', () => {
    const idx = buildEnrichmentIndex(assessment);
    const ev = toSplunkEvent(assessment.findings[0], idx, assessment);
    expect(ev.sourcetype).toBe(SOURCETYPE);
    expect(ev.source).toBe('flareinspect');
    expect(ev.index).toBe('main');
    expect(typeof ev.time).toBe('number');
    expect(ev.event.vulnerability.vendor).toBe('IONSEC.IO');
    expect(ev.event.vulnerability.signature).toBe('CFL-INSIGHT-005');
    expect(ev.event.vulnerability.severity).toBe('high');
    expect(ev.event.vulnerability.remediable).toBe(true);
    expect(ev.event.cloud.provider).toBe('cloudflare');
    expect(ev.event.cloud.account_id).toBe('acct-1');
    expect(ev.event.flareinspect.finding_id).toBe('f1');
    expect(ev.event.flareinspect.check_id).toBe('CFL-INSIGHT-005');
    expect(Array.isArray(ev.event.threat.enrichments)).toBe(true);
  });
});

describe('splunk.buildHecPayload', () => {
  test('produces one envelope per finding', () => {
    const out = buildHecPayload(assessment);
    expect(out.count).toBe(2);
    expect(out.events).toHaveLength(2);
    expect(out.events[0].event.vulnerability.signature).toBe('CFL-INSIGHT-005');
  });
});

describe('splunk.shipFindings', () => {
  test('dryRun returns events without making HTTP', async () => {
    const r = await shipFindings({ hecUrl: 'https://splunk.example.com:8088', hecToken: 'T', assessment, dryRun: true });
    expect(r.ok).toBe(true);
    expect(r.count).toBe(2);
    expect(r.sent).toBe(2);
    expect(r.failed).toBe(0);
    expect(r.events).toHaveLength(2);
    expect(r.dryRun).toBe(true);
  });

  test('live: posts one envelope per finding with proper headers', async () => {
    const h = makeHandler({ status: 200, body: '{"ackId":42}' });
    __setHandler('splunk.example.com', h);
    const r = await shipFindings({ hecUrl: 'https://splunk.example.com:8088', hecToken: 'TOK', assessment });
    expect(r.ok).toBe(true);
    expect(r.sent).toBe(2);
    expect(r.failed).toBe(0);
    expect(h.state.calls).toHaveLength(2);
    for (const call of h.state.calls) {
      expect(call.headers.authorization).toBe('Splunk TOK');
      expect(call.req.path).toBe('/services/collector/event');
      expect(call.req.method).toBe('POST');
    }
  });

  test('live: counts failures when HEC returns 4xx', async () => {
    __setHandler('splunk.example.com', makeHandler({ status: 403, body: '{"text":"Invalid token"}' }));
    const r = await shipFindings({ hecUrl: 'https://splunk.example.com:8088', hecToken: 'BAD', assessment });
    expect(r.ok).toBe(false);
    expect(r.sent).toBe(0);
    expect(r.failed).toBe(2);
    expect(r.errors[0].status).toBe(403);
  });

  test('live: continues on per-event error and aggregates', async () => {
    // Build a per-call handler that returns 500 on first, 200 on second.
    const calls = [];
    const handler = (opts, cb) => {
      calls.push(opts);
      const status = calls.length === 1 ? 500 : 200;
      return {
        on() {},
        write() {},
        end() {
          setImmediate(() => {
            const res = {
              statusCode: status,
              on(e, c) { if (e === 'data') c('{}'); if (e === 'end') c(); }
            };
            if (cb) cb(res);
          });
        },
        destroy() {}
      };
    };
    __setHandler('splunk.example.com', handler);
    const r = await shipFindings({ hecUrl: 'https://splunk.example.com:8088', hecToken: 'T', assessment });
    expect(r.sent).toBe(1);
    expect(r.failed).toBe(1);
    expect(r.ok).toBe(false);
  });

  test('rejects missing args', async () => {
    expect((await shipFindings({ assessment })).ok).toBe(false);
    expect((await shipFindings({ hecUrl: 'x' })).ok).toBe(false);
    expect((await shipFindings({ hecUrl: 'x', hecToken: 't' })).ok).toBe(false);
  });
});
