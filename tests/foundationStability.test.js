/**
 * Foundation-stability guards.
 *
 * The foundation phase extends the `configuration` capture in
 * AssessmentService. Any new top-level key MUST be safe to:
 *   - round-trip through JSON (write → read → equal)
 *   - round-trip through the recipe backup/rollback (no undefined leakage
 *     that would silently break the in-memory checksum, like the bug fixed
 *     for dnsTxtRecordRecipe).
 *
 * These tests do NOT run an end-to-end assessment (which would hit the live
 * Cloudflare API). They build a synthetic assessment in the shape the
 * foundation phase is supposed to produce, run it through the graph + path
 * engine, and assert the output is stable.
 *
 * If you add a new node type to the graph, add its key here too.
 */

'use strict';

const { buildResourceGraph } = require('../src/core/graph/resourceGraph');
const { findAttackPaths } = require('../src/core/graph/attackPaths');
const { SEVERITY_ORDER, worst, worstOf } = require('../src/core/graph/severity');

function synthAssessment() {
  return {
    assessmentId: '00000000-0000-4000-8000-000000000001',
    account: { id: 'acct', name: 'Acct', type: 'standard' },
    zones: [
      { id: 'z1', name: 'a.test', status: 'active', plan: 'Free' },
      { id: 'z2', name: 'b.test', status: 'active', plan: 'Enterprise' }
    ],
    findings: [
      { id: 'f1', checkId: 'CFL-DNS-001', severity: 'high',  status: 'failed',
        resource: { type: 'dns_record', zoneId: 'z1', id: 'r1' } },
      { id: 'f2', checkId: 'CFL-SSL-001', severity: 'low',   status: 'warning',
        resource: { type: 'zone', id: 'z1' } },
      { id: 'f3', checkId: 'CFL-HOLD-001',severity: 'critical', status: 'failed',
        resource: { type: 'zone', id: 'z2' } }
    ],
    configuration: {
      zones: {
        'a.test': { dns: { records: [
          { id: 'r1', name: 'app.a.test', type: 'A', content: '203.0.113.10', proxied: false }
        ] } },
        'b.test': { dns: { records: [
          { id: 'r2', name: 'api.b.test', type: 'CNAME', content: 'edge.cf.net', proxied: true }
        ] } }
      },
      r2: { acct: { buckets: [{ name: 'logs', created_on: '2025-01-01' }] } },
      tunnels: [{ id: 't1', name: 'corp-tunnel' }],
      workers: { routes: { 'a.test': [{ script: 'app', pattern: 'a.test/*' }] } }
    }
  };
}

describe('foundation stability', () => {
  test('JSON round-trip of the foundation configuration is stable', () => {
    const a = synthAssessment();
    const round = JSON.parse(JSON.stringify(a));
    expect(round).toEqual(a);
    // every key present after round-trip
    expect(round.configuration.zones['a.test'].dns.records[0].id).toBe('r1');
    expect(round.configuration.r2.acct.buckets[0].name).toBe('logs');
    expect(round.configuration.workers.routes['a.test'][0].script).toBe('app');
  });

  test('resource graph + attack paths are deterministic for the same input', () => {
    const a = synthAssessment();
    const g1 = buildResourceGraph(a);
    const g2 = buildResourceGraph(a);
    expect(g2).toEqual(g1);

    const p1 = findAttackPaths(g1, a);
    const p2 = findAttackPaths(g2, a);
    expect(p2).toEqual(p1);
  });

  test('graph node/edge shape is the contract for all consumers', () => {
    const g = buildResourceGraph(synthAssessment());

    for (const n of g.nodes) {
      expect(n).toEqual(expect.objectContaining({
        id: expect.any(String),
        type: expect.any(String),
        label: expect.any(String),
        props: expect.any(Object),
        severity: expect.stringMatching(/^(critical|high|medium|low|informational|pass)$/),
        findingIds: expect.any(Array),
        findingCount: expect.any(Number),
        failedCount: expect.any(Number)
      }));
    }
    for (const e of g.edges) {
      expect(e).toEqual(expect.objectContaining({
        id: expect.any(String),
        from: expect.any(String),
        to:   expect.any(String),
        type: expect.any(String)
      }));
    }
  });

  test('node types are restricted to the documented set', () => {
    const g = buildResourceGraph(synthAssessment());
    const allowed = new Set([
      'internet', 'account', 'zone', 'dns_record', 'origin', 'certificate',
      'access_app', 'access_policy', 'tunnel', 'worker', 'binding', 'r2_bucket',
      'load_balancer'
    ]);
    for (const n of g.nodes) {
      expect(allowed.has(n.type)).toBe(true);
    }
  });

  test('edge types are restricted to the documented set', () => {
    const g = buildResourceGraph(synthAssessment());
    const allowed = new Set([
      'contains', 'resolves_to', 'exposes', 'protected_by', 'routes_to',
      'authenticates_with', 'binds', 'serves'
    ]);
    for (const e of g.edges) {
      expect(allowed.has(e.type)).toBe(true);
    }
  });

  test('paths array contains only the documented path shape', () => {
    const g = buildResourceGraph(synthAssessment());
    const paths = findAttackPaths(g, synthAssessment());
    for (const p of paths) {
      expect(p).toEqual(expect.objectContaining({
        id: expect.any(String),
        title: expect.any(String),
        severity: expect.stringMatching(/^(critical|high|medium|low|informational|pass)$/),
        hopCount: expect.any(Number),
        nodes: expect.any(Array),
        edges: expect.any(Array),
        relatedCheckIds: expect.any(Array),
        remediableCheckIds: expect.any(Array)
      }));
    }
  });

  test('severity helpers are pure and side-effect-free', () => {
    expect(SEVERITY_ORDER[0]).toBe('critical');
    expect(SEVERITY_ORDER[SEVERITY_ORDER.length - 1]).toBe('pass');
    expect(worst('critical', 'low')).toBe('critical');
    expect(worst('low', 'critical')).toBe('critical');
    expect(worst(null, undefined)).toBe('pass');
    expect(worst('high', 'bogus')).toBe('high');
    expect(worstOf([
      { severity: 'high',     status: 'failed' },
      { severity: 'critical', status: 'failed' },
      { severity: 'low',      status: 'passed' }   // passed doesn't pull severity down
    ])).toBe('critical');
    expect(worstOf([])).toBe('pass');
  });

  test('foundation endpoint payload shape (mock of /api/posture/graph body)', () => {
    // The server endpoint returns { meta, graph, paths } — verify the
    // building blocks fit together without a live server.
    const a = synthAssessment();
    const graph = buildResourceGraph(a);
    const paths = findAttackPaths(graph, a);
    const meta = {
      assessmentId: a.assessmentId,
      generatedAt: new Date().toISOString(),
      rules: ['exposed-origin', 'weak-transport', 'open-access-app', 'tunnel-without-access', 'worker-plaintext-secret'],
      severityOrder: SEVERITY_ORDER
    };
    const payload = { meta, graph, paths };
    const round = JSON.parse(JSON.stringify(payload));
    expect(round.meta.assessmentId).toBe(a.assessmentId);
    expect(round.graph.nodes.length).toBe(graph.nodes.length);
    expect(round.paths.length).toBe(paths.length);
  });
});
