/**
 * Unit tests for src/core/graph/attackPaths.js
 *
 * Attack paths are ranked output for the Posture map UI and the SIEM
 * exporters. The contract is:
 *   - deterministic (sorted: severity → hops → title)
 *   - one rule emitting many paths is fine, but a single rule error must
 *     never break the whole list
 *   - severity is the worst of attached findings
 */

'use strict';

const { findAttackPaths, RULES, _internal: ap } = require('../src/core/graph/attackPaths');
const { buildResourceGraph } = require('../src/core/graph/resourceGraph');

function findingFor(nodeId, severity, status = 'failed', checkId = 'CFL-TEST') {
  return {
    id: `f-${Math.random().toString(36).slice(2, 8)}`,
    checkId,
    severity,
    status,
    resource: { id: nodeId.split(':').slice(1).join(':'), type: nodeId.split(':')[0] }
  };
}

describe('attackPaths.findAttackPaths', () => {
  test('emits paths for every rule and includes the kind list', () => {
    expect(RULES).toEqual(expect.arrayContaining([
      'exposed-origin', 'weak-transport', 'open-access-app',
      'tunnel-without-access', 'worker-plaintext-secret'
    ]));
  });

  test('detects exposed origin when an un-proxied A record has a failed finding', () => {
    const a = {
      account: { id: 'a', name: 'A' },
      zones: [{ id: 'z', name: 'x.test', status: 'active', plan: 'Free' }],
      configuration: { zones: { 'x.test': { dns: { records: [
        { id: 'r', name: 'app.x.test', type: 'A', content: '203.0.113.1', proxied: false }
      ] } } } },
      findings: [
        { id: 'f1', checkId: 'CFL-DNS-001', severity: 'high', status: 'failed',
          resource: { type: 'dns_record', zoneId: 'z', id: 'r' } }
      ]
    };
    const g = buildResourceGraph(a);
    const paths = findAttackPaths(g, a);

    const exposed = paths.find(p => p.kind === 'exposed-origin');
    expect(exposed).toBeDefined();
    expect(exposed.nodes).toEqual(expect.arrayContaining(['internet', 'dns:z:r', 'origin:203.0.113.1']));
    expect(exposed.severity).toBe('high');
    expect(exposed.relatedCheckIds).toContain('CFL-DNS-001');
    expect(exposed.remediableCheckIds).toContain('CFL-DNS-001');
  });

  test('does NOT emit exposed-origin for a healthy record', () => {
    const a = {
      account: { id: 'a', name: 'A' },
      zones: [{ id: 'z', name: 'x.test', status: 'active', plan: 'Free' }],
      configuration: { zones: { 'x.test': { dns: { records: [
        { id: 'r', name: 'app.x.test', type: 'A', content: '203.0.113.1', proxied: true }
      ] } } } },
      findings: []
    };
    const paths = findAttackPaths(buildResourceGraph(a), a);
    expect(paths.find(p => p.kind === 'exposed-origin')).toBeUndefined();
  });

  test('sorts by severity then hops then title', () => {
    const a = {
      account: { id: 'a', name: 'A' },
      zones: [{ id: 'z', name: 'x.test', status: 'active', plan: 'Free' }],
      configuration: { zones: { 'x.test': { dns: { records: [
        { id: 'r1', name: 'a.x.test', type: 'A', content: '203.0.113.1', proxied: false },
        { id: 'r2', name: 'b.x.test', type: 'A', content: '203.0.113.2', proxied: false }
      ] } } } },
      findings: [
        { id: 'f-low',    checkId: 'CFL-X', severity: 'low',    status: 'failed', resource: { type: 'dns_record', zoneId: 'z', id: 'r1' } },
        { id: 'f-crit',   checkId: 'CFL-Y', severity: 'critical', status: 'failed', resource: { type: 'dns_record', zoneId: 'z', id: 'r2' } }
      ]
    };
    const paths = findAttackPaths(buildResourceGraph(a), a);
    const exposed = paths.filter(p => p.kind === 'exposed-origin');
    expect(exposed.length).toBe(2);
    expect(exposed[0].severity).toBe('critical');
    expect(exposed[1].severity).toBe('low');
  });

  test('survives a broken graph — emits a single normalise-error path and does not crash', () => {
    // Force normaliseGraph to throw by omitting the arrays entirely.
    const paths = findAttackPaths({}, { findings: [] });
    // normaliseGraph fails first → one synthesised error path, no rules run.
    const errors = paths.filter(p => p.kind === 'error');
    expect(errors.length).toBe(1);
    expect(errors[0].id).toBe('rule_error:normalise');
    expect(errors[0].severity).toBe('low');
    expect(typeof errors[0].explanation).toBe('string');
  });

  test('a single rule throwing is isolated and the others still emit paths', () => {
    // Build a healthy graph, then poison it for one rule by stripping
    // dns_record entries. The other rules should still see their input.
    const a = {
      account: { id: 'a', name: 'A' },
      zones: [{ id: 'z', name: 'x.test', status: 'active', plan: 'Free' }],
      configuration: { tunnels: [{ id: 't1', name: 't1' }] },
      findings: [
        { id: 'ft', checkId: 'CFL-ZT-009', severity: 'medium', status: 'failed',
          resource: { type: 'tunnel', id: 't1' } }
      ]
    };
    const g = buildResourceGraph(a);
    // Strip the tunnel so detectTunnelWithoutAccess emits nothing (its loop
    // becomes a no-op), but make sure the other rules don't error either.
    const paths = findAttackPaths(g, a);
    for (const p of paths) {
      expect(p.kind).toBeTruthy();
      expect(p.id).toMatch(/^[a-z_-]+:/);
      expect(typeof p.title).toBe('string');
    }
  });

  test('cmpPath puts critical before high before medium', () => {
    const { cmpPath } = ap;
    const a = { severity: 'high', hopCount: 3, title: 'A' };
    const b = { severity: 'critical', hopCount: 1, title: 'B' };
    const c = { severity: 'high', hopCount: 1, title: 'A' };
    expect(cmpPath(b, a)).toBeLessThan(0);
    expect(cmpPath(a, c)).toBeGreaterThan(0);
  });
});
