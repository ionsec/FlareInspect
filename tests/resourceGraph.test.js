/**
 * Unit tests for src/core/graph/resourceGraph.js
 *
 * The resource graph is the shared spine for the Posture map, the SIEM
 * exporters, and the MCP server. These tests pin its node/edge shape so
 * every consumer (UI, exporters, MCP) can rely on a stable contract.
 */

'use strict';

const { buildResourceGraph, _internal: rgInternal } = require('../src/core/graph/resourceGraph');

function fixture(overrides = {}) {
  return {
    assessmentId: 'a-1',
    account: { id: 'acct-1', name: 'Acct' },
    zones: [
      { id: 'z-1', name: 'example.com', status: 'active', plan: 'Free' }
    ],
    findings: [],
    configuration: {
      zones: {
        'example.com': {
          dns: { records: [
            { id: 'r-1', name: 'app.example.com', type: 'A',     content: '203.0.113.5', proxied: false },
            { id: 'r-2', name: 'cdn.example.com', type: 'CNAME', content: 'edge.cf.net', proxied: true  },
            { id: 'r-3', name: 'blog.example.com',type: 'A',     content: '198.51.100.7', proxied: false },
            { id: 'r-4', name: 'foo.example.com', type: 'TXT',   content: 'v=spf1 -all',  proxied: false }
          ]}
        }
      }
    },
    ...overrides
  };
}

describe('resourceGraph.buildResourceGraph', () => {
  test('builds internet + account + zone roots', () => {
    const { nodes, edges } = buildResourceGraph(fixture());
    const byId = Object.fromEntries(nodes.map(n => [n.id, n]));

    expect(byId['internet']).toBeDefined();
    expect(byId['internet'].type).toBe('internet');
    expect(byId['account:acct-1']).toBeDefined();
    expect(byId['zone:z-1']).toBeDefined();
    expect(byId['zone:z-1'].label).toBe('example.com');

    const contains = edges.filter(e => e.type === 'contains');
    expect(contains).toEqual(expect.arrayContaining([
      expect.objectContaining({ from: 'internet',     to: 'account:acct-1' }),
      expect.objectContaining({ from: 'account:acct-1', to: 'zone:z-1'      })
    ]));
  });

  test('emits origin nodes only for un-proxied A/AAAA/CNAME and edges them as resolves_to', () => {
    const { nodes, edges } = buildResourceGraph(fixture());
    const origins = nodes.filter(n => n.type === 'origin');
    const byContent = Object.fromEntries(origins.map(n => [n.props.ip, n]));

    expect(byContent['203.0.113.5']).toBeDefined();
    expect(byContent['198.51.100.7']).toBeDefined();
    expect(byContent['edge.cf.net']).toBeUndefined();   // proxied CNAME — no origin

    const r1 = edges.find(e => e.to === 'origin:203.0.113.5');
    expect(r1).toBeDefined();
    expect(r1.type).toBe('resolves_to');                // un-proxied

    // TXT records: no origin, not an "exposed origin"
    const txtEdge = edges.find(e => e.to?.startsWith('origin:') && e.from?.includes('foo.example.com'));
    expect(txtEdge).toBeUndefined();
  });

  test('attaches findings to the right node by resource id', () => {
    const a = fixture({
      findings: [
        { id: 'f-1', checkId: 'CFL-DNS-001', severity: 'high', status: 'failed', resource: { type: 'dns_record', zoneId: 'z-1', id: 'r-1' } }
      ]
    });
    const { nodes } = buildResourceGraph(a);
    const dns = nodes.find(n => n.id === 'dns:z-1:r-1');
    expect(dns.findingIds).toContain('f-1');
    expect(dns.severity).toBe('high');

    // The zone picks up the same finding via the name fallback only if the
    // resource shape uses resourceName/zoneName — here we used id+zoneId.
    const zone = nodes.find(n => n.id === 'zone:z-1');
    expect(zone.findingCount).toBe(0);
  });

  test('worst severity on a node = worst of its failed/warning findings', () => {
    const a = fixture({
      findings: [
        { id: 'f-a', severity: 'low',      status: 'failed',  resource: { type: 'zone', id: 'z-1' } },
        { id: 'f-b', severity: 'critical', status: 'failed',  resource: { type: 'zone', id: 'z-1' } },
        { id: 'f-c', severity: 'high',     status: 'passed',  resource: { type: 'zone', id: 'z-1' } }
      ]
    });
    const { nodes } = buildResourceGraph(a);
    const zone = nodes.find(n => n.id === 'zone:z-1');
    expect(zone.severity).toBe('critical');
    expect(zone.findingCount).toBe(3);
    expect(zone.failedCount).toBe(2);
  });

  test('survives empty / minimal input', () => {
    expect(buildResourceGraph(null).nodes.length).toBeGreaterThanOrEqual(1);    // internet node
    expect(buildResourceGraph({}).nodes.length).toBeGreaterThanOrEqual(1);
    expect(buildResourceGraph({ zones: [] }).stats.nodeCount).toBe(2);           // internet + account
  });

  test('counts nodes/edges by type in stats', () => {
    const { stats } = buildResourceGraph(fixture());
    expect(stats.byNodeType.zone).toBe(1);
    expect(stats.byNodeType.dns_record).toBe(4);
    expect(stats.byNodeType.origin).toBe(2);
    expect(stats.byEdgeType.contains).toBeGreaterThanOrEqual(3);
    expect(stats.byEdgeType.resolves_to).toBe(2);
  });

  test('attaches R2 buckets to the account', () => {
    const a = fixture({
      configuration: {
        ...fixture().configuration,
        r2: { 'acct-1': { buckets: [{ name: 'logs', created_on: 'x' }] } }
      }
    });
    const { nodes, edges } = buildResourceGraph(a);
    expect(nodes.find(n => n.id === 'r2:logs')).toBeDefined();
    expect(edges.find(e => e.from === 'account:acct-1' && e.to === 'r2:logs' && e.type === 'contains')).toBeDefined();
  });

  test('isOriginRecord helper: unproxied A/AAAA/CNAME only', () => {
    const { isOriginRecord } = rgInternal;
    expect(isOriginRecord({ type: 'A',     proxied: false })).toBe(true);
    expect(isOriginRecord({ type: 'AAAA',  proxied: false })).toBe(true);
    expect(isOriginRecord({ type: 'CNAME', proxied: false })).toBe(true);
    expect(isOriginRecord({ type: 'A',     proxied: true  })).toBe(false);
    expect(isOriginRecord({ type: 'TXT',   proxied: false })).toBe(false);
    expect(isOriginRecord(null)).toBe(false);
  });
});
