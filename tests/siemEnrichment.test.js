/**
 * Unit tests for src/core/integrations/siem/enrichment.js
 *
 * Joins findings -> graph node -> attack paths. The contract that downstream
 * ECS/Splunk shippers rely on:
 *   - nodeId is non-null when a finding's (resourceType, resourceId) maps to a graph node
 *   - attackPathIds is non-empty when the finding is part of a path's recipe set
 *   - enrichFinding is pure (does not mutate input)
 *   - findingsByNodeId contains the seed finding
 */

'use strict';

const { buildEnrichmentIndex, enrichFinding, enrichAssessment } = require('../src/core/integrations/siem/enrichment');

describe('siem/enrichment.buildEnrichmentIndex', () => {
  test('returns graph + paths + indexes', () => {
    const a = {
      account: { id: 'a', name: 'A' },
      zones: [{ id: 'z', name: 'x.test', plan: 'Free' }],
      configuration: { zones: { 'x.test': { dns: { records: [
        { id: 'r', name: 'app.x.test', type: 'A', content: '203.0.113.1', proxied: false }
      ] } } } },
      findings: [
        { id: 'f1', checkId: 'CFL-DNS-001', severity: 'high', status: 'failed',
          resource: { type: 'dns_record', zoneId: 'z', id: 'r' } }
      ]
    };
    const idx = buildEnrichmentIndex(a);
    expect(idx.graph).toBeDefined();
    expect(idx.paths).toBeInstanceOf(Array);
    expect(idx.nodeByFindingId).toBeInstanceOf(Map);
    expect(idx.pathsByFindingId).toBeInstanceOf(Map);
    expect(idx.findingsByNodeId).toBeInstanceOf(Map);
    // f1 should be on a dns_record node
    expect(idx.nodeByFindingId.get('f1')).toMatch(/^dns:/);
  });

  test('exposed-origin path -> finding gets attackPathIds', () => {
    const a = {
      account: { id: 'a' },
      zones: [{ id: 'z', name: 'x.test' }],
      configuration: { zones: { 'x.test': { dns: { records: [
        { id: 'r', name: 'app.x.test', type: 'A', content: '203.0.113.1', proxied: false }
      ] } } } },
      findings: [
        { id: 'f1', checkId: 'CFL-INSIGHT-005', severity: 'high', status: 'failed',
          resource: { type: 'dns_record', zoneId: 'z', id: 'r' } }
      ]
    };
    const idx = buildEnrichmentIndex(a);
    // The exposed-origin path should be detected
    const ep = idx.paths.find(p => p.kind === 'exposed-origin');
    expect(ep).toBeDefined();
    // f1 should be linked to it (its checkId is in relatedCheckIds)
    const linked = idx.pathsByFindingId.get('f1') || [];
    expect(linked.length).toBeGreaterThan(0);
    expect(linked.some(p => p.kind === 'exposed-origin')).toBe(true);
  });
});

describe('siem/enrichment.enrichFinding', () => {
  test('adds flareinspect.{nodeId, attackPathIds, attackPaths}', () => {
    const a = {
      account: { id: 'a' },
      zones: [{ id: 'z', name: 'x.test' }],
      configuration: { zones: { 'x.test': { dns: { records: [
        { id: 'r', name: 'app.x.test', type: 'A', content: '203.0.113.1', proxied: false }
      ] } } } },
      findings: [
        { id: 'f1', checkId: 'CFL-INSIGHT-005', severity: 'high', status: 'failed',
          resource: { type: 'dns_record', zoneId: 'z', id: 'r' } }
      ]
    };
    const idx = buildEnrichmentIndex(a);
    const f = a.findings[0];
    const e = enrichFinding(f, idx);
    expect(e).not.toBe(f);                         // new object, no mutation
    expect(f.flareinspect).toBeUndefined();        // input not mutated
    expect(e.flareinspect).toBeDefined();
    expect(e.flareinspect.nodeId).toMatch(/^dns:/);
    expect(e.flareinspect.attackPathIds).toBeInstanceOf(Array);
    expect(e.flareinspect.attackPaths).toBeInstanceOf(Array);
    expect(e.flareinspect.attackPaths[0]).toHaveProperty('id');
    expect(e.flareinspect.attackPaths[0]).toHaveProperty('title');
    expect(e.flareinspect.attackPaths[0]).toHaveProperty('severity');
  });

  test('finding with no graph node gets nodeId=null and empty paths', () => {
    const a = {
      account: { id: 'a' },
      zones: [],
      findings: [
        { id: 'orphan', checkId: 'X', severity: 'low', status: 'failed',
          resource: { type: 'weird_type', id: 'nope' } }
      ]
    };
    const idx = buildEnrichmentIndex(a);
    const e = enrichFinding(a.findings[0], idx);
    expect(e.flareinspect.nodeId).toBeNull();
    expect(e.flareinspect.attackPathIds).toEqual([]);
  });

  test('handles missing resource cleanly (no throw)', () => {
    const idx = buildEnrichmentIndex({ account: { id: 'a' }, zones: [], findings: [] });
    const e = enrichFinding({ id: 'x', checkId: 'Y', severity: 'low', status: 'failed' }, idx);
    expect(e.flareinspect.nodeId).toBeNull();
  });
});

describe('siem/enrichment.enrichAssessment', () => {
  test('enriches every finding in one pass', () => {
    const a = {
      account: { id: 'a' },
      zones: [{ id: 'z', name: 'x.test' }],
      configuration: { zones: { 'x.test': { dns: { records: [
        { id: 'r1', name: 'a.x.test', type: 'A', content: '203.0.113.1', proxied: false },
        { id: 'r2', name: 'b.x.test', type: 'A', content: '203.0.113.2', proxied: true }
      ] } } } },
      findings: [
        { id: 'f1', checkId: 'CFL-INSIGHT-005', severity: 'high', status: 'failed',
          resource: { type: 'dns_record', zoneId: 'z', id: 'r1' } },
        { id: 'f2', checkId: 'CFL-DNS-100', severity: 'low', status: 'passed',
          resource: { type: 'dns_record', zoneId: 'z', id: 'r2' } }
      ]
    };
    const out = enrichAssessment(a);
    expect(out.findings).toHaveLength(2);
    for (const f of out.findings) {
      expect(f.flareinspect).toBeDefined();
    }
    expect(a.findings[0].flareinspect).toBeUndefined();   // input untouched
  });
});
