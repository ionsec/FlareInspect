/**
 * Unit tests for src/exporters/{ecs,splunkHec}.js
 *
 * Phase 2a file exporters — for pull / air-gapped SIEM ingestion.
 * The file written must be exactly what the live shipper would have sent
 * (same code path, same shape), so a manual replay works.
 */

'use strict';

const fs   = require('fs').promises;
const os   = require('os');
const path = require('path');
const EcsExporter       = require('../src/exporters/ecs');
const SplunkHecExporter = require('../src/exporters/splunkHec');

const assessment = {
  assessmentId: 'ast-1',
  account: { id: 'acct-1', name: 'Acme' },
  zones: [{ id: 'z1', name: 'x.test' }],
  configuration: { zones: { 'x.test': { dns: { records: [
    { id: 'r1', name: 'a.x.test', type: 'A', content: '203.0.113.1', proxied: false }
  ] } } } },
  findings: [
    { id: 'f1', checkId: 'CFL-INSIGHT-005', severity: 'high', status: 'failed',
      title: 'Exposed origin', resource: { type: 'dns_record', zoneId: 'z1', id: 'r1', name: 'a.x.test' } },
    { id: 'f2', checkId: 'CFL-DNS-100', severity: 'low', status: 'passed',
      title: 'Other', resource: { type: 'dns_record', zoneId: 'z1', id: 'r1', name: 'a.x.test' } }
  ]
};

let tmpDir;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'flareinspect-siem-'));
});

afterEach(async () => {
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe('EcsExporter.exportToFile', () => {
  test('writes NDJSON bulk file + index template', async () => {
    const ex = new EcsExporter({ indexName: 'flare-x' });
    const r = await ex.exportToFile(assessment, tmpDir);
    expect(r.count).toBe(2);
    expect(r.file).toContain('flare-x-');
    expect(r.tplFile).toContain('template.json');
    expect(r.indexTemplate.index_patterns).toEqual(['flareinspect-*']);

    const body = await fs.readFile(r.file, 'utf8');
    const lines = body.trim().split('\n');
    expect(lines).toHaveLength(4);     // 2 docs * 2 lines
    expect(JSON.parse(lines[0]).index._index).toBe('flare-x');
    expect(JSON.parse(lines[1])['vulnerability.id']).toBe('f1');

    const tpl = JSON.parse(await fs.readFile(r.tplFile, 'utf8'));
    expect(Object.keys(tpl.template.mappings.properties)).toContain('vulnerability.id');
  });

  test('buildBody returns the same NDJSON the file would have', () => {
    const ex = new EcsExporter({ indexName: 'flare-x' });
    const a = ex.buildBody(assessment);
    expect(a.trim().split('\n')).toHaveLength(4);
  });
});

describe('SplunkHecExporter.exportToFile', () => {
  test('writes one envelope per line', async () => {
    const ex = new SplunkHecExporter();
    const r = await ex.exportToFile(assessment, tmpDir);
    expect(r.count).toBe(2);
    expect(r.file).toContain('flareinspect-hec-');
    const body = await fs.readFile(r.file, 'utf8');
    const lines = body.trim().split('\n');
    expect(lines).toHaveLength(2);
    const ev0 = JSON.parse(lines[0]);
    expect(ev0.sourcetype).toBe('cloudflare:flareinspect:finding');
    expect(ev0.event.vulnerability.signature).toBe('CFL-INSIGHT-005');
  });

  test('buildEvents matches the file content', () => {
    const ex = new SplunkHecExporter();
    const events = ex.buildEvents(assessment);
    expect(events).toHaveLength(2);
    expect(events[0].event.vulnerability.signature).toBe('CFL-INSIGHT-005');
  });
});
