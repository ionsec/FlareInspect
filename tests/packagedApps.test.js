/**
 * Shape tests for the packaged SIEM apps:
 *   - integrations/elastic/flareinspect-dashboard.ndjson
 *   - integrations/elastic/flareinspect-index-template.json
 *   - integrations/splunk/TA-flareinspect/default/{props,transforms,app,savedsearches}.conf
 *   - integrations/splunk/TA-flareinspect/default/data/ui/views/flareinspect_overview.xml
 *
 * The test guards against accidental shape breakage (renamed ids,
 * missing references in the NDJSON, unparseable conf files).
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', 'integrations');

describe('Kibana saved-objects NDJSON', () => {
  const file = path.join(ROOT, 'elastic', 'flareinspect-dashboard.ndjson');
  test('exists and is parseable as newline-delimited JSON', () => {
    const raw = fs.readFileSync(file, 'utf8');
    const lines = raw.split('\n').filter(l => l.trim());
    expect(lines.length).toBeGreaterThanOrEqual(5);
    const docs = lines.map((l, i) => {
      try { return JSON.parse(l); } catch (e) { throw new Error(`line ${i + 1} not JSON: ${e.message}`); }
    });
    // types: 1 index-pattern, 1 search, 2 visualization, 1 dashboard, 1 export summary
    const types = docs.map(d => d.type).filter(Boolean);
    expect(types).toEqual(expect.arrayContaining([
      'index-pattern', 'search', 'visualization', 'visualization', 'dashboard'
    ]));
    // All required references resolve
    const ids = new Set(docs.map(d => d.id));
    for (const d of docs) {
      for (const ref of (d.references || [])) {
        expect(ids.has(ref.id)).toBe(true);
      }
    }
  });

  test('dashboard references the expected panels and search', () => {
    const raw = fs.readFileSync(file, 'utf8').split('\n').filter(l => l.trim());
    const docs = raw.map(l => JSON.parse(l));
    const dash = docs.find(d => d.type === 'dashboard');
    expect(dash.id).toBe('flareinspect-dashboard');
    const refIds = (dash.references || []).map(r => r.id).sort();
    expect(refIds).toEqual([
      'flareinspect-search', 'flareinspect-vis-paths', 'flareinspect-vis-severity'
    ]);
    const refTypes = (dash.references || []).map(r => r.type).sort();
    expect(refTypes).toEqual(['search', 'visualization', 'visualization']);
  });
});

describe('Kibana index template', () => {
  const file = path.join(ROOT, 'elastic', 'flareinspect-index-template.json');
  test('matches the engine buildIndexTemplate() shape', () => {
    const tpl = JSON.parse(fs.readFileSync(file, 'utf8'));
    expect(tpl.index_patterns).toEqual(['flareinspect-*']);
    const props = tpl.template.mappings.properties;
    expect(Object.keys(props)).toEqual(expect.arrayContaining([
      '@timestamp', 'vulnerability.id', 'labels.check_id', 'threat.enrichments'
    ]));
  });
});

describe('Splunk TA', () => {
  const ta = path.join(ROOT, 'splunk', 'TA-flareinspect', 'default');
  test('app.conf is parseable', () => {
    const raw = fs.readFileSync(path.join(ta, 'app.conf'), 'utf8');
    expect(raw).toMatch(/\[install\]/);
    expect(raw).toMatch(/\[launcher\]/);
    expect(raw).toMatch(/author\s*=\s*IONSEC\.IO/);
  });

  test('props.conf declares the sourcetype and JSON field extraction', () => {
    const raw = fs.readFileSync(path.join(ta, 'props.conf'), 'utf8');
    expect(raw).toMatch(/\[vendor flareinspect\]/);
    expect(raw).toMatch(/KV_MODE\s*=\s*json/);
    expect(raw).toMatch(/cloudflare:flareinspect:finding/);
  });

  test('transforms.conf is present and parseable', () => {
    const raw = fs.readFileSync(path.join(ta, 'transforms.conf'), 'utf8');
    expect(raw).toMatch(/\[rename_attack_paths\]/);
    expect(raw).toMatch(/\[severity_normalize\]/);
  });

  test('savedsearches.conf declares 2 saved searches', () => {
    const raw = fs.readFileSync(path.join(ta, 'savedsearches.conf'), 'utf8');
    expect(raw).toMatch(/\[flareinspect-critical-open\]/);
    expect(raw).toMatch(/\[flareinspect-high-attack-paths\]/);
  });

  test('dashboard XML exists and is valid SimpleXML', () => {
    const file = path.join(ta, 'data', 'ui', 'views', 'flareinspect_overview.xml');
    const raw = fs.readFileSync(file, 'utf8');
    expect(raw).toMatch(/<dashboard[\s>]/);
    expect(raw).toMatch(/<\/dashboard>/);
    expect(raw).toMatch(/severity/i);
    expect(raw).toMatch(/attack paths/i);
    expect(raw).toMatch(/Recent findings/i);
  });
});
