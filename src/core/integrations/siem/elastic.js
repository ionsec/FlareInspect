/**
 * @fileoverview Elasticsearch (ECS) shipper for FlareInspect findings.
 * @description Phase 2a — push findings into Elasticsearch using the **Elastic
 * Common Schema (ECS)** field layout, via the `_bulk` API.
 *
 * Each finding becomes a document with:
 *   - `@timestamp`, `event.kind: 'alert'`, `event.category: ['vulnerability']`
 *   - `vulnerability.id`, `vulnerability.severity`, `vulnerability.description`
 *   - `cloud.provider: 'cloudflare'`, `cloud.account.id`
 *   - `host.name` (zone), `url.full` (resource), `related.entity` (graph node ids)
 *   - `threat.enrichments[]` — attack-path context from the resource graph
 *   - `labels.*` — short tags for Kibana filtering (severity, checkId, status)
 *
 * Authentication: `ApiKey` (Elasticsearch 8+) preferred; basic auth supported
 * via `username`/`password`. Bulk NDJSON is line-delimited (action line + doc
 * line, both ending in \n).
 *
 * Reference: https://www.elastic.co/guide/en/ecs/current/index.html
 * @module core/integrations/siem/elastic
 */

'use strict';

const https = require('https');
const http  = require('http');
const { URL } = require('url');
const { buildEnrichmentIndex, enrichFinding } = require('./enrichment');

const ECS_VERSION = '8.11.0';

const SEVERITY_TO_ECS = {
  critical: 'CRITICAL',
  high:     'HIGH',
  medium:   'MEDIUM',
  low:      'LOW',
  informational: 'INFORMATIONAL'
};

/**
 * Map a FlareInspect finding to an ECS-shaped document.
 * Pure — no I/O, no side effects.
 * @param {object} finding
 * @param {object} index
 * @param {object} assessment
 * @returns {object}
 */
function toEcsDoc(finding, index, assessment) {
  const enriched = enrichFinding(finding, index);
  const f = enriched;
  const resource = f.resource || {};
  const accountId = (assessment && assessment.account && assessment.account.id) || 'unknown';
  const zoneName  = (assessment && assessment.zones && assessment.zones[0] && assessment.zones[0].name) || null;
  const nodeId    = (f.flareinspect && f.flareinspect.nodeId) || null;
  const paths     = (f.flareinspect && f.flareinspect.attackPaths) || [];

  // Threat enrichments — one per attack path
  const threatEnrichments = paths.map(p => ({
    indicator: {
      type: 'attack-path',
      name: p.title
    },
    attack: {
      type: p.severity
    },
    confidence: 'Medium',
    'threat.enrichments.matched.event': {
      kind: 'event',
      category: ['threat'],
      type: ['indicator']
    },
    matched: {
      atomic: p.id,
      field: 'flareinspect.attack_path.id',
      id: p.id
    }
  }));

  return {
    '@timestamp': new Date().toISOString(),
    'event.kind': 'alert',
    'event.category': ['vulnerability'],
    'event.type': ['info'],
    'event.action': 'flareinspect.finding',
    'event.dataset': 'flareinspect.finding',
    'event.module': 'flareinspect',
    'event.severity_name': SEVERITY_TO_ECS[(f.severity || '').toLowerCase()] || 'INFORMATIONAL',
    'event.severity': f.severity ? Math.max(0, Math.min(100, severityToScore(f.severity))) : 0,
    'event.created': new Date().toISOString(),
    'event.original': JSON.stringify(f),

    'ecs.version': ECS_VERSION,

    'cloud.provider': 'cloudflare',
    'cloud.account.id': accountId,

    'vulnerability.id': f.id || f.checkId,
    'vulnerability.classification': f.checkId,
    'vulnerability.severity': SEVERITY_TO_ECS[(f.severity || '').toLowerCase()] || 'INFORMATIONAL',
    'vulnerability.score': severityToScore(f.severity),
    'vulnerability.description': f.title || f.description || f.checkId,
    'vulnerability.message': f.description || '',
    'vulnerability.remediation': f.remediation || '',

    'host.name': zoneName || (resource.name || resource.id || 'unknown'),

    'url.full': resource.name || '',

    'related.entity': [
      ...(nodeId ? [nodeId] : []),
      ...paths.map(p => p.id)
    ].filter(Boolean),

    'threat.enrichments': threatEnrichments,

    'labels': {
      check_id: f.checkId,
      severity: (f.severity || 'informational').toLowerCase(),
      status:   (f.status   || 'unknown').toLowerCase(),
      remediable: f.recipe ? 'true' : 'false',
      node_id:   nodeId || '',
      path_count: String(paths.length)
    },

    // Provider-specific (FlareInspect)
    'flareinspect.assessment_id': (assessment && assessment.assessmentId) || null,
    'flareinspect.node_id': nodeId,
    'flareinspect.attack_path_ids': paths.map(p => p.id),
    'flareinspect.resource_type': resource.type || null,
    'flareinspect.resource_id':   resource.id   || null
  };
}

function severityToScore(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical') return 95;
  if (s === 'high')     return 75;
  if (s === 'medium')   return 50;
  if (s === 'low')      return 25;
  return 5;
}

/**
 * Build the full _bulk body as an array of action/doc lines, plus a doc list.
 * @param {object} assessment
 * @param {string} [indexName]   default 'flareinspect-findings'
 * @returns {{ body: string, count: number, index: object, paths: Array }}
 */
function buildBulkBody(assessment, indexName = 'flareinspect-findings') {
  const index = buildEnrichmentIndex(assessment);
  const findings = (assessment && assessment.findings) || [];
  const docs = findings.map(f => toEcsDoc(f, index, assessment));
  const lines = [];
  for (const d of docs) {
    lines.push(JSON.stringify({ index: { _index: indexName, _id: d['vulnerability.id'] } }));
    lines.push(JSON.stringify(d));
  }
  return { body: lines.join('\n') + (lines.length ? '\n' : ''), count: docs.length, index, paths: index.paths, docs };
}

/**
 * POST the _bulk body to Elasticsearch.
 * @param {string} esUrl       e.g. https://es.example.com
 * @param {string} body        NDJSON bulk body
 * @param {{apiKey?: string, username?: string, password?: string, timeoutMs?: number}} [opts]
 * @returns {Promise<{status:number, body:string, itemsCount:number}>}
 */
function postBulk(esUrl, body, opts = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(esUrl); } catch (e) { return reject(new Error('Invalid ES URL')); }
    const lib = url.protocol === 'http:' ? http : https;
    const headers = {
      'content-type': 'application/x-ndjson',
      'content-length': Buffer.byteLength(body)
    };
    if (opts.apiKey)   headers['authorization'] = `ApiKey ${opts.apiKey}`;
    else if (opts.username && opts.password) {
      headers['authorization'] = 'Basic ' + Buffer.from(`${opts.username}:${opts.password}`).toString('base64');
    }
    const req = lib.request({
      method: 'POST',
      hostname: url.hostname,
      port: url.port || (url.protocol === 'http:' ? 80 : 443),
      path: (url.pathname || '').replace(/\/$/, '') + '/_bulk',
      headers,
      timeout: opts.timeoutMs || 30000
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let items = 0;
        try {
          const parsed = JSON.parse(data);
          if (parsed && Array.isArray(parsed.items)) items = parsed.items.length;
        } catch (_) { /* ignore */ }
        resolve({ status: res.statusCode || 0, body: data, itemsCount: items });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('ES bulk timed out')));
    req.write(body);
    req.end();
  });
}

/**
 * End-to-end: enrich + ship.
 * @param {{ esUrl: string, apiKey?: string, username?: string, password?: string, assessment: object, indexName?: string, dryRun?: boolean }} args
 * @returns {Promise<{ ok: boolean, status: number, count: number, body?: string, itemsCount?: number, docs?: Array, error?: string }>}
 */
async function shipFindings(args) {
  if (!args || !args.esUrl) return { ok: false, status: 0, count: 0, error: 'esUrl is required' };
  if (!args.assessment)    return { ok: false, status: 0, count: 0, error: 'assessment is required' };
  const built = buildBulkBody(args.assessment, args.indexName || 'flareinspect-findings');
  if (args.dryRun) {
    return { ok: true, status: 0, count: built.count, body: built.body, docs: built.docs, dryRun: true };
  }
  try {
    const r = await postBulk(args.esUrl, built.body, {
      apiKey: args.apiKey,
      username: args.username,
      password: args.password
    });
    return { ok: r.status >= 200 && r.status < 300, status: r.status, count: built.count, itemsCount: r.itemsCount, body: r.body };
  } catch (err) {
    return { ok: false, status: 0, count: built.count, error: err.message };
  }
}

/**
 * Render the index template FlareInspect recommends.
 * Pure — returns the JSON body, no I/O.
 * @returns {object}
 */
function buildIndexTemplate() {
  return {
    index_patterns: ['flareinspect-*'],
    priority: 200,
    template: {
      settings: {
        'index.refresh_interval': '5s',
        'index.number_of_shards': 1
      },
      mappings: {
        dynamic: true,
        properties: {
          '@timestamp':           { type: 'date' },
          'event.kind':           { type: 'keyword' },
          'event.category':       { type: 'keyword' },
          'event.severity':       { type: 'integer' },
          'cloud.provider':       { type: 'keyword' },
          'cloud.account.id':     { type: 'keyword' },
          'vulnerability.id':     { type: 'keyword' },
          'vulnerability.classification': { type: 'keyword' },
          'vulnerability.severity': { type: 'keyword' },
          'vulnerability.score':  { type: 'float' },
          'host.name':            { type: 'keyword' },
          'url.full':             { type: 'keyword' },
          'related.entity':       { type: 'keyword' },
          'labels.check_id':      { type: 'keyword' },
          'labels.severity':      { type: 'keyword' },
          'labels.status':        { type: 'keyword' },
          'labels.node_id':       { type: 'keyword' },
          'labels.path_count':    { type: 'keyword' },
          'flareinspect.assessment_id': { type: 'keyword' },
          'flareinspect.node_id':       { type: 'keyword' },
          'flareinspect.attack_path_ids': { type: 'keyword' },
          'flareinspect.resource_type':  { type: 'keyword' },
          'flareinspect.resource_id':    { type: 'keyword' },
          'threat.enrichments': { type: 'nested' }
        }
      }
    }
  };
}

module.exports = { toEcsDoc, buildBulkBody, postBulk, shipFindings, buildIndexTemplate, ECS_VERSION };
