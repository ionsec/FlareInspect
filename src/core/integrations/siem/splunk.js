/**
 * @fileoverview Splunk HEC shipper for FlareInspect findings.
 * @description Phase 2a — push findings into Splunk via the **HTTP Event
 * Collector (HEC)** API, with fields aligned to the **Common Information Model
 * (CIM)** so existing Splunk dashboards (Vulnerabilities, Alerts) light up.
 *
 *   POST {hecUrl}/services/collector/event
 *   Authorization: Splunk <hec-token>
 *   Content-Type: application/json
 *
 * Body shape:
 *   {
 *     "time":       <epoch-seconds>,
 *     "host":       <zone or hostname>,
 *     "source":     "flareinspect",
 *     "sourcetype": "cloudflare:flareinspect:finding",
 *     "index":      "main",
 *     "event":      <CIM-shaped finding>
 *   }
 *
 * CIM fields used:
 *   - `vulnerability.*` (vendor, severity, signature, description, solution)
 *   - `threat.*`        (enrichments)
 *   - `cloud.*`         (provider, account_id)
 *
 * Reference: https://dev.splunk.com/enterprise/docs/data/httpeventcollector/
 * @module core/integrations/siem/splunk
 */

'use strict';

const https = require('https');
const http  = require('http');
const { URL } = require('url');
const { buildEnrichmentIndex, enrichFinding } = require('./enrichment');

const SOURCETYPE = 'cloudflare:flareinspect:finding';
const DEFAULT_INDEX = 'main';

const SEVERITY_TO_CIM = {
  critical: 'critical',
  high:     'high',
  medium:   'medium',
  low:      'low',
  informational: 'informational'
};

/**
 * Map a FlareInspect finding to a CIM-shaped event body.
 * @param {object} finding
 * @param {object} index
 * @param {object} assessment
 * @returns {object}
 */
function toSplunkEvent(finding, index, assessment) {
  const enriched = enrichFinding(finding, index);
  const f = enriched;
  const resource = f.resource || {};
  const accountId = (assessment && assessment.account && assessment.account.id) || 'unknown';
  const zoneName  = (assessment && assessment.zones && assessment.zones[0] && assessment.zones[0].name) || 'cloudflare';
  const nodeId    = (f.flareinspect && f.flareinspect.nodeId) || null;
  const paths     = (f.flareinspect && f.flareinspect.attackPaths) || [];
  const ts        = Math.floor(Date.now() / 1000);

  return {
    time: ts,
    host: zoneName,
    source: 'flareinspect',
    sourcetype: SOURCETYPE,
    index: DEFAULT_INDEX,
    event: {
      // ── CIM: Vulnerability ────────────────────────────────────────────
      vulnerability: {
        vendor: 'IONSEC.IO',
        product: 'FlareInspect',
        version: f.id || f.checkId,
        signature: f.checkId,
        severity: SEVERITY_TO_CIM[(f.severity || '').toLowerCase()] || 'informational',
        description: f.title || f.description || f.checkId,
        message: f.description || '',
        solution: f.remediation || '',
        remediable: !!f.recipe,
        status: (f.status || 'unknown').toLowerCase()
      },
      // ── CIM: Cloud / provider context ─────────────────────────────────
      cloud: {
        provider: 'cloudflare',
        account_id: accountId,
        zone: zoneName,
        region: 'global'
      },
      // ── CIM: Resource ─────────────────────────────────────────────────
      resource: {
        type: resource.type || null,
        id:   resource.id   || null,
        name: resource.name || resource.id || null
      },
      // ── FlareInspect enrichment (the part ECS doesn't have) ───────────
      flareinspect: {
        assessment_id: (assessment && assessment.assessmentId) || null,
        finding_id:    f.id,
        check_id:      f.checkId,
        node_id:       nodeId,
        attack_path_ids: paths.map(p => p.id),
        attack_paths:  paths.map(p => ({
          id: p.id, title: p.title, severity: p.severity, hop_count: p.hopCount
        }))
      },
      // ── Threat enrichments (CIM-compatible) ───────────────────────────
      threat: {
        enrichments: paths.map(p => ({
          type: 'attack-path',
          name: p.title,
          severity: p.severity,
          hop_count: p.hopCount,
          path_id: p.id
        }))
      }
    }
  };
}

/**
 * Build the full HEC payload for an assessment.
 * Returns the array of HEC envelopes (one per finding).
 * @param {object} assessment
 * @returns {{ events: Array, count: number, index: object, paths: Array }}
 */
function buildHecPayload(assessment) {
  const index = buildEnrichmentIndex(assessment);
  const findings = (assessment && assessment.findings) || [];
  const events = findings.map(f => toSplunkEvent(f, index, assessment));
  return { events, count: events.length, index, paths: index.paths };
}

/**
 * POST a single HEC envelope.
 * @param {string} hecUrl
 * @param {object} event
 * @param {{ hecToken: string, channel?: string, timeoutMs?: number }} opts
 * @returns {Promise<{status:number, body:string, ackId?:string}>}
 */
function postOne(hecUrl, event, opts = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(hecUrl); } catch (e) { return reject(new Error('Invalid HEC URL')); }
    const lib = url.protocol === 'http:' ? http : https;
    const body = JSON.stringify(event);
    const headers = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
      'authorization': `Splunk ${opts.hecToken}`
    };
    if (opts.channel) headers['x-splunk-request-channel'] = opts.channel;
    const req = lib.request({
      method: 'POST',
      hostname: url.hostname,
      port: url.port || (url.protocol === 'http:' ? 80 : 443),
      path: (url.pathname || '').replace(/\/$/, '') + '/services/collector/event',
      headers,
      timeout: opts.timeoutMs || 15000
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let ackId;
        try { const p = JSON.parse(data); ackId = p && p.ackId; } catch (_) {}
        resolve({ status: res.statusCode || 0, body: data, ackId });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('HEC timed out')));
    req.write(body);
    req.end();
  });
}

/**
 * End-to-end: enrich + ship every event in sequence (HEC has no real "bulk"
 * endpoint — each event is one HTTP call; the channel header keeps them ordered).
 * @param {{ hecUrl: string, hecToken: string, assessment: object, channel?: string, dryRun?: boolean }} args
 * @returns {Promise<{ ok: boolean, count: number, sent: number, failed: number, errors: Array, events?: Array }>}
 */
async function shipFindings(args) {
  if (!args || !args.hecUrl)  return { ok: false, count: 0, sent: 0, failed: 0, errors: [{ error: 'hecUrl is required' }] };
  if (!args.hecToken)         return { ok: false, count: 0, sent: 0, failed: 0, errors: [{ error: 'hecToken is required' }] };
  if (!args.assessment)       return { ok: false, count: 0, sent: 0, failed: 0, errors: [{ error: 'assessment is required' }] };
  const built = buildHecPayload(args.assessment);
  if (args.dryRun) {
    return { ok: true, count: built.count, sent: built.count, failed: 0, errors: [], events: built.events, dryRun: true };
  }
  const errors = [];
  let sent = 0;
  for (let i = 0; i < built.events.length; i++) {
    try {
      const r = await postOne(args.hecUrl, built.events[i], { hecToken: args.hecToken, channel: args.channel || 'flareinspect' });
      if (r.status >= 200 && r.status < 300) sent++;
      else errors.push({ index: i, status: r.status, body: r.body });
    } catch (err) {
      errors.push({ index: i, error: err.message });
    }
  }
  return { ok: errors.length === 0, count: built.count, sent, failed: errors.length, errors };
}

module.exports = { toSplunkEvent, buildHecPayload, postOne, shipFindings, SOURCETYPE };
