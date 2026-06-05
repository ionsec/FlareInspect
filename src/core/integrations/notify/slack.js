/**
 * @fileoverview Slack Block Kit notifier.
 * @description Posts a formatted message to a Slack Incoming Webhook URL.
 * Pure transport — no business logic, no assessment access.
 * @module core/integrations/notify/slack
 */

'use strict';

const https = require('https');
const { URL } = require('url');

/**
 * Build the Block Kit payload from a summary object.
 * @param {{
 *   title: string,
 *   score?: number|null,
 *   grade?: string|null,
 *   totals?: {critical:number,high:number,medium:number,low:number,informational:number},
 *   topFindings?: Array<{title:string, severity:string, resourceType?:string, resourceName?:string}>,
 *   link?: string|null,
 *   attackPathCount?: number
 * }} summary
 */
function buildPayload(summary) {
  const s = summary || {};
  const t = s.totals || {};
  const top = (s.topFindings || []).slice(0, 5).map((f, i) => ({
    type: 'rich_text',
    elements: [{
      type: 'rich_text_section',
      elements: [
        { type: 'text', text: `${i + 1}. `, style: { bold: true } },
        { type: 'text', text: `[${String(f.severity || 'low').toUpperCase()}] ` },
        { type: 'text', text: f.title }
      ]
    }]
  }));

  const fields = [
    { type: 'mrkdwn', text: `*Score:*\n${s.score != null ? s.score : '—'}${s.grade ? ` (${s.grade})` : ''}` },
    { type: 'mrkdwn', text: `*Critical:* ${t.critical || 0}   *High:* ${t.high || 0}` },
    { type: 'mrkdwn', text: `*Medium:* ${t.medium || 0}   *Low:* ${t.low || 0}` },
    { type: 'mrkdwn', text: `*Attack paths:* ${s.attackPathCount != null ? s.attackPathCount : 0}` }
  ];

  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: s.title || 'FlareInspect' } },
    { type: 'section', fields },
    ...top,
  ];
  if (s.link) {
    blocks.push({ type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: 'Open in dashboard' }, url: s.link }] });
  }
  return { text: s.title || 'FlareInspect', blocks };
}

/**
 * POST a payload to a Slack incoming webhook URL.
 * @param {string} webhookUrl
 * @param {object} payload   the Block Kit payload
 * @returns {Promise<{status:number, body:string}>}
 */
function post(webhookUrl, payload) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(webhookUrl); } catch (err) { return reject(new Error('Invalid Slack webhook URL')); }
    const body = JSON.stringify(payload);
    const req = https.request({
      method: 'POST',
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + (url.search || ''),
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body)
      },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode || 0, body: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Slack webhook timed out')));
    req.write(body);
    req.end();
  });
}

module.exports = { buildPayload, post };
