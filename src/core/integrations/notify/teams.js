/**
 * @fileoverview Microsoft Teams notifier (Power Automate Workflows / Adaptive Card).
 * @description O365 Connectors were retired; Power Automate Workflows is the supported
 * path. The same payload also works with the legacy messageCard fallback.
 * @module core/integrations/notify/teams
 */

'use strict';

const https = require('https');
const { URL } = require('url');

/**
 * Build an Adaptive Card 1.5 payload from a summary object.
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
function buildAdaptiveCard(summary) {
  const s = summary || {};
  const t = s.totals || {};
  const top = (s.topFindings || []).slice(0, 5).map(f => ({
    type: 'TextBlock',
    text: `**[${String(f.severity || 'low').toUpperCase()}]** ${f.title}`,
    wrap: true,
    spacing: 'Small'
  }));

  const card = {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        contentUrl: null,
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.5',
          body: [
            { type: 'TextBlock', text: s.title || 'FlareInspect', weight: 'Bolder', size: 'Medium' },
            {
              type: 'FactSet',
              facts: [
                { title: 'Score', value: s.score != null ? String(s.score) : '—' },
                { title: 'Grade', value: s.grade || '—' },
                { title: 'Critical', value: String(t.critical || 0) },
                { title: 'High', value: String(t.high || 0) },
                { title: 'Medium', value: String(t.medium || 0) },
                { title: 'Low', value: String(t.low || 0) },
                { title: 'Attack paths', value: String(s.attackPathCount != null ? s.attackPathCount : 0) }
              ]
            },
            ...top
          ],
          actions: s.link
            ? [{ type: 'Action.OpenUrl', title: 'Open in dashboard', url: s.link }]
            : []
        }
      }
    ]
  };
  return card;
}

/**
 * POST to a Teams Power Automate Workflows webhook URL.
 * @param {string} webhookUrl
 * @param {object} payload
 * @returns {Promise<{status:number, body:string}>}
 */
function post(webhookUrl, payload) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(webhookUrl); } catch (err) { return reject(new Error('Invalid Teams webhook URL')); }
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
    req.on('timeout', () => req.destroy(new Error('Teams webhook timed out')));
    req.write(body);
    req.end();
  });
}

module.exports = { buildAdaptiveCard, post };
