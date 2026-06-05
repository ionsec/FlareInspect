/**
 * @fileoverview Generic HMAC-signed webhook notifier.
 * @description POSTs a JSON payload to a generic URL with an `X-FlareInspect-Signature`
 * header (HMAC-SHA256 of the raw body, hex-encoded). Verifiers recompute the
 * signature with the shared secret and reject mismatches.
 * @module core/integrations/notify/webhook
 */

'use strict';

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const HEADER_SIGNATURE = 'x-flareinspect-signature';
const HEADER_EVENT     = 'x-flareinspect-event';
const HEADER_DELIVERY  = 'x-flareinspect-delivery';

/**
 * Compute the HMAC-SHA256 signature of a JSON string.
 * @param {string} body
 * @param {string} secret
 * @returns {string} hex digest prefixed with "sha256="
 */
function sign(body, secret) {
  if (!secret) return '';
  return 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
}

/**
 * POST a payload to a generic webhook URL with HMAC signature.
 * @param {string} webhookUrl
 * @param {object} payload
 * @param {{secret?: string, event?: string}} [opts]
 * @returns {Promise<{status:number, body:string, signature:string, delivery:string}>}
 */
function post(webhookUrl, payload, opts = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(webhookUrl); } catch (err) { return reject(new Error('Invalid webhook URL')); }
    const body = JSON.stringify(payload);
    const sig = sign(body, opts.secret);
    const delivery = crypto.randomUUID();
    const headers = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
      [HEADER_EVENT]: opts.event || 'assessment.summary',
      [HEADER_DELIVERY]: delivery,
    };
    if (sig) headers[HEADER_SIGNATURE] = sig;
    const lib = url.protocol === 'http:' ? http : https;
    const req = lib.request({
      method: 'POST',
      hostname: url.hostname,
      port: url.port || (url.protocol === 'http:' ? 80 : 443),
      path: url.pathname + (url.search || ''),
      headers,
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode || 0, body: data, signature: sig, delivery }));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Webhook timed out')));
    req.write(body);
    req.end();
  });
}

module.exports = { post, sign, HEADER_SIGNATURE, HEADER_EVENT, HEADER_DELIVERY };
