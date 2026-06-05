/**
 * @fileoverview Integration tests for GET/PUT /api/settings and the OpenAPI spec route.
 *
 * Strategy mirrors integrationsShip.test.js: import the Express `app` (no auto
 * listen on require), bind to a random port, exercise over raw http. The
 * settings store is pointed at a throwaway temp file via FLAREINSPECT_SETTINGS_FILE.
 */

'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Point the runtime settings store at a temp file BEFORE requiring the server.
const SETTINGS_FILE = path.join(os.tmpdir(), `flareinspect-settings-api-${process.pid}.json`);
process.env.FLAREINSPECT_SETTINGS_FILE = SETTINGS_FILE;

jest.mock('p-limit', () => ({ default: () => (fn) => fn() }));
jest.mock('https', () => {
  class Agent { createConnection() { return null; } }
  return { request: () => ({ on() {}, write() {}, end() {}, destroy() {} }), Agent };
});

let server;
let baseUrl;

function httpRequest(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(baseUrl + urlPath);
    const req = http.request(
      { method, hostname: u.hostname, port: u.port, path: u.pathname + u.search, headers: { 'content-type': 'application/json' } },
      (res) => {
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => {
          try { resolve({ status: res.statusCode, json: data ? JSON.parse(data) : null }); }
          catch (_) { resolve({ status: res.statusCode, json: null }); }
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

beforeAll(async () => {
  const { app } = require('../web/server');
  server = app.listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
  if (server) await new Promise(r => server.close(r));
  try { fs.unlinkSync(SETTINGS_FILE); } catch (_) { /* ignore */ }
});

beforeEach(() => { try { fs.unlinkSync(SETTINGS_FILE); } catch (_) { /* ignore */ } });

describe('OpenAPI spec', () => {
  test('GET /api-docs/openapi.json returns a valid spec', async () => {
    const res = await httpRequest('GET', '/api-docs/openapi.json');
    expect(res.status).toBe(200);
    expect(res.json.openapi).toMatch(/^3\./);
    expect(res.json.paths['/api/settings']).toBeDefined();
    expect(res.json.paths['/api/assess']).toBeDefined();
  });
});

describe('GET /api/settings', () => {
  test('returns a masked view + remediation status, with no secret values', async () => {
    const res = await httpRequest('GET', '/api/settings');
    expect(res.status).toBe(200);
    expect(res.json.remediation).toBe('disabled');
    // secret key: present, but never a raw value
    expect(res.json.settings.slackWebhook.secret).toBe(true);
    expect(res.json.settings.slackWebhook).not.toHaveProperty('value');
    // non-secret key: value field present (null when unset)
    expect(res.json.settings.aiProvider).toHaveProperty('value');
  });
});

describe('PUT /api/settings', () => {
  test('persists values and masks secrets on read-back', async () => {
    const put = await httpRequest('PUT', '/api/settings', {
      slackWebhook: 'https://hooks.slack.com/services/T/B/secret1234',
      aiProvider: 'anthropic',
      aiModel: 'claude-opus-4-8'
    });
    expect(put.status).toBe(200);
    expect(put.json.ok).toBe(true);

    const get = await httpRequest('GET', '/api/settings');
    expect(get.json.settings.slackWebhook.configured).toBe(true);
    expect(get.json.settings.slackWebhook.source).toBe('settings');
    expect(get.json.settings.slackWebhook.hint).toMatch(/1234$/);
    expect(get.json.settings.slackWebhook).not.toHaveProperty('value');
    expect(get.json.settings.aiProvider.value).toBe('anthropic');
    expect(get.json.settings.aiModel.value).toBe('claude-opus-4-8');
  });

  test('rejects invalid enum values with 400', async () => {
    const res = await httpRequest('PUT', '/api/settings', { aiProvider: 'bogus-provider' });
    expect(res.status).toBe(400);
  });
});
