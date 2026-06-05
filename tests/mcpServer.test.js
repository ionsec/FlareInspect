/**
 * Unit tests for mcp/server.mjs (engine-seam surface, no MCP transport).
 *
 * The MCP server is mostly a thin wrapper — the real safety is in the
 * tool implementations. We import the tool functions directly via the
 * CJS bridge (mcp/bridge.cjs) — no need to spin up an MCP transport.
 *
 * A true MCP-transport test would require running the SDK over stdio
 * and parsing JSON-RPC frames. We cover that with a manual smoke; here
 * we cover the engine seam + the edit-scope gate.
 */

'use strict';

const path = require('path');
const bridge = require('../mcp/bridge.cjs');
const { isRemediationEnabled, verifyEditScope } = require('../src/core/auth/editScope');

describe('mcp/server engine surface', () => {
  test('toolGetAttackPaths returns the documented shape', async () => {
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
    const out = await bridge.toolGetAttackPaths({ assessment: a });
    expect(out.graph.nodeCount).toBeGreaterThan(0);
    expect(out.graph.edgeCount).toBeGreaterThan(0);
    expect(out.paths.find(p => p.kind === 'exposed-origin')).toBeDefined();
  });

  test('toolListFindings filters by severity and status', async () => {
    const a = { findings: [
      { id: '1', severity: 'high',     status: 'failed' },
      { id: '2', severity: 'critical', status: 'failed' },
      { id: '3', severity: 'low',      status: 'passed' }
    ]};
    const out1 = await bridge.toolListFindings({ assessment: a, severity: 'high' });
    expect(out1.count).toBe(1);
    expect(out1.findings[0].id).toBe('1');
    const out2 = await bridge.toolListFindings({ assessment: a, status: 'failed' });
    expect(out2.count).toBe(2);
    const out3 = await bridge.toolListFindings({ assessment: a, severity: 'high', status: 'failed' });
    expect(out3.count).toBe(1);
  });
});

describe('mcp/server safety gate', () => {
  test('isRemediationEnabled defaults to off', () => {
    const old = { ...process.env };
    delete process.env.FLAREINSPECT_ALLOW_REMEDIATION;
    expect(isRemediationEnabled(old)).toBe(false);
  });

  test('verifyEditScope rejects empty / wrong token', () => {
    expect(verifyEditScope('wrong', { env: { FLAREINSPECT_EDIT_SCOPE: 'right' } })).toBe(false);
    expect(verifyEditScope('',     { env: { FLAREINSPECT_EDIT_SCOPE: 'right' } })).toBe(false);
  });

  test('verifyEditScope accepts the env-bound opaque secret', () => {
    expect(verifyEditScope('s3cr3t', { env: { FLAREINSPECT_EDIT_SCOPE: 's3cr3t' } })).toBe(true);
  });

  test('verifyEditScope accepts a JWT with permission:edit', () => {
    // Construct one via Node's crypto (no jsonwebtoken dep needed).
    const crypto = require('crypto');
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body   = Buffer.from(JSON.stringify({ sub: 'agent', permission: 'edit' })).toString('base64url');
    const sig    = crypto.createHmac('sha256', 'k').update(`${header}.${body}`).digest('base64url');
    const tok = `${header}.${body}.${sig}`;
    expect(verifyEditScope(tok, { env: {} })).toBe(true);
  });
});

describe('mcp/server entrypoint sanity', () => {
  test('server.mjs is a real, parseable ESM file with the expected exports', () => {
    const fs = require('fs');
    const src = fs.readFileSync(path.join(__dirname, '..', 'mcp', 'server.mjs'), 'utf8');
    expect(src).toMatch(/export\s+(async\s+)?function\s+toolAssess/);
    expect(src).toMatch(/export\s+(async\s+)?function\s+toolGetAttackPaths/);
    expect(src).toMatch(/export\s+(async\s+)?function\s+toolListFindings/);
    expect(src).toMatch(/export\s+(async\s+)?function\s+toolApplyRemediation/);
    expect(src).toMatch(/export\s+(async\s+)?function\s+toolRollback/);
    expect(src).toMatch(/export\s+(async\s+)?function\s+toolPlanRemediation/);
  });

  test('package.json registers flareinspect-mcp in bin', () => {
    const pkg = require('../package.json');
    expect(pkg.bin && pkg.bin['flareinspect-mcp']).toBe('./mcp/server.mjs');
  });
});

