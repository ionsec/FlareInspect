/**
 * Unit tests for src/core/auth/editScope.js
 *
 * The "edit-scope" claim is the safety boundary for the MCP apply/rollback
 * tools (and, later, /api/remediate/apply). It must:
 *   - be off by default (no FLAREINSPECT_ALLOW_REMEDIATION → no apply)
 *   - accept the env-bound opaque secret
 *   - accept a JWT with permission:edit / tag:edit / scope:edit
 *   - reject tokens with read-only / missing claims
 *   - reject empty / non-string input
 */

'use strict';

const { isRemediationEnabled, verifyEditScope, decodeJwt, _internal } = require('../src/core/auth/editScope');

function makeJwt(payload, secret = 'k') {
  const crypto = _internal.crypto;
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body   = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig    = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

describe('editScope.isRemediationEnabled', () => {
  test('is off by default', () => {
    expect(isRemediationEnabled({})).toBe(false);
  });
  test('respects the documented true-values', () => {
    for (const v of ['1', 'true', 'yes', 'on', 'TRUE', 'Yes']) {
      expect(isRemediationEnabled({ FLAREINSPECT_ALLOW_REMEDIATION: v })).toBe(true);
    }
  });
  test('rejects arbitrary / empty values', () => {
    for (const v of ['', '0', 'false', 'no', 'off', 'lol']) {
      expect(isRemediationEnabled({ FLAREINSPECT_ALLOW_REMEDIATION: v })).toBe(false);
    }
  });
});

describe('editScope.verifyEditScope', () => {
  test('rejects empty / non-string input', () => {
    expect(verifyEditScope('')).toBe(false);
    expect(verifyEditScope(null)).toBe(false);
    expect(verifyEditScope(undefined)).toBe(false);
    expect(verifyEditScope(42)).toBe(false);
    expect(verifyEditScope({})).toBe(false);
  });

  test('accepts the env-bound opaque secret', () => {
    expect(verifyEditScope('s3cret', { env: { FLAREINSPECT_EDIT_SCOPE: 's3cret' } })).toBe(true);
    expect(verifyEditScope('wrong',  { env: { FLAREINSPECT_EDIT_SCOPE: 's3cret' } })).toBe(false);
  });

  test('accepts an explicit expected (no env)', () => {
    expect(verifyEditScope('abc', { expected: 'abc' })).toBe(true);
    expect(verifyEditScope('abc', { expected: 'xyz' })).toBe(false);
  });

  test('accepts a JWT with permission:edit', () => {
    const tok = makeJwt({ sub: 'agent', permission: 'edit' });
    expect(verifyEditScope(tok, { env: {} })).toBe(true);
  });

  test('accepts a JWT with aud containing tag:edit', () => {
    const tok = makeJwt({ sub: 'agent', aud: ['cloudflare', 'tag:edit'] });
    expect(verifyEditScope(tok, { env: {} })).toBe(true);
  });

  test('accepts a JWT with scope claim containing edit', () => {
    const tok = makeJwt({ sub: 'agent', scope: 'read write edit' });
    expect(verifyEditScope(tok, { env: {} })).toBe(true);
  });

  test('rejects a JWT with read-only claims', () => {
    const tok = makeJwt({ sub: 'agent', permission: 'read', aud: 'cloudflare' });
    expect(verifyEditScope(tok, { env: {} })).toBe(false);
  });

  test('rejects a malformed JWT', () => {
    expect(verifyEditScope('not-a-jwt', { env: {} })).toBe(false);
    expect(verifyEditScope('aaa.bbb.ccc', { env: {} })).toBe(false);   // body is "bbb" not base64-json
  });
});

describe('editScope.decodeJwt', () => {
  test('round-trips a payload', () => {
    const tok = makeJwt({ a: 1, b: 'x' });
    expect(decodeJwt(tok)).toEqual({ a: 1, b: 'x' });
  });
  test('returns null for non-JWT', () => {
    expect(decodeJwt('foo')).toBeNull();
    expect(decodeJwt('a.b')).toBeNull();
    expect(decodeJwt('a.b.c.d')).toBeNull();
  });
});
