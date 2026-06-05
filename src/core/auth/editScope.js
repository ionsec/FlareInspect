/**
 * @fileoverview Edit-scope policy for write-capable tools.
 * @description Both the MCP `apply_remediation` / `rollback` tools and (in
 * future) the web `/api/remediate/apply` endpoint must check this policy
 * before mutating. The "edit-scoped token" was previously only described in
 * a tool description — this is the actual gate.
 *
 * Two conditions must BOTH hold for an apply/rollback to be allowed:
 *   1. FLAREINSPECT_ALLOW_REMEDIATION is enabled (see isRemediationEnabled).
 *   2. The supplied token satisfies verifyEditScope(token):
 *        - a raw string is accepted if it matches FLAREINSPECT_EDIT_SCOPE
 *          (for non-JWT use cases — e.g. an opaque env-bound secret);
 *        - a JWT with `permission: 'edit'` (or `aud` containing `tag:edit`)
 *          is accepted when jsonwebtoken is available;
 *        - anything else is rejected.
 *
 * The MCP server passes whatever token the agent supplies; the agent is
 * expected to fetch it from the user's secret store. For a quick local
 * test, set FLAREINSPECT_EDIT_SCOPE to the same string the agent supplies.
 * @module core/auth/editScope
 */

'use strict';

const crypto = require('crypto');

const ENV_ALLOW = 'FLAREINSPECT_ALLOW_REMEDIATION';
const ENV_SCOPE = 'FLAREINSPECT_EDIT_SCOPE';

const TRUE_SET = new Set(['1', 'true', 'yes', 'on']);

/**
 * True if the operator has flipped the global remediation kill switch.
 * @param {object} [env]
 * @returns {boolean}
 */
function isRemediationEnabled(env = process.env) {
  return TRUE_SET.has(String(env[ENV_ALLOW] || '').toLowerCase());
}

/**
 * Verify that a token has edit scope. Throws no errors — returns boolean
 * so the caller can produce a clean MCP error response.
 *
 * @param {string} token
 * @param {object} [opts]
 * @param {object} [opts.env]       process.env (or a stub)
 * @param {string} [opts.expected]  an explicit expected token (overrides env)
 * @returns {boolean}
 */
function verifyEditScope(token, opts = {}) {
  if (!token || typeof token !== 'string') return false;
  const env = opts.env || process.env;
  const expected = opts.expected || env[ENV_SCOPE];
  // Opaque-secret mode: token must match the env-bound expected value.
  if (expected && token === expected) return true;
  // JWT mode: best-effort decode + claim check (no signature verification
  // by default — the issuer-side API is responsible for signing; we just
  // look at the claims here).
  const decoded = decodeJwt(token);
  if (decoded) {
    if (decoded.permission === 'edit') return true;
    if (Array.isArray(decoded.aud) && decoded.aud.some(a => String(a).includes('tag:edit'))) return true;
    if (typeof decoded.aud === 'string' && decoded.aud.includes('tag:edit')) return true;
    if (decoded.scope && /\bedit\b/.test(decoded.scope)) return true;
  }
  return false;
}

/**
 * Tiny zero-dependency JWT decode. Returns null if the token is not a
 * well-formed JWT. (We don't verify signatures here — the agent's host
 * environment is expected to obtain the token from a trusted source.)
 * @param {string} token
 * @returns {object|null}
 */
function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(payload);
  } catch (_) {
    return null;
  }
}

module.exports = {
  isRemediationEnabled,
  verifyEditScope,
  decodeJwt,
  ENV_ALLOW,
  ENV_SCOPE,
  // exported for tests
  _internal: { crypto },
};
