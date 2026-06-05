/**
 * @fileoverview Shared severity ordering for the resource graph and attack-path engine.
 * @description One source of truth for severity comparison + a stable worst-of helper.
 * The same constants exist in `web/public/app.js` (SEVERITY_ORDER) — both sides must agree,
 * so this module exports the canonical list and the browser keeps its local copy in sync
 * (or the dashboard can fetch the assessment's `meta.severityOrder` instead).
 * @module core/graph/severity
 */

'use strict';

const SEVERITY_ORDER = Object.freeze([
  'critical',
  'high',
  'medium',
  'low',
  'informational',
  'pass'
]);

const SEVERITY_INDEX = Object.freeze(
  SEVERITY_ORDER.reduce((acc, sev, idx) => {
    acc[sev] = idx;
    return acc;
  }, {})
);

/**
 * Return the more severe of two severity labels.
 * Unknown / nullish values are treated as `pass` (least severe).
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
function worst(a, b) {
  const ai = SEVERITY_INDEX[a] ?? SEVERITY_INDEX.pass;
  const bi = SEVERITY_INDEX[b] ?? SEVERITY_INDEX.pass;
  return SEVERITY_ORDER[Math.min(ai, bi)];
}

/**
 * Compute the worst severity across a list of findings.
 * @param {Array<{severity?: string, status?: string}>} findings
 * @returns {string} one of SEVERITY_ORDER (defaults to `pass` if empty/unknown)
 */
function worstOf(findings) {
  let out = 'pass';
  for (const f of findings || []) {
    if (f && f.status === 'passed') continue;       // passed findings don't drag severity up
    out = worst(out, f && f.severity);
  }
  return out;
}

module.exports = {
  SEVERITY_ORDER,
  SEVERITY_INDEX,
  worst,
  worstOf,
};
