/**
 * @fileoverview Remediation Backup Manager
 * @description The safety core of remediation. Captures before/after snapshots of
 *   the exact Cloudflare values a remediation run touches, persists them as
 *   checksum-protected rollback bundles, and validates integrity before any
 *   rollback replay. The "before" bundle is written BEFORE any mutation so a crash
 *   mid-apply never loses the rollback source of truth.
 * @module core/remediation/backupManager
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCHEMA_VERSION = 1;

/**
 * @typedef {Object} BackupEntry
 * @property {string} checkId
 * @property {string} resourceId
 * @property {string} resourceType
 * @property {string} setting
 * @property {*} valueBefore
 * @property {*} valueProposed
 * @property {*} [valueAfter]
 * @property {string} risk
 * @property {boolean} applied
 * @property {boolean} verified
 * @property {string|null} error
 * @property {string} [accountId]              Account-scope recipes thread accountId
 * @property {string} [createdResourceId]      Set by create-recipes for delete-on-rollback
 * @property {string} [createdResourceType]    E.g. 'dns_record', 'notification_policy'
 * @property {string} [restoreOp]              'patch' (default) | 'delete' for created resources
 */

/**
 * Deterministic checksum over the entries. Uses a recursive key-sorted stringify so
 * re-serialization of an unchanged bundle always yields an identical hash.
 */
function computeChecksum(entries) {
  return crypto.createHash('sha256').update(stableStringify(entries)).digest('hex');
}

/**
 * Recursive, key-sorted JSON stringify for stable hashing.
 */
function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

/**
 * Build an in-memory rollback bundle with a fresh integrity checksum.
 */
function buildBundle({ phase, assessmentId, toolVersion, accountName, entries }) {
  const safeEntries = entries || [];
  return {
    schema: SCHEMA_VERSION,
    createdAt: new Date().toISOString(),
    phase,                         // 'before' | 'complete'
    assessmentId: assessmentId || null,
    accountName: accountName || null,
    toolVersion: toolVersion || null,
    entries: safeEntries,
    checksum: computeChecksum(safeEntries)
  };
}

function defaultFileName(bundle) {
  const ts = bundle.createdAt.replace(/[:.]/g, '-');
  const id = (bundle.assessmentId || 'assessment').replace(/[^a-zA-Z0-9_-]/g, '');
  return `${ts}-${id}.backup.json`;
}

/**
 * Persist a bundle to disk. If filePath is provided it is overwritten in place
 * (used to upgrade a 'before' bundle to a 'complete' one); otherwise a new file is
 * created under dir. Returns the absolute path written.
 */
function saveBundle(bundle, { dir, filePath } = {}) {
  const target = filePath || path.join(dir || process.cwd(), defaultFileName(bundle));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(bundle, null, 2), 'utf8');
  return path.resolve(target);
}

/**
 * Load and validate a bundle. Throws if the schema is unknown or the checksum does
 * not match (tamper / corruption guard) — rollback must never replay a bad bundle.
 */
function loadBundle(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (e) {
    throw new Error(`Backup bundle is not valid JSON: ${e.message}`);
  }
  if (bundle.schema !== SCHEMA_VERSION) {
    throw new Error(`Unsupported backup schema version: ${bundle.schema} (expected ${SCHEMA_VERSION})`);
  }
  if (!Array.isArray(bundle.entries)) {
    throw new Error('Backup bundle is missing an entries array');
  }
  const expected = computeChecksum(bundle.entries);
  if (bundle.checksum !== expected) {
    throw new Error('Backup bundle checksum mismatch — refusing to roll back from a tampered or corrupt bundle');
  }
  return bundle;
}

/**
 * List backup bundles in a directory, newest first, with light metadata.
 */
function listBundles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.backup.json'))
    .map(f => {
      const full = path.join(dir, f);
      try {
        const b = JSON.parse(fs.readFileSync(full, 'utf8'));
        return {
          file: f,
          path: path.resolve(full),
          createdAt: b.createdAt,
          phase: b.phase,
          assessmentId: b.assessmentId,
          accountName: b.accountName,
          entryCount: Array.isArray(b.entries) ? b.entries.length : 0,
          appliedCount: Array.isArray(b.entries) ? b.entries.filter(e => e.applied).length : 0
        };
      } catch {
        return { file: f, path: path.resolve(full), error: 'unreadable' };
      }
    })
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

module.exports = {
  SCHEMA_VERSION,
  computeChecksum,
  stableStringify,
  buildBundle,
  saveBundle,
  loadBundle,
  listBundles,
  defaultFileName
};
