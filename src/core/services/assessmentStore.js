/**
 * @fileoverview Shared on-disk assessment store.
 * @description Persists completed assessments to `web/data/assessments/` so they
 *   can be read back by id (by the web dashboard, the MCP server, etc.) without
 *   re-running a scan or re-supplying the Cloudflare token. Reads require no
 *   credentials — they are just stored results.
 * @module core/services/assessmentStore
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ASSESSMENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function dataDir() {
  if (process.env.FLAREINSPECT_DATA_DIR) return process.env.FLAREINSPECT_DATA_DIR;
  // repo-root/web/data/assessments — same directory the web server uses, so an
  // assessment created over MCP also shows up in the dashboard and vice-versa.
  return path.join(__dirname, '..', '..', '..', 'web', 'data', 'assessments');
}

function isValidId(id) {
  return typeof id === 'string' && ASSESSMENT_ID_PATTERN.test(id);
}

/** Persist an assessment as <id>.json and latest.json. Best-effort; returns the file path or null. */
function persist(assessment, { dir = dataDir() } = {}) {
  if (!assessment) return null;
  fs.mkdirSync(dir, { recursive: true });
  const payload = JSON.stringify(assessment, null, 2);
  if (assessment.assessmentId) {
    fs.writeFileSync(path.join(dir, `${assessment.assessmentId}.json`), payload);
  }
  fs.writeFileSync(path.join(dir, 'latest.json'), payload);
  return assessment.assessmentId ? path.join(dir, `${assessment.assessmentId}.json`) : path.join(dir, 'latest.json');
}

/** Load the latest assessment, or null if none. */
function loadLatest({ dir = dataDir() } = {}) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'latest.json'), 'utf8')); }
  catch (_) { return null; }
}

/**
 * Load an assessment by id, or the latest when id is omitted.
 * Throws on an invalid id or when the assessment is not found.
 */
function loadById(id, { dir = dataDir() } = {}) {
  if (!id) {
    const latest = loadLatest({ dir });
    if (!latest) throw new Error('No assessment available yet. Run flareinspect_assess first.');
    return latest;
  }
  if (!isValidId(id)) throw new Error('Invalid assessmentId.');
  try { return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8')); }
  catch (_) { throw new Error(`Assessment ${id} not found.`); }
}

/** List saved assessments (compact metadata), newest first. */
function list({ dir = dataDir() } = {}) {
  let names;
  try { names = fs.readdirSync(dir); } catch (_) { return []; }
  const entries = names
    .filter(n => n.endsWith('.json') && n !== 'latest.json')
    .map(n => {
      try {
        const a = JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8'));
        return {
          assessmentId: a.assessmentId,
          accountName: a.account && a.account.name,
          score: a.score && a.score.overallScore,
          grade: a.score && a.score.grade,
          findings: (a.findings || []).length,
          completedAt: a.completedAt || a.startedAt || null
        };
      } catch (_) { return null; }
    })
    .filter(Boolean);
  entries.sort((x, y) => new Date(y.completedAt || 0) - new Date(x.completedAt || 0));
  return entries;
}

module.exports = { persist, loadById, loadLatest, list, isValidId, dataDir, ASSESSMENT_ID_PATTERN };
