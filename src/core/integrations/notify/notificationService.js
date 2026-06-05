/**
 * @fileoverview Notification service — dispatch a summary to one or more channels.
 * @description Builds the summary payload from an assessment (score, grade, severity
 * counts, top findings, attack-path count, optional link), then dispatches to
 * the enabled channels with a severity-threshold filter.
 *
 * All transports (slack, teams, webhook) live under src/core/integrations/notify/.
 * Configuration is read from env vars OR the optional `integrations.notifications.*`
 * config block. Secrets are *only* read from env (FLAREINSPECT_*_WEBHOOK).
 * @module core/integrations/notify/notificationService
 */

'use strict';

const slack = require('./slack');
const teams = require('./teams');
const webhook = require('./webhook');

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, pass: 5 };

/**
 * Build a summary from an assessment.
 * @param {object} assessment
 * @param {{link?: string|null, topFindingsLimit?: number}} [opts]
 * @returns {object}
 */
function buildSummary(assessment, opts = {}) {
  const a = assessment || {};
  const findings = Array.isArray(a.findings) ? a.findings : [];
  const totals = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const f of findings) {
    const sev = (f.severity || 'informational').toLowerCase();
    if (totals[sev] != null) totals[sev]++;
  }
  const top = [...findings]
    .filter(f => (f.status === 'failed' || f.status === 'warning'))
    .sort((x, y) => (SEVERITY_RANK[(x.severity || 'low').toLowerCase()] ?? 9) - (SEVERITY_RANK[(y.severity || 'low').toLowerCase()] ?? 9))
    .slice(0, opts.topFindingsLimit || 5)
    .map(f => ({
      title: f.title || f.checkId || f.id,
      severity: f.severity,
      resourceType: f.resource && f.resource.type,
      resourceName: f.resource && (f.resource.name || f.resource.id)
    }));
  return {
    title: opts.title || `FlareInspect: ${a.assessmentId || 'assessment'}`,
    score: (a.score && typeof a.score === 'object' ? a.score.total : a.score) || null,
    grade: a.grade || (a.score && typeof a.score === 'object' ? a.score.grade : null) || null,
    totals,
    topFindings: top,
    link: opts.link || null,
    attackPathCount: opts.attackPathCount != null ? opts.attackPathCount : (a._meta && a._meta.attackPathCount) || 0
  };
}

/**
 * Resolve the targets from env vars.
 * @returns {{slack?: string, teams?: string, webhook?: string, secret?: string, threshold?: string}}
 */
function targetsFromEnv(env = process.env) {
  return {
    slack:   env.FLAREINSPECT_SLACK_WEBHOOK   || null,
    teams:   env.FLAREINSPECT_TEAMS_WEBHOOK   || null,
    webhook: env.FLAREINSPECT_WEBHOOK_URL     || null,
    secret:  env.FLAREINSPECT_WEBHOOK_SECRET  || null,
    threshold: env.FLAREINSPECT_NOTIFY_THRESHOLD || null
  };
}

/**
 * Should the summary cross the threshold?
 * If no threshold is set, always notify. Otherwise only notify if the worst
 * severity in the totals is at or above the threshold.
 * @param {object} summary
 * @param {string|null} threshold   one of critical|high|medium|low|informational
 * @returns {boolean}
 */
function passesThreshold(summary, threshold) {
  if (!threshold) return true;
  const t = String(threshold).toLowerCase();
  const tIdx = SEVERITY_RANK[t];
  if (tIdx == null) return true;
  // worst severity in totals
  let worst = 'pass';
  for (const sev of Object.keys(SEVERITY_RANK)) {
    if (summary.totals && summary.totals[sev] > 0 && (SEVERITY_RANK[sev] ?? 99) < (SEVERITY_RANK[worst] ?? 99)) worst = sev;
  }
  return (SEVERITY_RANK[worst] ?? 99) <= tIdx;
}

/**
 * Dispatch a summary to enabled channels.
 * @param {object} summary
 * @param {{slack?:string, teams?:string, webhook?:string, secret?:string, threshold?:string|null, dryRun?:boolean}} targets
 * @returns {Promise<{ok:boolean, sent:Array, skipped:Array, errors:Array, payloads?:object}>}
 */
async function dispatch(summary, targets = {}) {
  const result = { ok: true, sent: [], skipped: [], errors: [], payloads: {} };
  if (!passesThreshold(summary, targets.threshold)) {
    result.skipped.push({ reason: 'below-threshold', threshold: targets.threshold });
    return result;
  }

  if (targets.slack) {
    try {
      const payload = slack.buildPayload(summary);
      result.payloads.slack = payload;
      if (!targets.dryRun) {
        const r = await slack.post(targets.slack, payload);
        if (r.status >= 200 && r.status < 300) result.sent.push({ channel: 'slack', status: r.status });
        else { result.ok = false; result.errors.push({ channel: 'slack', status: r.status, body: r.body }); }
      } else {
        result.sent.push({ channel: 'slack', status: 0, dryRun: true });
      }
    } catch (err) { result.ok = false; result.errors.push({ channel: 'slack', error: err.message }); }
  }

  if (targets.teams) {
    try {
      const payload = teams.buildAdaptiveCard(summary);
      result.payloads.teams = payload;
      if (!targets.dryRun) {
        const r = await teams.post(targets.teams, payload);
        if (r.status >= 200 && r.status < 300) result.sent.push({ channel: 'teams', status: r.status });
        else { result.ok = false; result.errors.push({ channel: 'teams', status: r.status, body: r.body }); }
      } else {
        result.sent.push({ channel: 'teams', status: 0, dryRun: true });
      }
    } catch (err) { result.ok = false; result.errors.push({ channel: 'teams', error: err.message }); }
  }

  if (targets.webhook) {
    try {
      const payload = summary;
      result.payloads.webhook = payload;
      if (!targets.dryRun) {
        const r = await webhook.post(targets.webhook, payload, { secret: targets.secret, event: 'assessment.summary' });
        if (r.status >= 200 && r.status < 300) result.sent.push({ channel: 'webhook', status: r.status, delivery: r.delivery });
        else { result.ok = false; result.errors.push({ channel: 'webhook', status: r.status, body: r.body }); }
      } else {
        result.sent.push({ channel: 'webhook', status: 0, dryRun: true });
      }
    } catch (err) { result.ok = false; result.errors.push({ channel: 'webhook', error: err.message }); }
  }

  if (result.sent.length === 0 && result.errors.length === 0) {
    result.skipped.push({ reason: 'no-targets' });
  }
  return result;
}

module.exports = { buildSummary, dispatch, passesThreshold, targetsFromEnv };
