/**
 * @fileoverview Remediation Engine
 * @description Orchestrates the safe remediation lifecycle: select remediable
 *   findings, capture a "before" backup, optionally apply changes, capture an
 *   "after" backup, verify, and support rollback from a backup bundle. Mutations are
 *   deterministic (recipe registry); the AI planner only orders/annotates. Per-item
 *   failures are isolated and never abort the batch.
 * @module core/remediation/remediationEngine
 */

const pLimit = require('p-limit').default;
const logger = require('../utils/logger');
const recipeRegistry = require('./recipeRegistry');
const backupManager = require('./backupManager');

const DEFAULT_CONCURRENCY = 4;

/**
 * Build a recipe execution context from a finding (or a backup entry).
 */
function contextFor(source) {
  return {
    zoneId: source.resourceId,
    resourceId: source.resourceId,
    resourceType: source.resourceType,
    finding: source.finding || null
  };
}

/**
 * Filter findings by zone names / check categories, mirroring assess CLI semantics.
 */
function filterFindings(findings, { checks, zones, excludeZones, zoneNameById } = {}) {
  let result = findings;
  if (checks && checks.length) {
    const set = new Set(checks.map(c => String(c).toLowerCase()));
    result = result.filter(f =>
      set.has(String(f.checkId).toLowerCase()) || set.has(String(f.service).toLowerCase())
    );
  }
  if (zones && zones.length) {
    const set = new Set(zones.map(z => z.toLowerCase()));
    result = result.filter(f => set.has(String(zoneNameById?.[f.resourceId] || '').toLowerCase()));
  }
  if (excludeZones && excludeZones.length) {
    const set = new Set(excludeZones.map(z => z.toLowerCase()));
    result = result.filter(f => !set.has(String(zoneNameById?.[f.resourceId] || '').toLowerCase()));
  }
  return result;
}

/**
 * Build a remediation plan from an assessment. Performs LIVE reads to capture
 * current values (the backup source) and to skip already-compliant settings.
 *
 * @returns {Promise<{items: object[], manualItems: object[], skipped: object[], summary: object}>}
 */
async function buildPlan(assessment, { client, planner, checks, zones, excludeZones, concurrency } = {}) {
  const findings = Array.isArray(assessment.findings) ? assessment.findings : [];
  const zoneNameById = {};
  (assessment.zones || []).forEach(z => { zoneNameById[z.id] = z.name; });

  const failing = filterFindings(
    findings.filter(f => f.status === 'FAIL'),
    { checks, zones, excludeZones, zoneNameById }
  );

  const remediableFindings = [];
  const manualItems = [];
  for (const f of failing) {
    if (recipeRegistry.has(f.checkId)) remediableFindings.push(f);
    else manualItems.push({
      checkId: f.checkId,
      checkTitle: f.checkTitle,
      severity: f.severity,
      resourceId: f.resourceId,
      resourceType: f.resourceType,
      remediation: f.remediation
    });
  }

  const limit = pLimit(concurrency || DEFAULT_CONCURRENCY);
  const items = [];
  const skipped = [];

  await Promise.all(remediableFindings.map(f => limit(async () => {
    const recipe = recipeRegistry.get(f.checkId);
    const ctx = contextFor({ ...f, finding: f });
    try {
      const valueBefore = await recipe.read(client, ctx);
      if (recipe.isCompliant(valueBefore)) {
        skipped.push({ checkId: f.checkId, resourceId: f.resourceId, reason: 'already-compliant', valueBefore });
        return;
      }
      items.push({
        checkId: f.checkId,
        title: recipe.title,
        setting: recipe.setting,
        scope: recipe.scope,
        risk: recipe.risk,
        reversible: recipe.reversible,
        severity: f.severity,
        resourceId: f.resourceId,
        resourceType: f.resourceType,
        resourceName: zoneNameById[f.resourceId] || f.resourceId,
        valueBefore,
        valueProposed: recipe.proposed(ctx),
        valueAfter: null,
        applied: false,
        verified: false,
        error: null
      });
    } catch (err) {
      skipped.push({ checkId: f.checkId, resourceId: f.resourceId, reason: 'read-failed', error: err.message });
      logger.warn(`Could not read current state for ${f.checkId} on ${f.resourceId}`, { error: err.message });
    }
  })));

  let orderedItems = items;
  let ai = { used: false };
  if (planner) {
    try {
      const result = await planner.annotate(items, manualItems);
      orderedItems = result.items;
      ai = { used: result.aiUsed, provider: result.provider, notes: result.notes };
    } catch (err) {
      logger.warn('AI planner failed; falling back to rules-only ordering', { error: err.message });
      orderedItems = rulesOnlyOrder(items);
    }
  } else {
    orderedItems = rulesOnlyOrder(items);
  }

  return {
    items: orderedItems,
    manualItems,
    skipped,
    ai,
    summary: {
      assessmentId: assessment.assessmentId,
      accountName: assessment.account?.name,
      remediable: orderedItems.length,
      manual: manualItems.length,
      skipped: skipped.length,
      byRisk: countBy(orderedItems, 'risk')
    }
  };
}

/** Deterministic fallback ordering: severity, then risk ascending (safe-first). */
function rulesOnlyOrder(items) {
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const riskRank = { low: 0, medium: 1, high: 2 };
  return [...items].sort((a, b) =>
    (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9) ||
    (riskRank[a.risk] ?? 9) - (riskRank[b.risk] ?? 9)
  );
}

function countBy(arr, key) {
  return arr.reduce((acc, x) => { acc[x[key]] = (acc[x[key]] || 0) + 1; return acc; }, {});
}

function itemToEntry(item) {
  return {
    checkId: item.checkId,
    resourceId: item.resourceId,
    resourceType: item.resourceType,
    resourceName: item.resourceName,
    setting: item.setting,
    risk: item.risk,
    valueBefore: item.valueBefore ?? null,
    valueProposed: item.valueProposed ?? null,
    valueAfter: item.valueAfter ?? null,
    applied: !!item.applied,
    verified: !!item.verified,
    error: item.error || null
  };
}

/**
 * Apply a set of (already-approved) plan items. Writes the "before" backup BEFORE
 * any mutation, then applies each item, captures the "after" state, verifies, and
 * persists the completed bundle to the same file.
 *
 * @returns {Promise<{bundlePath: string, bundle: object, results: object[]}>}
 */
async function apply(items, { client, backupDir, filePath, assessment, concurrency } = {}) {
  if (!items || items.length === 0) {
    return { bundlePath: null, bundle: null, results: [] };
  }

  // 1. Persist the "before" backup FIRST — this is the rollback source of truth.
  const beforeBundle = backupManager.buildBundle({
    phase: 'before',
    assessmentId: assessment?.assessmentId,
    accountName: assessment?.account?.name,
    toolVersion: assessment?.metadata?.toolVersion || require('../../../package.json').version,
    entries: items.map(itemToEntry)
  });
  const bundlePath = backupManager.saveBundle(beforeBundle, { dir: backupDir, filePath });
  logger.info(`Backup (before) written: ${bundlePath}`);

  // 2. Apply each item with isolated failure handling.
  const limit = pLimit(concurrency || DEFAULT_CONCURRENCY);
  await Promise.all(items.map(item => limit(async () => {
    const recipe = recipeRegistry.get(item.checkId);
    const ctx = contextFor(item);
    try {
      await recipe.apply(client, ctx);
      item.applied = true;
      item.valueAfter = await recipe.read(client, ctx);
      item.verified = await recipe.verify(client, ctx);
      if (!item.verified) {
        logger.warn(`Applied ${item.checkId} on ${item.resourceId} but verification failed`);
      }
    } catch (err) {
      item.error = err.message;
      logger.fail(`Failed to apply ${item.checkId} on ${item.resourceId}: ${err.message}`);
    }
  })));

  // 3. Persist the completed bundle (before + after) to the same file.
  const completeBundle = backupManager.buildBundle({
    phase: 'complete',
    assessmentId: assessment?.assessmentId,
    accountName: assessment?.account?.name,
    toolVersion: beforeBundle.toolVersion,
    entries: items.map(itemToEntry)
  });
  backupManager.saveBundle(completeBundle, { filePath: bundlePath });
  logger.info(`Backup (complete) written: ${bundlePath}`);

  return { bundlePath, bundle: completeBundle, results: items };
}

/**
 * Roll back a previously-applied remediation from a backup bundle. Restores each
 * applied, reversible entry to its captured valueBefore and verifies the result.
 *
 * @returns {Promise<{results: object[], reportPath: string|null}>}
 */
async function rollback(bundle, { client, backupDir, concurrency } = {}) {
  const entries = (bundle.entries || []).filter(e => e.applied);
  const limit = pLimit(concurrency || DEFAULT_CONCURRENCY);
  const results = [];

  await Promise.all(entries.map(entry => limit(async () => {
    const recipe = recipeRegistry.get(entry.checkId);
    const ctx = contextFor(entry);
    const result = {
      checkId: entry.checkId,
      resourceId: entry.resourceId,
      resourceName: entry.resourceName,
      setting: entry.setting,
      valueBefore: entry.valueAfter,   // for the rollback report: was=after
      valueAfter: entry.valueBefore,   // target=original
      applied: false,
      verified: false,
      error: null
    };
    if (!recipe) {
      result.error = 'No recipe found for this check (cannot roll back)';
    } else if (!recipe.reversible) {
      result.error = 'Recipe is not reversible';
    } else {
      try {
        await recipe.restore(client, ctx, entry.valueBefore);
        result.applied = true;
        const restored = await recipe.read(client, ctx);
        result.valueAfter = restored;
        // Verified if restored value matches the original (or original was null/skip)
        result.verified = entry.valueBefore === null || entry.valueBefore === undefined
          ? true
          : JSON.stringify(restored) === JSON.stringify(entry.valueBefore);
      } catch (err) {
        result.error = err.message;
        logger.fail(`Rollback failed for ${entry.checkId} on ${entry.resourceId}: ${err.message}`);
      }
    }
    results.push(result);
  })));

  // Write a rollback report alongside the backups (does not overwrite the bundle).
  let reportPath = null;
  if (backupDir) {
    const reportBundle = backupManager.buildBundle({
      phase: 'rollback',
      assessmentId: bundle.assessmentId,
      accountName: bundle.accountName,
      toolVersion: bundle.toolVersion,
      entries: results
    });
    reportPath = backupManager.saveBundle(reportBundle, {
      dir: backupDir,
      filePath: undefined
    });
  }

  return { results, reportPath };
}

module.exports = {
  buildPlan,
  apply,
  rollback,
  filterFindings,
  rulesOnlyOrder,
  itemToEntry,
  contextFor
};
