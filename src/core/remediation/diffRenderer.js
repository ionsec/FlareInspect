/**
 * @fileoverview Remediation Diff Renderer
 * @description Renders setting-level before->after diffs for remediation plans and
 *   results, both as human-friendly CLI tables and as structured objects for the web
 *   dashboard / JSON reports.
 * @module core/remediation/diffRenderer
 */

const chalk = require('chalk');
const Table = require('cli-table3');

const RISK_COLORS = {
  low: chalk.green,
  medium: chalk.yellow,
  high: chalk.red
};

/** Compact, readable rendering of any value (scalars and small objects). */
function formatValue(value) {
  if (value === null || value === undefined) return '∅';
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function colorRisk(risk) {
  const fn = RISK_COLORS[risk] || chalk.white;
  return fn((risk || 'unknown').toUpperCase());
}

/**
 * Structured diff for a single plan item (used by JSON reports and the web UI).
 */
function buildItemDiff(item) {
  return {
    checkId: item.checkId,
    title: item.title,
    setting: item.setting,
    resourceId: item.resourceId,
    resourceType: item.resourceType,
    risk: item.risk,
    before: item.valueBefore ?? null,
    proposed: item.valueProposed ?? null,
    after: item.valueAfter ?? null,
    applied: !!item.applied,
    verified: !!item.verified,
    error: item.error || null
  };
}

/** Render the planned (not-yet-applied) changes as a CLI table. */
function renderPlanTable(items) {
  if (!items || items.length === 0) {
    return chalk.gray('  No automatically remediable findings.');
  }
  const table = new Table({
    head: ['Check', 'Resource', 'Setting', 'Current → Proposed', 'Risk'].map(h => chalk.bold(h)),
    wordWrap: true,
    style: { head: [], border: [] }
  });
  for (const item of items) {
    table.push([
      item.checkId,
      item.resourceName || item.resourceId || '—',
      item.setting,
      `${chalk.gray(formatValue(item.valueBefore))} → ${chalk.cyan(formatValue(item.valueProposed))}`,
      colorRisk(item.risk)
    ]);
  }
  return table.toString();
}

/** Render the results of an apply/rollback run as a CLI table. */
function renderResultTable(items) {
  if (!items || items.length === 0) {
    return chalk.gray('  Nothing was applied.');
  }
  const table = new Table({
    head: ['Check', 'Resource', 'Setting', 'Before → After', 'Status'].map(h => chalk.bold(h)),
    wordWrap: true,
    style: { head: [], border: [] }
  });
  for (const item of items) {
    let status;
    if (item.error) status = chalk.red('✗ ' + item.error);
    else if (item.applied && item.verified) status = chalk.green('✓ verified');
    else if (item.applied && !item.verified) status = chalk.yellow('⚠ applied, unverified');
    else status = chalk.gray('skipped');

    table.push([
      item.checkId,
      item.resourceName || item.resourceId || '—',
      item.setting,
      `${chalk.gray(formatValue(item.valueBefore))} → ${chalk.cyan(formatValue(item.valueAfter))}`,
      status
    ]);
  }
  return table.toString();
}

/** Render advisory (manual-only) findings that have no executable recipe. */
function renderManualList(manualItems) {
  if (!manualItems || manualItems.length === 0) return '';
  const lines = [chalk.bold('\nManual remediation required (not auto-applied):')];
  for (const m of manualItems) {
    lines.push(`  ${chalk.yellow('•')} [${m.severity?.toUpperCase() || '—'}] ${m.checkId} ${m.checkTitle || ''}`);
    if (m.remediation) lines.push(`      ${chalk.gray(m.remediation)}`);
  }
  return lines.join('\n');
}

module.exports = {
  formatValue,
  colorRisk,
  buildItemDiff,
  renderPlanTable,
  renderResultTable,
  renderManualList
};
