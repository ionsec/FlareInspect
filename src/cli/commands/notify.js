/**
 * @fileoverview `flareinspect notify` command.
 * @description Read an assessment JSON, build a summary, dispatch to enabled
 * notification channels. Targets: slack|teams|webhook (or "all").
 * @module cli/commands/notify
 */

'use strict';

const fs = require('fs').promises;
const chalk = require('chalk');
const ora = require('ora');
const { buildSummary, dispatch, targetsFromEnv } = require('../../core/integrations/notify/notificationService');
const logger = require('../../core/utils/logger');

/**
 * Execute the notify command.
 * @param {{
 *   input: string,
 *   target?: string,
 *   threshold?: string,
 *   link?: string,
 *   dryRun?: boolean,
 *   slack?: string,
 *   teams?: string,
 *   webhook?: string,
 *   secret?: string
 * }} options
 */
async function execute(options) {
  const spinner = ora('Loading assessment data…').start();
  try {
    const raw = await fs.readFile(options.input, 'utf8');
    const assessment = JSON.parse(raw);
    spinner.succeed('Assessment data loaded');

    const summary = buildSummary(assessment, {
      link: options.link || null,
      topFindingsLimit: 5,
      attackPathCount: assessment._meta && assessment._meta.attackPathCount
    });

    const envTargets = targetsFromEnv();
    const targets = {
      slack:   options.slack   || (options.target === 'all' || options.target === 'slack' ? envTargets.slack : null),
      teams:   options.teams   || (options.target === 'all' || options.target === 'teams' ? envTargets.teams : null),
      webhook: options.webhook || (options.target === 'all' || options.target === 'webhook' ? envTargets.webhook : null),
      secret:  options.secret  || envTargets.secret,
      threshold: options.threshold || envTargets.threshold,
      dryRun: !!options.dryRun
    };

    spinner.start('Dispatching notifications…');
    const result = await dispatch(summary, targets);
    spinner.stop();

    if (result.skipped.length) {
      for (const s of result.skipped) {
        console.log(chalk.yellow(`↷ Skipped: ${s.reason}${s.threshold ? ` (threshold=${s.threshold})` : ''}`));
      }
    }
    if (result.sent.length) {
      for (const s of result.sent) {
        console.log(chalk.green(`✓ Sent via ${s.channel}${s.dryRun ? ' (dry run)' : ` (HTTP ${s.status})`}`));
      }
    }
    if (result.errors.length) {
      for (const e of result.errors) {
        console.log(chalk.red(`✗ ${e.channel}: ${e.error || `HTTP ${e.status}`}`));
           }
    }
    if (options.dryRun) {
      console.log(chalk.cyan('\n--- Dry-run payloads ---'));
      console.log(JSON.stringify(result.payloads, null, 2));
    }
    if (!result.ok) process.exit(1);
  } catch (err) {
    spinner.fail('Notify failed');
    console.error(chalk.red('Error:'), err.message);
    logger.error('Notify failed', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

module.exports = { execute };
