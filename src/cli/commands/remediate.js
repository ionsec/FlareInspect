/**
 * @fileoverview Remediate Command Handler
 * @description CLI for AI-assisted, safety-first remediation of Cloudflare findings.
 *   `plan` is a dry-run (no mutations); `apply` requires the explicit --apply flag and
 *   confirmation; `rollback` restores from a checksum-verified backup bundle.
 * @module cli/commands/remediate
 */

const fs = require('fs');
const fsp = require('fs').promises;
const readline = require('readline');
const chalk = require('chalk');
const ora = require('ora');

const CloudflareClient = require('../../core/services/cloudflareClient');
const ConfigManager = require('../../core/config');
const engine = require('../../core/remediation/remediationEngine');
const backupManager = require('../../core/remediation/backupManager');
const diffRenderer = require('../../core/remediation/diffRenderer');
const { createPlanner } = require('../../core/ai/remediationPlanner');
const logger = require('../../core/utils/logger');

/** Ask a yes/no question. Non-interactive (no TTY) returns the provided default. */
function confirm(question, defaultYes = false) {
  if (!process.stdin.isTTY) return Promise.resolve(defaultYes);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const suffix = defaultYes ? ' (Y/n) ' : ' (y/N) ';
  return new Promise(resolve => {
    rl.question(chalk.yellow(question) + suffix, answer => {
      rl.close();
      const a = answer.trim().toLowerCase();
      if (a === '') return resolve(defaultYes);
      resolve(a === 'y' || a === 'yes');
    });
  });
}

async function loadAssessment(inputPath) {
  const raw = await fsp.readFile(inputPath, 'utf8');
  const data = JSON.parse(raw);
  if (!Array.isArray(data.findings)) {
    throw new Error('Input file does not look like a FlareInspect assessment (no findings array)');
  }
  return data;
}

function makeClient(token) {
  if (!token || token.length < 10) {
    throw new Error('Invalid Cloudflare API token. Provide --token or set CLOUDFLARE_TOKEN.');
  }
  return new CloudflareClient(token);
}

// Cloudflare permissions required to APPLY remediations. FlareInspect assessment is
// read-only; remediation writes config and therefore needs a different, edit-scoped
// token. Create one at dash.cloudflare.com -> My Profile -> API Tokens.
const REQUIRED_WRITE_SCOPES = [
  'Zone → Zone Settings → Edit   (SSL mode, TLS, HSTS, security level, Brotli, HTTP/2-3, …)',
  'Zone → DNS → Edit             (DNSSEC)',
  'Zone → Zone → Read            (to enumerate zones)'
];

function printScopeNotice() {
  console.log(chalk.yellow('\n⚠  Remediation writes to your live Cloudflare config.'));
  console.log(chalk.gray('   The read-only token used for `assess` will NOT work for `apply`.'));
  console.log(chalk.gray('   Provide a token with these scopes:'));
  REQUIRED_WRITE_SCOPES.forEach(s => console.log(chalk.gray(`     • ${s}`)));
}

/** True if an error message indicates a missing-permission / auth failure. */
function looksLikePermissionError(message = '') {
  return /403|authentication failed|permission|not authorized|insufficient/i.test(message);
}

function printPlanSummary(plan) {
  console.log(chalk.bold('\nRemediation plan'));
  console.log(diffRenderer.renderPlanTable(plan.items));
  if (plan.ai?.used) {
    console.log(chalk.gray(`\nAI planner: ${plan.ai.provider}${plan.ai.notes ? ` (${plan.ai.notes})` : ''}`));
    for (const item of plan.items) {
      if (item.aiRationale) {
        console.log(chalk.gray(`  • ${item.checkId}: ${item.aiRationale}${item.aiRiskNote ? ` — ${chalk.yellow(item.aiRiskNote)}` : ''}`));
      }
    }
  } else {
    console.log(chalk.gray('\nAI planner: disabled (rules-only ordering)'));
  }
  if (plan.skipped?.length) {
    console.log(chalk.gray(`\nSkipped ${plan.skipped.length} already-compliant or unreadable check(s).`));
  }
  console.log(diffRenderer.renderManualList(plan.manualItems));
}

// ---------------------------------------------------------------------------
// plan (dry-run)
// ---------------------------------------------------------------------------
async function planAction(options) {
  const config = new ConfigManager();
  const opts = config.mergeRemediationOptions(options);
  const spinner = ora('Loading assessment...').start();
  try {
    const assessment = await loadAssessment(options.input);
    const client = makeClient(opts.token);
    const planner = createPlanner(opts.ai);

    spinner.text = 'Reading live Cloudflare state and building plan...';
    const plan = await engine.buildPlan(assessment, {
      client, planner,
      checks: opts.checks, zones: opts.zones, excludeZones: opts.excludeZones,
      concurrency: opts.concurrency
    });
    spinner.succeed('Plan ready (dry-run — nothing was changed)');

    printPlanSummary(plan);

    // Always persist a "before" backup, even in dry-run — the rollback source of truth.
    if (plan.items.length) {
      const bundle = backupManager.buildBundle({
        phase: 'before',
        assessmentId: assessment.assessmentId,
        accountName: assessment.account?.name,
        toolVersion: require('../../../package.json').version,
        entries: plan.items.map(engine.itemToEntry)
      });
      const backupPath = backupManager.saveBundle(bundle, { dir: opts.backupDir });
      console.log(chalk.green(`\n✓ Backup (before) written: ${backupPath}`));
      console.log(chalk.gray(`  Apply with: flareinspect remediate apply -i ${options.input} --apply`));
    }

    if (options.output) {
      await fsp.writeFile(options.output, JSON.stringify(plan, null, 2), 'utf8');
      console.log(chalk.green(`✓ Plan written: ${options.output}`));
    }
  } catch (error) {
    spinner.fail('Plan failed');
    console.error(chalk.red('Error:'), error.message);
    logger.error('Remediate plan failed', { error: error.message });
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------
async function applyAction(options) {
  const config = new ConfigManager();
  const opts = config.mergeRemediationOptions(options);
  const spinner = ora('Loading assessment...').start();
  try {
    const assessment = await loadAssessment(options.input);
    const client = makeClient(opts.token);
    const planner = createPlanner(opts.ai);

    spinner.text = 'Reading live Cloudflare state and building plan...';
    const plan = await engine.buildPlan(assessment, {
      client, planner,
      checks: opts.checks, zones: opts.zones, excludeZones: opts.excludeZones,
      concurrency: opts.concurrency
    });
    spinner.stop();

    printPlanSummary(plan);

    if (!plan.items.length) {
      console.log(chalk.green('\nNothing to remediate automatically.'));
      return;
    }

    if (!options.apply) {
      console.log(chalk.yellow('\nDry-run only. Re-run with --apply to make these changes.'));
      printScopeNotice();
      return;
    }

    printScopeNotice();

    // --- Confirmation gating ------------------------------------------------
    const highRisk = plan.items.filter(i => i.risk === 'high');
    const standard = plan.items.filter(i => i.risk !== 'high');
    // --yes or remediation.autoApprove skips the batch prompt for standard changes.
    const skipBatchPrompt = options.yes || opts.autoApprove;
    let approved = [];

    if (!skipBatchPrompt) {
      const ok = await confirm(`\nApply ${standard.length} standard change(s) to Cloudflare?`);
      if (!ok) { console.log(chalk.gray('Aborted.')); return; }
    }
    approved = standard;

    // High-risk items always require an explicit extra gate.
    for (const item of highRisk) {
      if (options.force) {
        approved.push(item);
      } else if (!options.yes) {
        const ok = await confirm(`  HIGH RISK — apply ${item.checkId} (${item.title}) on ${item.resourceName}?`);
        if (ok) approved.push(item);
      } else {
        console.log(chalk.yellow(`  Skipping high-risk ${item.checkId} on ${item.resourceName} (use --force to include).`));
      }
    }

    if (!approved.length) { console.log(chalk.gray('\nNo changes approved.')); return; }

    const applySpinner = ora(`Applying ${approved.length} change(s)...`).start();
    const result = await engine.apply(approved, {
      client, backupDir: opts.backupDir, assessment, concurrency: opts.concurrency
    });
    applySpinner.succeed('Apply complete');

    console.log(diffRenderer.renderResultTable(result.results));
    console.log(chalk.green(`\n✓ Backup bundle: ${result.bundlePath}`));
    console.log(chalk.gray(`  Roll back with: flareinspect remediate rollback --backup ${result.bundlePath}`));

    const failed = result.results.filter(r => r.error);
    if (failed.length) {
      console.log(chalk.red(`\n⚠️  ${failed.length} change(s) failed — see table above.`));
      if (failed.some(r => looksLikePermissionError(r.error))) {
        console.log(chalk.yellow('\nSome failures look permission-related. Your token may lack edit scopes.'));
        printScopeNotice();
      }
      process.exit(1);
    }
  } catch (error) {
    spinner.fail('Apply failed');
    console.error(chalk.red('Error:'), error.message);
    logger.error('Remediate apply failed', { error: error.message });
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------
async function rollbackAction(options) {
  const config = new ConfigManager();
  const opts = config.mergeRemediationOptions(options);
  const spinner = ora('Loading backup bundle...').start();
  try {
    if (!fs.existsSync(options.backup)) {
      throw new Error(`Backup bundle not found: ${options.backup}`);
    }
    const bundle = backupManager.loadBundle(options.backup); // validates checksum
    const client = makeClient(opts.token);
    const applied = (bundle.entries || []).filter(e => e.applied);
    spinner.succeed(`Bundle verified — ${applied.length} applied change(s) eligible for rollback`);

    if (!applied.length) { console.log(chalk.green('Nothing to roll back.')); return; }

    console.log(chalk.bold('\nWill restore:'));
    applied.forEach(e => console.log(
      `  ${e.checkId} on ${e.resourceName || e.resourceId}: ` +
      `${diffRenderer.formatValue(e.valueAfter)} → ${chalk.cyan(diffRenderer.formatValue(e.valueBefore))}`
    ));

    if (!options.yes) {
      const ok = await confirm(`\nRoll back ${applied.length} change(s)?`);
      if (!ok) { console.log(chalk.gray('Aborted.')); return; }
    }

    const rollSpinner = ora('Rolling back...').start();
    const result = await engine.rollback(bundle, { client, backupDir: opts.backupDir, concurrency: opts.concurrency });
    rollSpinner.succeed('Rollback complete');

    console.log(diffRenderer.renderResultTable(result.results));
    if (result.reportPath) console.log(chalk.green(`\n✓ Rollback report: ${result.reportPath}`));

    const failed = result.results.filter(r => r.error);
    if (failed.length) {
      console.log(chalk.red(`\n⚠️  ${failed.length} rollback(s) failed.`));
      process.exit(1);
    }
  } catch (error) {
    spinner.fail('Rollback failed');
    console.error(chalk.red('Error:'), error.message);
    logger.error('Remediate rollback failed', { error: error.message });
    process.exit(1);
  }
}

/**
 * Register the `remediate` command (with plan/apply/rollback subcommands).
 */
function register(program) {
  const remediate = program
    .command('remediate')
    .description('AI-assisted, safety-first remediation of Cloudflare findings');

  remediate
    .command('plan')
    .description('Dry-run: show proposed changes and write a backup, but mutate nothing')
    .requiredOption('-i, --input <file>', 'Assessment JSON file (from `flareinspect assess`)')
    .option('-t, --token <token>', 'Cloudflare API token')
    .option('-o, --output <file>', 'Write the structured plan to this file')
    .option('--backup-dir <dir>', 'Directory for backup bundles')
    .option('--checks <checks>', 'Comma-separated checkIds or categories to include')
    .option('--zones <zones>', 'Comma-separated zone names to include')
    .option('--exclude-zones <zones>', 'Comma-separated zone names to exclude')
    .option('--no-ai', 'Disable the AI planner (rules-only ordering)')
    .option('--ai-provider <provider>', 'AI provider (anthropic|openai|ollama|none)')
    .option('--ai-model <model>', 'AI model id (e.g. claude-opus-4-8, gpt-4o, llama3.1)')
    .option('--ai-base-url <url>', 'Base URL for a local/Ollama server (default http://localhost:11434)')
    .option('--concurrency <n>', 'Parallel operations', parseInt)
    .action(planAction);

  remediate
    .command('apply')
    .description('Apply remediations (requires --apply); backs up before and after')
    .requiredOption('-i, --input <file>', 'Assessment JSON file (from `flareinspect assess`)')
    .option('-t, --token <token>', 'Cloudflare API token')
    .option('--apply', 'Actually mutate Cloudflare (without this flag, runs as a dry-run)')
    .option('--yes', 'Skip the batch confirmation prompt (still skips high-risk unless --force)')
    .option('--force', 'Include high-risk changes without per-item confirmation')
    .option('--auto-approve', 'Auto-approve low/medium-risk changes')
    .option('--backup-dir <dir>', 'Directory for backup bundles')
    .option('--checks <checks>', 'Comma-separated checkIds or categories to include')
    .option('--zones <zones>', 'Comma-separated zone names to include')
    .option('--exclude-zones <zones>', 'Comma-separated zone names to exclude')
    .option('--no-ai', 'Disable the AI planner (rules-only ordering)')
    .option('--ai-provider <provider>', 'AI provider (anthropic|openai|ollama|none)')
    .option('--ai-model <model>', 'AI model id (e.g. claude-opus-4-8, gpt-4o, llama3.1)')
    .option('--ai-base-url <url>', 'Base URL for a local/Ollama server (default http://localhost:11434)')
    .option('--concurrency <n>', 'Parallel operations', parseInt)
    .action(applyAction);

  remediate
    .command('rollback')
    .description('Restore Cloudflare config from a checksum-verified backup bundle')
    .requiredOption('--backup <file>', 'Backup bundle JSON file')
    .option('-t, --token <token>', 'Cloudflare API token')
    .option('--yes', 'Skip the confirmation prompt')
    .option('--backup-dir <dir>', 'Directory for the rollback report')
    .option('--concurrency <n>', 'Parallel operations', parseInt)
    .action(rollbackAction);
}

module.exports = { register, planAction, applyAction, rollbackAction };
