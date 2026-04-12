#!/usr/bin/env node

/**
 * @fileoverview FlareInspect CLI Entry Point
 * @description Main command-line interface for Cloudflare security assessment
 * @module cli/index
 */

const { program } = require('commander');
const chalk = require('chalk');
const { displayBanner, displayCredits } = require('./utils/banner');
const assessCommand = require('./commands/assess');
const exportCommand = require('./commands/export');
const diffCommand = require('./commands/diff');
const helpCommand = require('./commands/help');
const pkg = require('../../package.json');

// Error handling
process.on('unhandledRejection', (error) => {
  console.error(chalk.red('Error:'), error.message);
  process.exit(1);
});

// Display banner on startup (skip if launching interactive mode)
if (!process.argv.includes('--no-banner') && !process.argv.includes('-q') && process.argv.slice(2).length > 0) {
  displayBanner();
}

// Configure CLI
program
  .name('flareinspect')
  .description('FlareInspect - Cloudflare Security Assessment Tool by IONSEC.IO')
  .version(pkg.version, '-v, --version', 'Display version information')
  .option('-q, --quiet', 'Quiet mode - suppress banner and non-essential output')
  .option('--no-banner', 'Skip displaying the banner')
  .option('--debug', 'Enable debug mode');

// Assess command
program
  .command('assess')
  .description('Run a comprehensive Cloudflare security assessment')
  .option('-t, --token <token>', 'Cloudflare API token')
  .option('-o, --output <file>', 'Output file for assessment results')
  .option('-f, --format <format>', 'Output format (json|html|sarif|markdown|csv|ocsf)', 'json')
  .option('--no-export', 'Skip automatic export of results')
  .option('--ci', 'CI/CD mode: JSON to stdout, no spinners, exit codes by threshold')
  .option('--threshold <score>', 'Minimum security score (0-100) to pass (CI mode)')
  .option('--fail-on <severity>', 'Fail if any finding at or above this severity (critical|high|medium|low)')
  .option('--zones <zones>', 'Comma-separated list of zone names to assess')
  .option('--exclude-zones <zones>', 'Comma-separated list of zone names to exclude')
  .option('--checks <checks>', 'Comma-separated list of check categories to run (dns,ssl,waf,zerotrust,etc.)')
  .option('--concurrency <n>', 'Number of zones to assess in parallel', parseInt, 3)
  .option('--compliance <framework>', 'Generate compliance report for framework (cis|soc2|pci|nist)')
  .option('--sensitivity <level>', 'Data sensitivity level for contextual scoring (critical|high|medium|low)')
  .action(assessCommand.execute);

// Export command
program
  .command('export')
  .description('Export assessment results to different formats')
  .requiredOption('-i, --input <file>', 'Input assessment file (JSON)')
  .requiredOption('-o, --output <file>', 'Output file path')
  .option('-f, --format <format>', 'Export format (json|html|ocsf|sarif|markdown|csv|asff)', 'json')
  .action(exportCommand.execute);

// Diff command
program
  .command('diff')
  .description('Compare two assessments for security posture drift')
  .requiredOption('--baseline <file>', 'Baseline assessment file (JSON)')
  .requiredOption('--current <file>', 'Current assessment file (JSON)')
  .option('-o, --output <file>', 'Output file for diff results')
  .option('-f, --format <format>', 'Output format (json|markdown)', 'json')
  .action(diffCommand.execute);

// Help command (custom)
program
  .command('help [command]')
  .description('Display help for a specific command')
  .action(helpCommand.execute);

// Credits command
program
  .command('credits')
  .description('Display information about IONSEC.IO')
  .action(() => {
    displayCredits();
  });

// Launch interactive mode if no command provided
if (!process.argv.slice(2).length && !process.env.FLAREINSPECT_INTERACTIVE) {
  process.env.FLAREINSPECT_INTERACTIVE = 'true';
  require('./interactive');
} else {
  program.parse(process.argv);
}
