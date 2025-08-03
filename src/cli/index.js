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
  .requiredOption('-t, --token <token>', 'Cloudflare API token')
  .option('-o, --output <file>', 'Output file for assessment results')
  .option('-f, --format <format>', 'Output format (json|html)', 'json')
  .option('--no-export', 'Skip automatic export of results')
  .action(assessCommand.execute);

// Export command
program
  .command('export')
  .description('Export assessment results to different formats')
  .requiredOption('-i, --input <file>', 'Input assessment file (JSON)')
  .requiredOption('-o, --output <file>', 'Output file path')
  .option('-f, --format <format>', 'Export format (json|html|ocsf)', 'json')
  .action(exportCommand.execute);

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
  // Launch interactive mode directly without parsing
  process.env.FLAREINSPECT_INTERACTIVE = 'true';
  require('./interactive');
} else {
  // Parse arguments only if we have commands
  program.parse(process.argv);
}