/**
 * @fileoverview Help Command Handler
 * @description Displays detailed help information for FlareInspect commands
 * @module cli/commands/help
 */

const chalk = require('chalk');
const { displaySimpleHeader } = require('../utils/banner');

const commandHelp = {
  assess: {
    description: 'Run a comprehensive Cloudflare security assessment',
    usage: 'flareinspect assess --token <token> [options]',
    options: [
      { flag: '-t, --token <token>', description: 'Cloudflare API token (required)' },
      { flag: '-o, --output <file>', description: 'Output file for assessment results' },
      { flag: '-f, --format <format>', description: 'Output format: json or html (default: json)' },
      { flag: '--no-export', description: 'Skip automatic export of results' },
      { flag: '--debug', description: 'Enable debug mode for detailed logging' }
    ],
    examples: [
      {
        command: 'flareinspect assess --token YOUR_TOKEN',
        description: 'Run assessment and save to timestamped file'
      },
      {
        command: 'flareinspect assess --token YOUR_TOKEN --output report.html --format html',
        description: 'Run assessment and export as HTML report'
      },
      {
        command: 'flareinspect assess --token YOUR_TOKEN --debug',
        description: 'Run assessment with debug logging'
      }
    ]
  },
  
  export: {
    description: 'Export assessment results to different formats',
    usage: 'flareinspect export --input <file> --output <file> [options]',
    options: [
      { flag: '-i, --input <file>', description: 'Input assessment file in JSON format (required)' },
      { flag: '-o, --output <file>', description: 'Output file path (required)' },
      { flag: '-f, --format <format>', description: 'Export format: json, html, or ocsf (default: json)' }
    ],
    examples: [
      {
        command: 'flareinspect export -i assessment.json -o report.html -f html',
        description: 'Convert JSON assessment to HTML report'
      },
      {
        command: 'flareinspect export -i assessment.json -o ocsf-findings.json -f ocsf',
        description: 'Export findings in OCSF format'
      }
    ]
  }
};

/**
 * Execute help command
 */
function execute(command) {
  displaySimpleHeader();
  
  if (command && commandHelp[command]) {
    // Show specific command help
    showCommandHelp(command);
  } else {
    // Show general help
    showGeneralHelp();
  }
}

/**
 * Show help for a specific command
 */
function showCommandHelp(command) {
  const help = commandHelp[command];
  
  console.log(chalk.cyan.bold(`Command: ${command}`));
  console.log(chalk.white(help.description));
  console.log();
  
  console.log(chalk.yellow('Usage:'));
  console.log(`  ${help.usage}`);
  console.log();
  
  console.log(chalk.yellow('Options:'));
  help.options.forEach(option => {
    console.log(`  ${chalk.green(option.flag.padEnd(25))} ${option.description}`);
  });
  console.log();
  
  if (help.examples && help.examples.length > 0) {
    console.log(chalk.yellow('Examples:'));
    help.examples.forEach(example => {
      console.log(chalk.gray(`  # ${example.description}`));
      console.log(`  $ ${example.command}`);
      console.log();
    });
  }
}

/**
 * Show general help
 */
function showGeneralHelp() {
  console.log(chalk.cyan.bold('FlareInspect - Cloudflare Security Assessment Tool'));
  console.log(chalk.white('Enterprise-grade security assessment for Cloudflare configurations'));
  console.log();
  
  console.log(chalk.yellow('Usage:'));
  console.log('  flareinspect <command> [options]');
  console.log();
  
  console.log(chalk.yellow('Available Commands:'));
  console.log(`  ${chalk.green('assess'.padEnd(15))} Run a comprehensive Cloudflare security assessment`);
  console.log(`  ${chalk.green('export'.padEnd(15))} Export assessment results to different formats`);
  console.log(`  ${chalk.green('help'.padEnd(15))} Display help information`);
  console.log(`  ${chalk.green('credits'.padEnd(15))} Display information about IONSEC.IO`);
  console.log();
  
  console.log(chalk.yellow('Global Options:'));
  console.log(`  ${chalk.green('-v, --version'.padEnd(25))} Display version information`);
  console.log(`  ${chalk.green('-q, --quiet'.padEnd(25))} Quiet mode - suppress banner`);
  console.log(`  ${chalk.green('--no-banner'.padEnd(25))} Skip displaying the banner`);
  console.log(`  ${chalk.green('--debug'.padEnd(25))} Enable debug mode`);
  console.log();
  
  console.log(chalk.yellow('Quick Start:'));
  console.log(chalk.gray('  # Run assessment'));
  console.log('  $ flareinspect assess --token YOUR_CLOUDFLARE_TOKEN');
  console.log();
  console.log(chalk.gray('  # Generate HTML report'));
  console.log('  $ flareinspect export -i assessment.json -o report.html -f html');
  console.log();
  
  console.log(chalk.yellow('Required Cloudflare API Permissions:'));
  console.log('  • Zone:Read');
  console.log('  • DNS:Read');
  console.log('  • SSL and Certificates:Read');
  console.log('  • Firewall Services:Read');
  console.log('  • Account Settings:Read');
  console.log();
  
  console.log(chalk.gray('For more information on a specific command:'));
  console.log('  $ flareinspect help <command>');
  console.log();
  
  console.log(chalk.gray('Documentation: https://github.com/ionsec/flareinspect'));
  console.log(chalk.gray('Support: security@ionsec.io'));
}

module.exports = {
  execute
};