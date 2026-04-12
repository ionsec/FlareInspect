/**
 * @fileoverview ASCII Banner for FlareInspect CLI
 * @module cli/utils/banner
 */

const figlet = require('figlet');
const chalk = require('chalk');
const pkg = require('../../../package.json');

/**
 * Display the FlareInspect banner
 */
function displayBanner() {
  console.clear();
  
  // Main banner
  const banner = figlet.textSync('FlareInspect', {
    font: 'ANSI Shadow',
    horizontalLayout: 'default',
    verticalLayout: 'default',
    width: 80,
    whitespaceBreak: true
  });

  console.log(chalk.cyan(banner));
  
  // Subtitle and credits
  console.log(chalk.yellow('  ═══════════════════════════════════════════════════════════════════════'));
  console.log(chalk.white.bold(`            Cloudflare Security Assessment Tool v${pkg.version}`));
  console.log(chalk.green.bold('                      Powered by IONSEC.IO'));
  console.log(chalk.yellow('  ═══════════════════════════════════════════════════════════════════════'));
  console.log();
  console.log(chalk.gray('  🔒 Enterprise-grade security assessment for Cloudflare configurations'));
  console.log(chalk.gray('  📊 OCSF-compliant security findings and comprehensive reporting'));
  console.log(chalk.gray('  🚀 Built with ❤️  by the IONSEC.IO team'));
  console.log();
  console.log(chalk.yellow('  ═══════════════════════════════════════════════════════════════════════'));
  console.log();
}

/**
 * Display a simple header for non-interactive modes
 */
function displaySimpleHeader() {
  console.log(chalk.cyan('FlareInspect') + ' - ' + chalk.white('Cloudflare Security Assessment Tool'));
  console.log(chalk.green('Powered by IONSEC.IO') + ' | ' + chalk.gray(`v${pkg.version}`));
  console.log(chalk.yellow('─'.repeat(60)));
  console.log();
}

/**
 * Display assessment start banner
 */
function displayAssessmentBanner() {
  console.log();
  console.log(chalk.yellow('  ╔═══════════════════════════════════════════════════════════════════╗'));
  console.log(chalk.yellow('  ║') + chalk.cyan.bold('             Starting Cloudflare Security Assessment              ') + chalk.yellow('║'));
  console.log(chalk.yellow('  ╚═══════════════════════════════════════════════════════════════════╝'));
  console.log();
}

/**
 * Display completion banner
 */
function displayCompletionBanner(stats = {}) {
  console.log();
  console.log(chalk.green('  ╔═══════════════════════════════════════════════════════════════════╗'));
  console.log(chalk.green('  ║') + chalk.white.bold('              Assessment Completed Successfully!                 ') + chalk.green('║'));
  console.log(chalk.green('  ╚═══════════════════════════════════════════════════════════════════╝'));
  
  if (stats.duration || stats.findings) {
    console.log();
    console.log(chalk.white('  Summary:'));
    if (stats.duration) {
      console.log(chalk.gray(`  • Duration: ${stats.duration}`));
    }
    if (stats.findings !== undefined) {
      console.log(chalk.gray(`  • Total Findings: ${stats.findings}`));
    }
    if (stats.critical !== undefined) {
      console.log(chalk.red(`  • Critical Issues: ${stats.critical}`));
    }
    if (stats.high !== undefined) {
      console.log(chalk.yellow(`  • High Risk Issues: ${stats.high}`));
    }
  }
  console.log();
}

/**
 * Display error banner
 */
function displayErrorBanner(message) {
  console.log();
  console.log(chalk.red('  ╔═══════════════════════════════════════════════════════════════════╗'));
  console.log(chalk.red('  ║') + chalk.white.bold('                     Assessment Failed!                          ') + chalk.red('║'));
  console.log(chalk.red('  ╚═══════════════════════════════════════════════════════════════════╝'));
  console.log();
  if (message) {
    console.log(chalk.red('  Error: ') + chalk.white(message));
  }
  console.log();
}

/**
 * Display credits and contact information
 */
function displayCredits() {
  console.log();
  console.log(chalk.yellow('  ═══════════════════════════════════════════════════════════════════════'));
  console.log(chalk.white.bold('                              About IONSEC.IO'));
  console.log(chalk.yellow('  ═══════════════════════════════════════════════════════════════════════'));
  console.log();
  console.log(chalk.gray('  IONSEC.IO specializes in cloud security assessments and DevSecOps'));
  console.log(chalk.gray('  solutions. We help organizations secure their cloud infrastructure'));
  console.log(chalk.gray('  with automated tools and expert guidance.'));
  console.log();
  console.log(chalk.white('  🌐 Website: ') + chalk.cyan('https://ionsec.io'));
  console.log(chalk.white('  📧 Contact: ') + chalk.cyan('security@ionsec.io'));
  console.log(chalk.white('  🐙 GitHub:  ') + chalk.cyan('https://github.com/ionsec'));
  console.log();
  console.log(chalk.yellow('  ═══════════════════════════════════════════════════════════════════════'));
  console.log();
}

module.exports = {
  displayBanner,
  displaySimpleHeader,
  displayAssessmentBanner,
  displayCompletionBanner,
  displayErrorBanner,
  displayCredits
};
