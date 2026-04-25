/**
 * @fileoverview ASCII banner for the FlareInspect CLI
 * @module cli/utils/banner
 *
 * Visual identity (matches FlareInspect brand v1):
 *  - "Flare" in light-amber, "Inspect" in italic flare orange
 *  - flare orange = #f6821f (Cloudflare-adjacent oklch 72 .17 52)
 *  - flare deep   = #b85a14
 *  - tagline in muted gray, mono-feel rule lines
 */

const figlet = require('figlet');
const chalk = require('chalk');
const pkg = require('../../../package.json');

// Brand palette (sRGB approximations of the design's OKLCH tokens)
const FLARE       = chalk.hex('#f6821f');
const FLARE_BOLD  = chalk.hex('#f6821f').bold;
const FLARE_DIM   = chalk.hex('#b85a14');
const INK         = chalk.hex('#eaeaec');
const INK_DIM     = chalk.hex('#7a7a82');
const RULE        = chalk.hex('#3a3a42');

// 7-line ASCII rendering of the flare-in-reticle mark (compact for terminals)
const MARK = [
  '       ·       ',
  '    ·  ▲  ·    ',
  '   ◂ ╱╲   ╱╲ ▸ ',
  '   ◂ ╲╱ ◉ ╲╱ ▸ ',
  '   ◂ ╱╲   ╱╲ ▸ ',
  '    ·  ▼  ·    ',
  '       ·       '
];

const RULE_LINE = '  ' + '─'.repeat(71);

/**
 * Display the FlareInspect banner.
 */
function displayBanner() {
  console.clear();

  const word = figlet.textSync('FlareInspect', {
    font: 'ANSI Shadow',
    horizontalLayout: 'default',
    verticalLayout: 'default',
    width: 80,
    whitespaceBreak: true
  });

  // Render the wordmark in flare orange
  console.log(FLARE(word));

  // Tagline
  console.log(RULE(RULE_LINE));
  console.log(INK.bold(`            Cloudflare Security Assessment  ·  v${pkg.version}`));
  console.log(FLARE_DIM('                       by ionsec.io'));
  console.log(RULE(RULE_LINE));
  console.log();
  console.log(INK_DIM('  ▸ 40+ checks across 21 Cloudflare security categories'));
  console.log(INK_DIM('  ▸ Evidence-rich findings · drift detection · CI gates'));
  console.log(INK_DIM('  ▸ Exports: JSON · HTML · OCSF · SARIF · MD · CSV · ASFF'));
  console.log();
  console.log(RULE(RULE_LINE));
  console.log();
}

/**
 * Display a compact header for non-interactive modes.
 */
function displaySimpleHeader() {
  // "Flare" + italic "Inspect" approximation: bold flare for both, dim tagline
  console.log(FLARE_BOLD('Flare') + FLARE('Inspect') + INK_DIM(`  ·  v${pkg.version}`));
  console.log(INK_DIM('Cloudflare security assessment · by ionsec.io'));
  console.log(RULE('─'.repeat(60)));
  console.log();
}

/**
 * Print the small ASCII flare mark (useful for status output).
 */
function displayMark() {
  MARK.forEach(line => console.log(FLARE(line)));
}

/**
 * Display assessment-start banner.
 */
function displayAssessmentBanner() {
  console.log();
  console.log(RULE('  ┌' + '─'.repeat(67) + '┐'));
  console.log(RULE('  │') + FLARE_BOLD('             Starting Cloudflare Security Assessment              ') + RULE('│'));
  console.log(RULE('  └' + '─'.repeat(67) + '┘'));
  console.log();
}

/**
 * Display completion banner.
 */
function displayCompletionBanner(stats = {}) {
  const OK = chalk.hex('#56b366'); // oklch(72% .15 155) approximation
  console.log();
  console.log(OK('  ┌' + '─'.repeat(67) + '┐'));
  console.log(OK('  │') + INK.bold('              Assessment Completed Successfully                   ') + OK('│'));
  console.log(OK('  └' + '─'.repeat(67) + '┘'));

  if (stats.duration || stats.findings != null) {
    console.log();
    console.log(INK('  Summary:'));
    if (stats.duration)        console.log(INK_DIM(`  • Duration:        ${stats.duration}`));
    if (stats.findings != null) console.log(INK_DIM(`  • Total findings:  ${stats.findings}`));
    if (stats.critical != null) console.log(chalk.hex('#d04141')(`  • Critical issues: ${stats.critical}`));
    if (stats.high != null)     console.log(FLARE(`  • High risk:       ${stats.high}`));
  }
  console.log();
}

/**
 * Display error banner.
 */
function displayErrorBanner(message) {
  const ERR = chalk.hex('#d04141');
  console.log();
  console.log(ERR('  ┌' + '─'.repeat(67) + '┐'));
  console.log(ERR('  │') + INK.bold('                       Assessment Failed                          ') + ERR('│'));
  console.log(ERR('  └' + '─'.repeat(67) + '┘'));
  console.log();
  if (message) {
    console.log(ERR('  Error: ') + INK(message));
  }
  console.log();
}

/**
 * Display credits and contact information.
 */
function displayCredits() {
  console.log();
  console.log(RULE(RULE_LINE));
  console.log(INK.bold('                              About IONSEC.IO'));
  console.log(RULE(RULE_LINE));
  console.log();
  console.log(INK_DIM('  IONSEC.IO specializes in cloud security assessments and DevSecOps'));
  console.log(INK_DIM('  solutions. We help organizations secure their cloud infrastructure'));
  console.log(INK_DIM('  with automated tools and expert guidance.'));
  console.log();
  console.log(INK('  Website: ') + FLARE('https://ionsec.io'));
  console.log(INK('  Contact: ') + FLARE('security@ionsec.io'));
  console.log(INK('  GitHub:  ') + FLARE('https://github.com/ionsec'));
  console.log();
  console.log(RULE(RULE_LINE));
  console.log();
}

module.exports = {
  displayBanner,
  displaySimpleHeader,
  displayMark,
  displayAssessmentBanner,
  displayCompletionBanner,
  displayErrorBanner,
  displayCredits,
};
