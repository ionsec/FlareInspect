/**
 * @fileoverview Diff Command Handler
 * @description Compares two assessments and reports security posture drift
 * @module cli/commands/diff
 */

const fs = require('fs').promises;
const chalk = require('chalk');
const ora = require('ora');
const DiffService = require('../../core/services/diffService');
const logger = require('../../core/utils/logger');

async function execute(options) {
  const spinner = ora('Loading assessments...').start();

  try {
    const [baselineData, currentData] = await Promise.all([
      fs.readFile(options.baseline, 'utf8'),
      fs.readFile(options.current, 'utf8')
    ]);

    const baseline = JSON.parse(baselineData);
    const current = JSON.parse(currentData);

    spinner.text = 'Comparing assessments...';
    const diffService = new DiffService();
    const diff = diffService.compare(baseline, current);

    spinner.succeed('Comparison complete');

    // Display drift report
    console.log(chalk.cyan('\n' + diffService.generateDriftReport(diff)));

    // Export if requested
    if (options.output) {
      const format = options.format || 'json';
      let content;
      if (format === 'markdown' || format === 'md') {
        content = generateMarkdownDiff(diff);
      } else {
        content = JSON.stringify(diff, null, 2);
      }
      await fs.writeFile(options.output, content, 'utf8');
      console.log(chalk.green(`\n✓ Diff results exported to: ${options.output}`));
    }

    // Exit with error if regressions detected
    if (diffService.hasRegression(diff)) {
      console.log(chalk.red('\n⚠️  Regressions detected!'));
      process.exit(1);
    }

  } catch (error) {
    spinner.fail('Diff failed');
    console.error(chalk.red('Error:'), error.message);
    logger.error('Diff command failed', { error: error.message });
    process.exit(1);
  }
}

function generateMarkdownDiff(diff) {
  const s = diff.summary;
  const lines = [];
  lines.push('# FlareInspect Drift Report');
  lines.push('');
  lines.push(`**Score**: ${s.baselineScore} → ${s.currentScore} (${s.scoreDelta >= 0 ? '+' : ''}${s.scoreDelta})`);
  lines.push(`**Grade**: ${s.baselineGrade} → ${s.currentGrade}`);
  lines.push('');
  lines.push('| Category | Count |');
  lines.push('|----------|-------|');
  lines.push(`| New | ${s.newFindings} |`);
  lines.push(`| Resolved | ${s.resolvedFindings} |`);
  lines.push(`| Regressions | ${s.regressions} |`);
  lines.push(`| Improvements | ${s.improvements} |`);
  lines.push('');

  if (diff.regressions?.length > 0) {
    lines.push('## Regressions');
    diff.regressions.forEach(f => {
      lines.push(`- **[${f.severity?.toUpperCase()}]** ${f.checkTitle} - ${f.resourceId}`);
    });
    lines.push('');
  }

  if (diff.improvements?.length > 0) {
    lines.push('## Improvements');
    diff.improvements.forEach(f => {
      lines.push(`- **[${f.severity?.toUpperCase()}]** ${f.checkTitle} - ${f.resourceId}`);
    });
    lines.push('');
  }

  return lines.join('\n');
}

module.exports = { execute };
