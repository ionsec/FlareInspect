/**
 * @fileoverview Assessment Command Handler
 * @description Handles the 'assess' command for running Cloudflare security assessments
 * @module cli/commands/assess
 */

const AssessmentService = require('../../core/services/assessmentService');
const { displayAssessmentBanner, displayCompletionBanner, displayErrorBanner } = require('../utils/banner');
const { exportAssessment } = require('./export');
const logger = require('../../core/utils/logger');
const chalk = require('chalk');
const fs = require('fs').promises;
const path = require('path');
const moment = require('moment');

/**
 * Execute the assessment command
 */
async function execute(options) {
  try {
    // Set debug mode if requested
    if (options.debug || process.env.DEBUG === 'true') {
      process.env.CLOUDFLARE_DEBUG = 'true';
      logger.level = 'debug';
    }

    // Display assessment banner
    if (!options.quiet) {
      displayAssessmentBanner();
    }

    // Validate API token
    if (!options.token || options.token.length < 10) {
      throw new Error('Invalid Cloudflare API token provided');
    }

    // Initialize assessment service
    const assessmentService = new AssessmentService();

    // Run assessment
    console.log(chalk.cyan('Starting Cloudflare security assessment...\n'));
    
    const assessment = await assessmentService.runAssessment({
      apiToken: options.token
    });

    // Check if assessment failed
    if (assessment.status === 'failed') {
      displayErrorBanner(assessment.error);
      process.exit(1);
    }

    // Display completion banner with stats
    const stats = {
      duration: moment.duration(assessment.executionTime).humanize(),
      findings: assessment.findings?.length || 0,
      critical: assessment.summary?.criticalFindings || 0,
      high: assessment.summary?.highFindings || 0
    };
    
    displayCompletionBanner(stats);

    // Display summary
    displayAssessmentSummary(assessment);

    // Export results if requested
    if (!options.noExport && options.output) {
      console.log(chalk.cyan('\nExporting results...'));
      
      const exportOptions = {
        format: options.format || 'json',
        output: options.output,
        assessment: assessment
      };

      await exportAssessment(exportOptions);
      console.log(chalk.green(`✓ Results exported to: ${options.output}`));
    } else if (!options.output) {
      // Save to default location
      const timestamp = moment().format('YYYYMMDD-HHmmss');
      const defaultOutput = `flareinspect-${timestamp}.json`;
      
      await fs.writeFile(
        defaultOutput,
        JSON.stringify(assessment, null, 2),
        'utf8'
      );
      
      console.log(chalk.green(`\n✓ Assessment results saved to: ${defaultOutput}`));
      console.log(chalk.gray(`  Run 'flareinspect export -i ${defaultOutput} -f html -o report.html' to generate HTML report`));
    }

  } catch (error) {
    displayErrorBanner(error.message);
    logger.error('Assessment failed', { error: error.message, stack: error.stack });
    process.exit(1);
  }
}

/**
 * Display assessment summary
 */
function displayAssessmentSummary(assessment) {
  console.log(chalk.white.bold('\n📊 Assessment Summary\n'));

  // Account info
  console.log(chalk.cyan('Account Information:'));
  console.log(chalk.gray(`  • Account: ${assessment.account?.name || 'Unknown'}`));
  console.log(chalk.gray(`  • Zones Assessed: ${assessment.zones?.length || 0}`));
  console.log(chalk.gray(`  • Assessment ID: ${assessment.assessmentId}`));
  console.log();

  // Security score
  const score = assessment.score || {};
  const grade = score.grade || 'F';
  const gradeColor = {
    'A': 'green',
    'B': 'blue',
    'C': 'yellow',
    'D': 'magenta',
    'F': 'red'
  }[grade] || 'gray';

  console.log(chalk.cyan('Security Score:'));
  console.log(chalk[gradeColor].bold(`  • Grade: ${grade}`));
  console.log(chalk.gray(`  • Score: ${score.overallScore || 0}/100`));
  console.log();

  // Findings summary
  const summary = assessment.summary || {};
  console.log(chalk.cyan('Findings Summary:'));
  console.log(chalk.gray(`  • Total Checks: ${summary.totalChecks || 0}`));
  console.log(chalk.green(`  • Passed: ${summary.passedChecks || 0}`));
  console.log(chalk.red(`  • Failed: ${summary.failedChecks || 0}`));
  console.log();

  // Risk distribution
  console.log(chalk.cyan('Risk Distribution:'));
  if (summary.criticalFindings > 0) {
    console.log(chalk.red.bold(`  • Critical: ${summary.criticalFindings}`));
  }
  if (summary.highFindings > 0) {
    console.log(chalk.red(`  • High: ${summary.highFindings}`));
  }
  if (summary.mediumFindings > 0) {
    console.log(chalk.yellow(`  • Medium: ${summary.mediumFindings}`));
  }
  if (summary.lowFindings > 0) {
    console.log(chalk.blue(`  • Low: ${summary.lowFindings}`));
  }
  if (summary.informationalFindings > 0) {
    console.log(chalk.gray(`  • Informational: ${summary.informationalFindings}`));
  }
  console.log();

  // Top risks
  const report = assessment.report || {};
  const topRisks = report.executiveSummary?.topRisks || [];
  
  if (topRisks.length > 0) {
    console.log(chalk.cyan('Top Security Risks:'));
    topRisks.slice(0, 3).forEach((risk, index) => {
      const severityColor = {
        'critical': 'red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'blue'
      }[risk.severity] || 'gray';
      
      console.log(chalk[severityColor](`  ${index + 1}. ${risk.title} (${risk.severity})`));
    });
    console.log();
  }

  // Service breakdown
  const byService = summary.byService || {};
  const services = Object.keys(byService).filter(s => byService[s] > 0);
  
  if (services.length > 0) {
    console.log(chalk.cyan('Findings by Service:'));
    services.forEach(service => {
      console.log(chalk.gray(`  • ${service}: ${byService[service]} issues`));
    });
  }
}

module.exports = {
  execute
};