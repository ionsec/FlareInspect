/**
 * @fileoverview Export Command Handler
 * @description Handles the 'export' command for exporting assessment results
 * @module cli/commands/export
 */

const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');
const ora = require('ora');
const JSONExporter = require('../../exporters/json');
const HTMLExporter = require('../../exporters/html');
const SARIFExporter = require('../../exporters/sarif');
const MarkdownExporter = require('../../exporters/markdown');
const CSVExporter = require('../../exporters/csv');
const ASFFExporter = require('../../exporters/asff');
const logger = require('../../core/utils/logger');

/**
 * Execute the export command
 */
async function execute(options) {
  const spinner = ora('Loading assessment data...').start();
  
  try {
    // Read input file
    const inputData = await fs.readFile(options.input, 'utf8');
    const assessment = JSON.parse(inputData);
    
    spinner.succeed('Assessment data loaded');
    
    // Validate assessment data
    if ((!assessment.assessmentId && !assessment.assessment?.id) || !assessment.findings) {
      throw new Error('Invalid assessment data format');
    }
    
    // Ensure assessmentId is set for backward compatibility
    if (!assessment.assessmentId && assessment.assessment?.id) {
      assessment.assessmentId = assessment.assessment.id;
    }

    // Export based on format
    spinner.start(`Exporting to ${options.format.toUpperCase()} format...`);
    
    await exportAssessment({
      format: options.format,
      output: options.output,
      assessment: assessment
    });
    
    spinner.succeed(`Export completed successfully`);
    console.log(chalk.green(`✓ Results exported to: ${options.output}`));
    
  } catch (error) {
    spinner.fail('Export failed');
    console.error(chalk.red('Error:'), error.message);
    logger.error('Export failed', { error: error.message, stack: error.stack });
    process.exit(1);
  }
}

/**
 * Export assessment to specified format
 */
async function exportAssessment(options) {
  const { format, output, assessment } = options;
  
  switch (format.toLowerCase()) {
    case 'json':
    case 'ocsf':
      const jsonExporter = new JSONExporter();
      const jsonData = format === 'ocsf' 
        ? await jsonExporter.exportOCSF(assessment)
        : await jsonExporter.export(assessment);
      await fs.writeFile(output, JSON.stringify(jsonData, null, 2), 'utf8');
      break;
      
    case 'html':
      const htmlExporter = new HTMLExporter();
      const htmlContent = await htmlExporter.export(assessment);
      await fs.writeFile(output, htmlContent, 'utf8');
      break;

    case 'sarif':
      const sarifExporter = new SARIFExporter();
      const sarifData = await sarifExporter.export(assessment);
      await fs.writeFile(output, JSON.stringify(sarifData, null, 2), 'utf8');
      break;

    case 'markdown':
    case 'md':
      const mdExporter = new MarkdownExporter();
      const mdContent = await mdExporter.export(assessment);
      await fs.writeFile(output, mdContent, 'utf8');
      break;

    case 'csv':
      const csvExporter = new CSVExporter();
      const csvContent = await csvExporter.export(assessment);
      await fs.writeFile(output, csvContent, 'utf8');
      break;

    case 'asff':
      const asffExporter = new ASFFExporter();
      const asffData = await asffExporter.export(assessment);
      await fs.writeFile(output, JSON.stringify(asffData, null, 2), 'utf8');
      break;
      
    default:
      throw new Error(`Unsupported export format: ${format}. Supported: json, html, ocsf, sarif, markdown, csv, asff`);
  }
}

module.exports = {
  execute,
  exportAssessment
};