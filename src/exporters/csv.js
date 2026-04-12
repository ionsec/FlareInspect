/**
 * @fileoverview CSV Exporter for FlareInspect
 * @description Exports findings in CSV format for spreadsheet import
 * @module exporters/csv
 */

const logger = require('../core/utils/logger');

class CSVExporter {
  async export(assessment) {
    logger.info('Exporting assessment to CSV format');

    const findings = assessment.findings || [];
    const headers = ['CheckID', 'Title', 'Service', 'Severity', 'Status', 'Description', 'Remediation', 'ResourceID', 'ResourceType', 'Compliance'];
    const rows = [headers.join(',')];

    findings.forEach(f => {
      const row = [
        this.escapeCsv(f.checkId || ''),
        this.escapeCsv(f.checkTitle || ''),
        this.escapeCsv(f.service || ''),
        this.escapeCsv(f.severity || ''),
        this.escapeCsv(f.status || ''),
        this.escapeCsv(f.description || ''),
        this.escapeCsv(f.remediation || ''),
        this.escapeCsv(f.resourceId || ''),
        this.escapeCsv(f.resourceType || ''),
        this.escapeCsv((f.compliance || []).join(';'))
      ];
      rows.push(row.join(','));
    });

    return rows.join('\n');
  }

  escapeCsv(value) {
    const str = String(value);
    if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
      return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
  }
}

module.exports = CSVExporter;
