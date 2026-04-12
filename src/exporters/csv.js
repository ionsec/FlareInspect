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
    const headers = ['CheckID', 'Title', 'Service', 'Severity', 'Status', 'Description', 'Remediation', 'ResourceID', 'ResourceType', 'Compliance', 'EvidenceSummary', 'Observed', 'Expected', 'AffectedEntities', 'Counts', 'ReviewGuidance'];
    const rows = [headers.join(',')];

    findings.forEach(f => {
      const evidence = f.evidence || {};
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
        this.escapeCsv((f.compliance || []).join(';')),
        this.escapeCsv(evidence.summary || ''),
        this.escapeCsv(evidence.observed || f.metadata?.actualValue || ''),
        this.escapeCsv(evidence.expected || f.metadata?.expectedValue || ''),
        this.escapeCsv(this.formatAffectedEntities(evidence.affectedEntities || [])),
        this.escapeCsv(this.formatCounts(evidence.counts || {})),
        this.escapeCsv(evidence.reviewGuidance || '')
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

  formatAffectedEntities(entities) {
    return entities
      .map(entity => entity.name || entity.email || entity.id || entity.resource || JSON.stringify(entity))
      .join('; ');
  }

  formatCounts(counts) {
    return Object.entries(counts)
      .map(([key, value]) => `${key}=${value}`)
      .join('; ');
  }
}

module.exports = CSVExporter;
