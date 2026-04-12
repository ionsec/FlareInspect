/**
 * @fileoverview SARIF v2.1.0 Exporter for FlareInspect
 * @description Exports findings in SARIF format for GitHub Advanced Security
 * @module exporters/sarif
 */

const logger = require('../core/utils/logger');
const pkg = require('../../package.json');

class SARIFExporter {
  async export(assessment) {
    logger.info('Exporting assessment to SARIF format');

    const findings = (assessment.findings || []).filter(f => f.status === 'FAIL');
    const rules = this.buildRules(assessment.findings || []);
    const results = findings.map(f => this.buildResult(f));

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'FlareInspect',
            version: pkg.version,
            informationUri: 'https://github.com/ionsec/flareinspect',
            organization: 'IONSEC.IO',
            rules
          }
        },
        results,
        invocations: [{
          executionSuccessful: assessment.status === 'completed',
          startTimeUtc: assessment.startedAt,
          endTimeUtc: assessment.completedAt
        }]
      }]
    };
  }

  buildRules(findings) {
    const seen = new Set();
    return findings.filter(f => {
      if (seen.has(f.checkId)) return false;
      seen.add(f.checkId);
      return true;
    }).map(f => ({
      id: f.checkId,
      name: f.checkTitle,
      shortDescription: { text: f.description || f.checkTitle },
      fullDescription: { text: f.remediation || 'No remediation available' },
      defaultConfiguration: { level: this.mapLevel(f.severity) },
      helpUri: 'https://developers.cloudflare.com/'
    }));
  }

  buildResult(finding) {
    return {
      ruleId: finding.checkId,
      ruleIndex: 0,
      level: this.mapLevel(finding.severity),
      message: { text: finding.description },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: finding.resourceId || 'unknown' },
          region: { startLine: 1 }
        }
      }],
      remediation: { description: { text: finding.remediation || 'Review and remediate' } },
      partialFingerprints: {
        checkId: finding.checkId,
        resourceId: finding.resourceId || 'unknown'
      }
    };
  }

  mapLevel(severity) {
    const map = { critical: 'error', high: 'error', medium: 'warning', low: 'note', informational: 'note' };
    return map[severity?.toLowerCase()] || 'warning';
  }
}

module.exports = SARIFExporter;
