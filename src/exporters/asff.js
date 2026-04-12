/**
 * @fileoverview AWS Security Hub ASFF Exporter for FlareInspect
 * @description Exports findings in ASFF format for hybrid cloud environments
 * @module exporters/asff
 */

const logger = require('../core/utils/logger');
const pkg = require('../../package.json');

class ASFFExporter {
  async export(assessment) {
    logger.info('Exporting assessment to ASFF format');

    const findings = (assessment.findings || []).filter(f => f.status === 'FAIL');

    return findings.map(finding => ({
      SchemaVersion: '2018-10-08',
      Id: `flareinspect:${assessment.assessmentId}:${finding.checkId}:${finding.resourceId}`,
      ProductArn: 'arn:aws:securityhub:::product:ionsec/flareinspect',
      ProductFields: {
        Product: 'FlareInspect',
        Version: pkg.version,
        CheckId: finding.checkId,
        Service: finding.service,
        Provider: 'Cloudflare'
      },
      GeneratorId: 'flareinspect',
      AwsAccountId: assessment.account?.id || 'unknown',
      Types: ['Software and Configuration Checks/Cloudflare'],
      FirstObservedAt: finding.timestamp ? new Date(finding.timestamp).toISOString() : new Date().toISOString(),
      LastObservedAt: finding.timestamp ? new Date(finding.timestamp).toISOString() : new Date().toISOString(),
      CreatedAt: new Date().toISOString(),
      Severity: {
        Product: this.mapNormalizedSeverity(finding.severity),
        Normalized: this.mapSeverityScore(finding.severity),
        Original: finding.severity || 'MEDIUM'
      },
      Title: finding.checkTitle || 'Cloudflare Security Finding',
      Description: finding.description || 'Security issue detected',
      Remediation: {
        Recommendation: {
          Text: finding.remediation || 'Review Cloudflare documentation',
          Url: 'https://developers.cloudflare.com/'
        }
      },
      SourceUrl: 'https://github.com/ionsec/flareinspect',
      Resources: [{
        Type: 'AwsAccount',
        Id: `cloudflare::account:${assessment.account?.id || 'unknown'}`,
        Partition: 'aws',
        Region: 'global',
        Details: { AwsAccount: { Name: assessment.account?.name || 'Unknown' } }
      }],
      RecordState: 'ACTIVE',
      Workflow: { Status: 'NEW' }
    }));
  }

  mapNormalizedSeverity(severity) {
    const map = { critical: 90, high: 70, medium: 40, low: 20, informational: 10 };
    return map[severity?.toLowerCase()] || 40;
  }

  mapSeverityScore(severity) {
    const map = { critical: 90, high: 70, medium: 40, low: 20, informational: 10 };
    return map[severity?.toLowerCase()] || 40;
  }
}

module.exports = ASFFExporter;
