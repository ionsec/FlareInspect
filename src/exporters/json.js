/**
 * @fileoverview JSON Exporter
 * @description Exports assessment results to JSON format with OCSF support
 * @module exporters/json
 */

const { toOCSF, convertFindingsToOCSF } = require('../core/utils/ocsf');
const logger = require('../core/utils/logger');

class JSONExporter {
  /**
   * Export assessment to standard JSON format
   */
  async export(assessment) {
    logger.info('Exporting assessment to JSON format');
    
    return {
      metadata: {
        exportedAt: new Date().toISOString(),
        exportFormat: 'flareinspect-json',
        version: '1.0.0',
        vendor: 'IONSEC.IO'
      },
      assessment: {
        id: assessment.assessmentId,
        status: assessment.status,
        startedAt: assessment.startedAt,
        completedAt: assessment.completedAt,
        duration: assessment.executionTime,
        provider: assessment.provider
      },
      account: assessment.account,
      zones: assessment.zones,
      score: assessment.score,
      summary: assessment.summary,
      findings: assessment.findings,
      report: assessment.report,
      configuration: assessment.configuration
    };
  }

  /**
   * Export assessment to OCSF-compliant JSON format
   */
  async exportOCSF(assessment) {
    logger.info('Exporting assessment to OCSF-compliant JSON format');
    
    // Convert findings to OCSF format
    const ocsfFindings = convertFindingsToOCSF(assessment.findings || []);
    
    // Build OCSF-compliant document
    const ocsfDocument = {
      metadata: {
        version: '1.1.0',
        extension: {
          name: 'cloudflare',
          version: '1.0.0'
        },
        product: {
          name: 'FlareInspect',
          vendor_name: 'IONSEC.IO',
          version: '1.0.0',
          lang: 'en'
        },
        profiles: ['cloud', 'security_control'],
        log_name: 'cloudflare_security_assessment',
        log_provider: 'flareinspect',
        logged_time: Math.floor(Date.now() / 1000),
        original_time: assessment.startedAt ? Math.floor(new Date(assessment.startedAt).getTime() / 1000) : Math.floor(Date.now() / 1000),
        processed_time: Math.floor(Date.now() / 1000),
        event_count: ocsfFindings.length
      },
      
      // OCSF Cloud Resource
      cloud: {
        provider: 'Cloudflare',
        account: {
          uid: assessment.account?.id || 'unknown',
          name: assessment.account?.name || 'Unknown Account',
          type: assessment.account?.type || 'standard'
        },
        region: 'global',
        zone: assessment.zones?.map(z => ({
          uid: z.id,
          name: z.name,
          type: 'dns_zone'
        })) || []
      },
      
      // Assessment metadata
      assessment_info: {
        uid: assessment.assessmentId,
        type: 'security_assessment',
        start_time: assessment.startedAt ? Math.floor(new Date(assessment.startedAt).getTime() / 1000) : null,
        end_time: assessment.completedAt ? Math.floor(new Date(assessment.completedAt).getTime() / 1000) : null,
        duration: assessment.executionTime,
        status: assessment.status,
        status_id: assessment.status === 'completed' ? 1 : 2,
        status_code: assessment.status === 'completed' ? '200' : '500',
        status_detail: assessment.status === 'completed' ? 'Assessment completed successfully' : 'Assessment failed'
      },
      
      // Summary statistics
      statistics: {
        total_findings: assessment.summary?.totalChecks || 0,
        passed_checks: assessment.summary?.passedChecks || 0,
        failed_checks: assessment.summary?.failedChecks || 0,
        critical_findings: assessment.summary?.criticalFindings || 0,
        high_findings: assessment.summary?.highFindings || 0,
        medium_findings: assessment.summary?.mediumFindings || 0,
        low_findings: assessment.summary?.lowFindings || 0,
        informational_findings: assessment.summary?.informationalFindings || 0,
        compliance_score: assessment.summary?.complianceScore || 0,
        security_score: assessment.score?.overallScore || 0,
        security_grade: assessment.score?.grade || 'F',
        security_insights: this.extractSecurityInsightsStats(assessment)
      },
      
      // Compliance mapping
      compliance: {
        frameworks: ['SOC2', 'ISO27001', 'PCI-DSS', 'NIST', 'CIS'],
        status: 'partial',
        requirements: this.mapComplianceRequirements(assessment.findings || [])
      },
      
      // OCSF findings
      findings: ocsfFindings,
      
      // Observables (unique resources)
      observables: this.extractObservables(assessment),
      
      // Raw data reference
      raw_data: {
        configuration: assessment.configuration,
        zones_assessed: assessment.zones?.length || 0,
        api_calls_made: assessment.metadata?.totalApiCalls || 0
      }
    };
    
    return ocsfDocument;
  }

  /**
   * Map compliance requirements from findings
   */
  mapComplianceRequirements(findings) {
    const requirements = {};
    
    findings.forEach(finding => {
      if (finding.compliance && Array.isArray(finding.compliance)) {
        finding.compliance.forEach(framework => {
          if (!requirements[framework]) {
            requirements[framework] = {
              total: 0,
              passed: 0,
              failed: 0
            };
          }
          
          requirements[framework].total++;
          if (finding.status === 'PASS') {
            requirements[framework].passed++;
          } else {
            requirements[framework].failed++;
          }
        });
      }
    });
    
    return requirements;
  }

  /**
   * Extract Security Insights statistics
   */
  extractSecurityInsightsStats(assessment) {
    const insightsData = assessment.configuration?.securityInsights;
    if (!insightsData) {
      return {
        total_insights: 0,
        critical_insights: 0,
        high_insights: 0,
        moderate_insights: 0,
        low_insights: 0
      };
    }

    let total = 0;
    let critical = 0;
    let high = 0;
    let moderate = 0;
    let low = 0;

    // Account insights
    if (insightsData.account?.summary) {
      const s = insightsData.account.summary;
      total += s.total || 0;
      critical += s.bySeverity?.critical || 0;
      high += s.bySeverity?.high || 0;
      moderate += s.bySeverity?.moderate || 0;
      low += s.bySeverity?.low || 0;
    }

    // Zone insights
    if (insightsData.zones) {
      Object.values(insightsData.zones).forEach(zoneData => {
        if (zoneData.summary) {
          const s = zoneData.summary;
          total += s.total || 0;
          critical += s.bySeverity?.critical || 0;
          high += s.bySeverity?.high || 0;
          moderate += s.bySeverity?.moderate || 0;
          low += s.bySeverity?.low || 0;
        }
      });
    }

    return {
      total_insights: total,
      critical_insights: critical,
      high_insights: high,
      moderate_insights: moderate,
      low_insights: low
    };
  }

  /**
   * Extract unique observables from assessment
   */
  extractObservables(assessment) {
    const observables = [];
    const seen = new Set();
    
    // Add zones as observables
    assessment.zones?.forEach(zone => {
      const key = `zone:${zone.id}`;
      if (!seen.has(key)) {
        seen.add(key);
        observables.push({
          name: zone.name,
          type: 'domain_name',
          type_id: 2,
          value: zone.name,
          reputation: {
            score: zone.status === 'active' ? 100 : 50,
            score_id: zone.status === 'active' ? 1 : 3
          }
        });
      }
    });
    
    // Add account as observable
    if (assessment.account?.id) {
      observables.push({
        name: assessment.account.name,
        type: 'cloud_account',
        type_id: 90,
        value: assessment.account.id
      });
    }
    
    // Add Security Insights subjects as observables
    const insightsData = assessment.configuration?.securityInsights;
    if (insightsData) {
      // Account insights
      if (insightsData.account?.insights) {
        insightsData.account.insights.forEach(insight => {
          if (insight.subject) {
            const key = `insight:${insight.id}`;
            if (!seen.has(key)) {
              seen.add(key);
              observables.push({
                name: insight.subject,
                type: 'security_insight',
                type_id: 99,
                value: insight.subject,
                metadata: {
                  severity: insight.severity,
                  issue_type: insight.issue_type,
                  issue_class: insight.issue_class
                }
              });
            }
          }
        });
      }
      
      // Zone insights
      if (insightsData.zones) {
        Object.values(insightsData.zones).forEach(zoneData => {
          if (zoneData.insights) {
            zoneData.insights.forEach(insight => {
              if (insight.subject) {
                const key = `insight:${insight.id}`;
                if (!seen.has(key)) {
                  seen.add(key);
                  observables.push({
                    name: insight.subject,
                    type: 'security_insight',
                    type_id: 99,
                    value: insight.subject,
                    metadata: {
                      severity: insight.severity,
                      issue_type: insight.issue_type,
                      issue_class: insight.issue_class
                    }
                  });
                }
              }
            });
          }
        });
      }
    }
    
    return observables;
  }
}

module.exports = JSONExporter;