/**
 * @fileoverview Cloudflare Assessment Report Service for FlareInspect
 * @description Generates comprehensive security assessment reports
 * @module core/services/reportService
 */

const logger = require('../utils/logger');
const pkg = require('../../../package.json');

class ReportService {
  constructor() {
    this.complianceFrameworks = {
      'SOC2': 'System and Organization Controls 2',
      'ISO27001': 'ISO/IEC 27001:2013',
      'PCI-DSS': 'Payment Card Industry Data Security Standard',
      'NIST': 'NIST Cybersecurity Framework',
      'CIS': 'Center for Internet Security Controls'
    };
  }

  /**
   * Generate comprehensive assessment report
   */
  generateReport(assessment) {
    logger.info('Generating comprehensive assessment report', {
      assessmentId: assessment.assessmentId,
      findingsCount: assessment.findings?.length || 0
    });

    const detailedFindings = this.buildDetailedFindings(assessment.findings || []);

    const report = {
      // Executive Summary
      executiveSummary: this.generateExecutiveSummary(assessment),
      
      // Account Overview
      accountOverview: this.generateAccountOverview(assessment),
      
      // Security Posture Summary
      securityPosture: this.generateSecurityPosture(assessment),
      
      // Security Findings
      securityFindings: this.generateSecurityFindings(assessment, detailedFindings),

      // Analysis
      analysis: this.generateAnalysis(assessment, detailedFindings),
      
      // Security Insights Details
      securityInsightsDetails: this.generateSecurityInsightsDetails(assessment),
      
      // Recommendations
      recommendations: this.generateRecommendations(assessment),
      
      // Metadata
      metadata: {
        assessmentId: assessment.assessmentId,
        timestamp: assessment.startedAt,
        duration: assessment.executionTime,
        toolVersion: pkg.version,
        vendor: 'IONSEC.IO'
      }
    };

    return report;
  }

  /**
   * Generate executive summary
   */
  generateExecutiveSummary(assessment) {
    const summary = assessment.summary || {};
    const score = assessment.score || {};
    
    const riskLevel = this.calculateRiskLevel(summary);

    return {
      assessmentDate: assessment.startedAt,
      accountName: assessment.account?.name || 'Unknown',
      overallScore: score.overallScore || 0,
      securityGrade: score.grade || 'F',
      riskLevel: riskLevel,
      
      keyFindings: {
        totalChecks: summary.totalChecks || 0,
        passedChecks: summary.passedChecks || 0,
        failedChecks: summary.failedChecks || 0,
        criticalIssues: summary.criticalFindings || 0,
        highRiskIssues: summary.highFindings || 0
      },
      
      topRisks: this.getTopRisks(assessment, 5)
    };
  }

  /**
   * Generate account overview
   */
  generateAccountOverview(assessment) {
    const account = assessment.account || {};
    const zones = assessment.zones || [];
    const config = assessment.configuration || {};

    return {
      accountDetails: {
        id: account.id,
        name: account.name,
        type: account.type,
        memberCount: config.account?.members || 0
      },
      
      subscriptionInfo: {
        plan: this.determinePrimaryPlan(zones),
        zonesCount: zones.length,
        activeZones: zones.filter(z => z.status === 'active').length,
        pendingZones: zones.filter(z => z.status === 'pending').length
      },
      
      domainPortfolio: {
        totalDomains: zones.length,
        domains: zones.map(zone => ({
          name: zone.name,
          status: zone.status,
          plan: zone.plan
        }))
      },
      
      securityInsights: this.generateSecurityInsightsOverview(config.securityInsights)
    };
  }

  /**
   * Generate security posture summary
   */
  generateSecurityPosture(assessment) {
    const summary = assessment.summary || {};
    const findings = assessment.findings || [];
    const categories = [...new Set(findings.map(f => f.service))].sort();
    const securityCategories = categories.reduce((acc, category) => {
      acc[category] = this.analyzeSecurityCategory(findings, category);
      return acc;
    }, {});

    return {
      overallPosture: {
        score: assessment.score?.overallScore || 0,
        grade: assessment.score?.grade || 'F'
      },
      
      securityCategories: securityCategories,
      
      riskDistribution: {
        critical: summary.criticalFindings || 0,
        high: summary.highFindings || 0,
        medium: summary.mediumFindings || 0,
        low: summary.lowFindings || 0,
        informational: summary.informationalFindings || 0
      }
    };
  }

  /**
   * Generate security findings section
   */
  generateSecurityFindings(assessment, detailedFindings = this.buildDetailedFindings(assessment.findings || [])) {
    const findings = assessment.findings || [];
    const categories = [...new Set(findings.map(f => f.service))].sort();
    const findingsByCategory = categories.reduce((acc, category) => {
      acc[category] = detailedFindings.filter(f => f.service === category);
      return acc;
    }, {});
    const findingsBySeverity = {
      critical: detailedFindings.filter(f => f.severity === 'critical'),
      high: detailedFindings.filter(f => f.severity === 'high'),
      medium: detailedFindings.filter(f => f.severity === 'medium'),
      low: detailedFindings.filter(f => f.severity === 'low'),
      informational: detailedFindings.filter(f => f.severity === 'informational')
    };
    
    return {
      criticalFindings: findingsBySeverity.critical,
      highRiskFindings: findingsBySeverity.high,
      mediumRiskFindings: findingsBySeverity.medium,
      lowRiskFindings: findingsBySeverity.low,
      informationalFindings: findingsBySeverity.informational,
      
      findingsByCategory: findingsByCategory,
      findingsBySeverity,
      detailedFindings,
      
      remediationPriority: this.prioritizeRemediation(findings)
    };
  }

  /**
   * Generate recommendations section
   */
  generateRecommendations(assessment) {
    const findings = assessment.findings || [];
    
    return {
      immediate: this.getImmediateRecommendations(findings),
      shortTerm: this.getShortTermRecommendations(findings),
      longTerm: this.getLongTermRecommendations(findings),
      
      implementationRoadmap: this.createImplementationRoadmap(findings)
    };
  }

  /**
   * Generate Security Insights details section
   */
  generateSecurityInsightsDetails(assessment) {
    const insightsData = assessment.configuration?.securityInsights;
    const insightsFindings = assessment.findings?.filter(f => f.service === 'security-insights') || [];
    
    if (!insightsData || (!insightsData.account && !insightsData.zones)) {
      return {
        available: false,
        message: 'Security Center Insights not available or not accessible'
      };
    }

    // Collect all insights
    const allInsights = [];
    
    // Account insights
    if (insightsData.account?.insights) {
      insightsData.account.insights.forEach(insight => {
        allInsights.push({
          ...insight,
          scope: 'account',
          resourceId: assessment.account?.id
        });
      });
    }
    
    // Zone insights
    if (insightsData.zones) {
      Object.entries(insightsData.zones).forEach(([zoneName, zoneData]) => {
        if (zoneData.insights) {
          zoneData.insights.forEach(insight => {
            allInsights.push({
              ...insight,
              scope: 'zone',
              resourceId: zoneName
            });
          });
        }
      });
    }

    // Group insights by type
    const insightsByType = {};
    allInsights.forEach(insight => {
      const type = insight.issue_type || 'unknown';
      if (!insightsByType[type]) {
        insightsByType[type] = [];
      }
      insightsByType[type].push(insight);
    });

    return {
      available: true,
      summary: {
        totalInsights: allInsights.length,
        accountInsights: insightsData.account?.insights?.length || 0,
        zoneInsights: allInsights.filter(i => i.scope === 'zone').length,
        criticalInsights: allInsights.filter(i => i.severity === 'Critical').length,
        highInsights: allInsights.filter(i => i.severity === 'High').length
      },
      insights: allInsights,
      byType: insightsByType,
      findings: insightsFindings,
      recommendations: this.generateInsightsRecommendations(allInsights)
    };
  }

  generateAnalysis(assessment, detailedFindings = this.buildDetailedFindings(assessment.findings || [])) {
    return {
      identityAccess: this.generateFocusedAnalysis(
        detailedFindings,
        ['account', 'zero-trust'],
        'Identity and access controls show the highest leverage fixes around MFA coverage, named administrators, and auditability.'
      ),
      zoneExposure: this.generateFocusedAnalysis(
        detailedFindings,
        ['dns', 'security-insights'],
        'Zone exposure analysis focuses on origin exposure, wildcard DNS, and other records that broaden public attack surface.'
      ),
      transportTls: this.generateFocusedAnalysis(
        detailedFindings,
        ['ssl', 'mtls', 'custom-hostnames', 'origin-certificates'],
        'Transport analysis highlights weak TLS, missing HSTS, certificate hygiene, and encryption posture gaps.'
      ),
      trafficProtection: this.generateFocusedAnalysis(
        detailedFindings,
        ['waf', 'api', 'bot', 'gateway'],
        'Traffic protection analysis highlights missing WAF, rate limiting, managed rulesets, and API-layer guardrails.'
      ),
      loggingForensics: this.generateFocusedAnalysis(
        detailedFindings,
        ['logpush', 'account', 'security-insights'],
        'Logging and forensics readiness depend on retained audit trails and telemetry export for critical security actions.'
      ),
      reviewerSummary: this.generateReviewerSummary(assessment, detailedFindings)
    };
  }

  /**
   * Generate recommendations based on Security Insights
   */
  generateInsightsRecommendations(insights) {
    const recommendations = [];
    
    // Check for critical insights
    const criticalInsights = insights.filter(i => i.severity === 'Critical');
    if (criticalInsights.length > 0) {
      recommendations.push({
        priority: 'immediate',
        title: 'Address Critical Security Insights',
        description: `${criticalInsights.length} critical security issues detected by Cloudflare Security Center require immediate attention.`,
        actions: criticalInsights.map(i => i.resolve_text || `Address ${i.issue_type}: ${i.subject}`)
      });
    }
    
    // Check for exposed credentials
    const exposedCreds = insights.filter(i => i.issue_type === 'exposed_credentials');
    if (exposedCreds.length > 0) {
      recommendations.push({
        priority: 'immediate',
        title: 'Rotate Exposed Credentials',
        description: 'Exposed credentials have been detected and must be rotated immediately.',
        actions: [
          'Immediately rotate all exposed credentials',
          'Review access logs for unauthorized access',
          'Implement credential scanning in CI/CD pipeline',
          'Enable alerts for credential exposure'
        ]
      });
    }
    
    // Check for origin exposure
    const originExposure = insights.filter(i => i.issue_type === 'dns_record_exposing_origin');
    if (originExposure.length > 0) {
      recommendations.push({
        priority: 'high',
        title: 'Hide Origin IP Addresses',
        description: 'Origin server IP addresses are exposed through DNS records.',
        actions: [
          'Enable Cloudflare proxy (orange cloud) for exposed records',
          'Review all DNS records for proxy status',
          'Implement firewall rules to only allow Cloudflare IPs',
          'Consider using Cloudflare Tunnel for origin protection'
        ]
      });
    }
    
    return recommendations;
  }

  /**
   * Generate Security Insights overview
   */
  generateSecurityInsightsOverview(insightsData) {
    if (!insightsData) {
      return {
        enabled: false,
        message: 'Security Insights data not available'
      };
    }

    const accountInsights = insightsData.account || {};
    const zoneInsights = insightsData.zones || {};
    
    // Aggregate all insights
    let totalInsights = 0;
    let totalCritical = 0;
    let totalHigh = 0;
    let totalModerate = 0;
    let totalLow = 0;
    
    // Account insights
    if (accountInsights.insights) {
      totalInsights += accountInsights.insights.length;
      if (accountInsights.summary) {
        totalCritical += accountInsights.summary.bySeverity.critical || 0;
        totalHigh += accountInsights.summary.bySeverity.high || 0;
        totalModerate += accountInsights.summary.bySeverity.moderate || 0;
        totalLow += accountInsights.summary.bySeverity.low || 0;
      }
    }
    
    // Zone insights
    Object.values(zoneInsights).forEach(zoneData => {
      if (zoneData.insights) {
        totalInsights += zoneData.insights.length;
        if (zoneData.summary) {
          totalCritical += zoneData.summary.bySeverity.critical || 0;
          totalHigh += zoneData.summary.bySeverity.high || 0;
          totalModerate += zoneData.summary.bySeverity.moderate || 0;
          totalLow += zoneData.summary.bySeverity.low || 0;
        }
      }
    });

    return {
      enabled: true,
      summary: {
        totalActiveInsights: totalInsights,
        bySeverity: {
          critical: totalCritical,
          high: totalHigh,
          moderate: totalModerate,
          low: totalLow
        }
      },
      accountLevel: {
        insightsCount: accountInsights.insights?.length || 0,
        hasError: !!accountInsights.error
      },
      zoneLevel: {
        zonesWithInsights: Object.keys(zoneInsights).filter(zone => 
          zoneInsights[zone].insights && zoneInsights[zone].insights.length > 0
        ).length,
        totalZones: Object.keys(zoneInsights).length
      }
    };
  }

  // Helper methods

  calculateRiskLevel(summary) {
    const critical = summary.criticalFindings || 0;
    const high = summary.highFindings || 0;
    
    if (critical > 0) return 'Critical';
    if (high > 3) return 'High';
    if (high > 0) return 'Medium';
    return 'Low';
  }

  getTopRisks(assessment, limit = 5) {
    const findings = this.buildDetailedFindings(assessment.findings || []);
    
    const severityWeight = {
      'critical': 10,
      'high': 7,
      'medium': 4,
      'low': 2,
      'informational': 1
    };
    
    return findings
      .filter(f => f.status === 'FAIL')
      .sort((a, b) => (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0))
      .slice(0, limit)
      .map(finding => ({
        title: finding.checkTitle,
        severity: finding.severity,
        service: finding.service,
        description: finding.description,
        remediation: finding.remediation,
        resource: finding.resourceName || finding.resourceId,
        evidenceSummary: finding.evidence?.summary,
        observed: finding.evidence?.observed,
        affectedEntities: finding.evidence?.affectedEntities || []
      }));
  }

  determinePrimaryPlan(zones) {
    const planCounts = {};
    zones.forEach(zone => {
      const plan = zone.plan || 'Free';
      planCounts[plan] = (planCounts[plan] || 0) + 1;
    });
    
    return Object.keys(planCounts).reduce((a, b) => 
      planCounts[a] > planCounts[b] ? a : b, 'Free'
    );
  }

  analyzeSecurityCategory(findings, category) {
    const categoryFindings = findings.filter(f => f.service === category);
    const passed = categoryFindings.filter(f => f.status === 'PASS').length;
    const failed = categoryFindings.filter(f => f.status === 'FAIL').length;
    const total = categoryFindings.length;
    
    return {
      score: total > 0 ? Math.round((passed / total) * 100) : 0,
      status: this.getSecurityStatus(passed, failed, total),
      findings: categoryFindings.length,
      criticalIssues: categoryFindings.filter(f => f.severity === 'critical').length
    };
  }

  getSecurityStatus(passed, failed, total) {
    if (total === 0) return 'not-assessed';
    const passRate = passed / total;
    if (passRate >= 0.9) return 'excellent';
    if (passRate >= 0.7) return 'good';
    if (passRate >= 0.5) return 'fair';
    return 'poor';
  }

  prioritizeRemediation(findings) {
    const failed = findings.filter(f => f.status === 'FAIL');
    const severityOrder = ['critical', 'high', 'medium', 'low'];
    
    return failed.sort((a, b) => {
      const aIndex = severityOrder.indexOf(a.severity);
      const bIndex = severityOrder.indexOf(b.severity);
      return aIndex - bIndex;
    });
  }

  formatRemediationAction(remediation) {
    if (!remediation) {
      return 'No remediation information available';
    }
    
    if (typeof remediation === 'string') {
      return remediation;
    }
    
    if (remediation.steps && Array.isArray(remediation.steps)) {
      return remediation.steps.join(' ');
    }
    
    if (remediation.recommendation) {
      return remediation.recommendation;
    }
    
    return JSON.stringify(remediation);
  }

  getImmediateRecommendations(findings) {
    return findings
      .filter(f => f.severity === 'critical' && f.status === 'FAIL')
      .map(f => ({
        title: f.checkTitle,
        action: this.formatRemediationAction(f.remediation),
        timeline: 'Immediate (0-24 hours)',
        effort: 'low'
      }));
  }

  getShortTermRecommendations(findings) {
    return findings
      .filter(f => f.severity === 'high' && f.status === 'FAIL')
      .map(f => ({
        title: f.checkTitle,
        action: this.formatRemediationAction(f.remediation),
        timeline: 'Short-term (1-30 days)',
        effort: 'medium'
      }));
  }

  getLongTermRecommendations(findings) {
    return findings
      .filter(f => f.severity === 'medium' && f.status === 'FAIL')
      .map(f => ({
        title: f.checkTitle,
        action: this.formatRemediationAction(f.remediation),
        timeline: 'Long-term (1-6 months)',
        effort: 'high'
      }));
  }

  createImplementationRoadmap(findings) {
    return {
      phase1: 'Critical and High severity issues (0-30 days)',
      phase2: 'Medium severity issues and quick wins (30-90 days)',
      phase3: 'Long-term improvements and optimization (90+ days)'
    };
  }

  buildDetailedFindings(findings) {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];

    return findings
      .map(finding => this.normalizeFindingForReport(finding))
      .sort((a, b) => {
        const severityDelta = severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
        if (severityDelta !== 0) return severityDelta;
        if (a.status !== b.status) return a.status === 'FAIL' ? -1 : 1;
        return a.checkTitle.localeCompare(b.checkTitle);
      });
  }

  normalizeFindingForReport(finding) {
    const evidence = this.normalizeEvidence(finding.evidence, finding);

    return {
      ...finding,
      resourceName: finding.metadata?.resourceName || finding.resourceId,
      evidence,
      reviewSummary: this.buildReviewSummary(finding, evidence),
      analysis: this.buildFindingAnalysis(finding, evidence)
    };
  }

  normalizeEvidence(evidence, finding) {
    return {
      summary: evidence?.summary || finding.description,
      expected: evidence?.expected ?? finding.metadata?.expectedValue ?? null,
      observed: evidence?.observed ?? finding.metadata?.actualValue ?? null,
      affectedEntities: Array.isArray(evidence?.affectedEntities) ? evidence.affectedEntities : [],
      counts: evidence?.counts && typeof evidence.counts === 'object' ? evidence.counts : {},
      source: evidence?.source && typeof evidence.source === 'object' ? evidence.source : {},
      raw: evidence?.raw && typeof evidence.raw === 'object' ? evidence.raw : {},
      reviewGuidance: evidence?.reviewGuidance || 'Review the observed state and validate that the affected identities/resources are expected.'
    };
  }

  buildReviewSummary(finding, evidence) {
    const entityCount = evidence.affectedEntities.length;
    const countText = entityCount > 0 ? `${entityCount} named item(s) affected.` : 'No named affected entities were returned.';
    return `${evidence.summary} ${countText} ${evidence.reviewGuidance}`.trim();
  }

  buildFindingAnalysis(finding, evidence) {
    const parts = [];

    if (finding.status === 'FAIL' || finding.status === 'WARNING') {
      parts.push(`Observed state: ${String(evidence.observed ?? 'unknown')}.`);
      if (evidence.expected) {
        parts.push(`Expected state: ${String(evidence.expected)}.`);
      }
      if (evidence.affectedEntities.length > 0) {
        parts.push(`Affected objects: ${evidence.affectedEntities.slice(0, 5).map(entity => entity.name || entity.email || entity.id || entity.resource || 'unknown').join(', ')}.`);
      }
    } else {
      parts.push(`Control validated with observed state: ${String(evidence.observed ?? 'compliant')}.`);
    }

    return parts.join(' ');
  }

  generateFocusedAnalysis(findings, services, defaultNarrative) {
    const relevantFindings = findings.filter(f => services.includes(f.service));
    const failingFindings = relevantFindings.filter(f => ['FAIL', 'WARNING'].includes(f.status));

    return {
      summary: failingFindings.length > 0
        ? `${defaultNarrative} ${failingFindings.length} finding(s) require review in this area.`
        : `No failing findings were recorded in this area. ${defaultNarrative}`,
      failingFindings: failingFindings.slice(0, 10),
      topAffectedEntities: this.collectTopAffectedEntities(failingFindings),
      quickWins: failingFindings.slice(0, 3).map(f => ({
        title: f.checkTitle,
        action: this.formatRemediationAction(f.remediation),
        reviewGuidance: f.evidence.reviewGuidance
      }))
    };
  }

  collectTopAffectedEntities(findings) {
    return findings
      .flatMap(f => f.evidence.affectedEntities || [])
      .slice(0, 10);
  }

  generateReviewerSummary(assessment, findings) {
    const failingFindings = findings.filter(f => ['FAIL', 'WARNING'].includes(f.status));
    const topFixes = failingFindings.slice(0, 5).map(f => ({
      title: f.checkTitle,
      service: f.service,
      resource: f.resourceName || f.resourceId,
      observed: f.evidence.observed,
      reviewGuidance: f.evidence.reviewGuidance
    }));

    return {
      accountName: assessment.account?.name || 'Unknown',
      totalFailingFindings: failingFindings.length,
      namedAffectedEntities: this.collectTopAffectedEntities(failingFindings),
      topFixes
    };
  }
}

module.exports = ReportService;
