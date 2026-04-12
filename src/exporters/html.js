/**
 * @fileoverview HTML Exporter
 * @description Exports assessment results to HTML format
 * @module exporters/html
 */

const Handlebars = require('handlebars');
const fs = require('fs').promises;
const path = require('path');
const dayjs = require('dayjs');
const logger = require('../core/utils/logger');
const pkg = require('../../package.json');

function safeJsonStringify(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

class HTMLExporter {
  constructor() {
    this.registerHelpers();
  }

  /**
   * Register Handlebars helpers
   */
  registerHelpers() {
    // Format date helper
    Handlebars.registerHelper('formatDate', (date) => {
      return dayjs(date).format('MMMM DD, YYYY HH:mm');
    });

    // Lowercase helper
    Handlebars.registerHelper('lowercase', (str) => {
      return str ? str.toLowerCase() : '';
    });

    // Status class helper
    Handlebars.registerHelper('statusClass', (status) => {
      const statusMap = {
        'active': 'pass',
        'pending': 'warning',
        'inactive': 'fail',
        'excellent': 'pass',
        'good': 'pass',
        'fair': 'warning',
        'poor': 'fail'
      };
      const statusStr = String(status || 'warning').toLowerCase();
      return statusMap[statusStr] || 'warning';
    });

    // Risk level class helper
    Handlebars.registerHelper('riskLevelClass', (level) => {
      const levelMap = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low'
      };
      const levelStr = String(level || 'medium').toLowerCase();
      return levelMap[levelStr] || 'medium';
    });

    // JSON stringify helper
    Handlebars.registerHelper('json', (context) => {
      return safeJsonStringify(context);
    });
  }

  /**
   * Export assessment to HTML format
   */
  async export(assessment) {
    logger.info('Exporting assessment to HTML format');
    
    try {
      // Load template
      const templatePath = path.join(__dirname, '../../templates/report.html');
      const templateContent = await fs.readFile(templatePath, 'utf8');
      const template = Handlebars.compile(templateContent);
      
      // Prepare data
      const data = this.prepareData(assessment);
      
      // Generate HTML
      const html = template(data);
      
      return html;
    } catch (error) {
      logger.error('HTML export failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Prepare data for template
   */
  prepareData(assessment) {
    const report = assessment.report || {};
    const summary = report.executiveSummary || {};
    const overview = report.accountOverview || {};
    const posture = report.securityPosture || {};
    const findings = report.securityFindings || {};
    const recommendations = report.recommendations || {};
    const insightsDetails = report.securityInsightsDetails || {};
    const analysis = report.analysis || {};

    // Calculate score circle values
    const score = assessment.score?.overallScore || 0;
    const circumference = 2 * Math.PI * 54; // radius = 54
    const scoreOffset = circumference - (score / 100) * circumference;

    // Prepare category data for chart
    const categories = posture.securityCategories || {};
    const categoryLabels = Object.keys(categories).map(cat => this.capitalizeFirst(cat));
    const categoryData = Object.values(categories).map(cat => cat.findings || 0);

    // Count findings by severity
    const countBySeverity = this.countFindingsBySeverity(assessment.findings || []);

    return {
      // Basic info
      assessmentId: assessment.assessmentId,
      accountName: summary.accountName || 'Unknown',
      assessmentDate: dayjs(summary.assessmentDate).format('MMMM DD, YYYY'),
      generatedAt: dayjs().format('MMMM DD, YYYY HH:mm'),
      
      // Scores and grades
      overallScore: score,
      securityGrade: summary.securityGrade || 'F',
      complianceScore: assessment.summary?.complianceScore || 0,
      scoreCircumference: circumference,
      scoreOffset: scoreOffset,
      
      // Risk and findings
      riskLevel: summary.riskLevel || 'High',
      riskLevelClass: (summary.riskLevel || 'high').toLowerCase(),
      totalChecks: summary.keyFindings?.totalChecks || 0,
      passedChecks: summary.keyFindings?.passedChecks || 0,
      failedChecks: summary.keyFindings?.failedChecks || 0,
      criticalFindingsCount: countBySeverity.critical || 0,
      highFindingsCount: countBySeverity.high || summary.keyFindings?.highRiskIssues || 0,
      mediumFindingsCount: countBySeverity.medium || 0,
      lowFindingsCount: countBySeverity.low || 0,
      
      // Counts for charts
      criticalCount: countBySeverity.critical,
      highCount: countBySeverity.high,
      mediumCount: countBySeverity.medium,
      lowCount: countBySeverity.low,
      informationalCount: countBySeverity.informational,
      riskChartData: [
        countBySeverity.critical,
        countBySeverity.high,
        countBySeverity.medium,
        countBySeverity.low,
        countBySeverity.informational
      ],
      riskChartLabels: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
      
      // Category chart data
      categoryLabels: categoryLabels,
      categoryData: categoryData,
      appVersion: pkg.version,
      
      // Top risks
      topRisks: summary.topRisks || [],
      
      // Domains
      domains: this.prepareDomains(overview.domainPortfolio?.domains || [], categories, assessment.findings || []),
      zonesCount: overview.domainPortfolio?.totalDomains || 0,
      
      // Findings arrays filtered by status - only show failures
      criticalFindings: (findings.criticalFindings || []).filter(f => f.status === 'FAIL'),
      highRiskFindings: (findings.highRiskFindings || []).filter(f => f.status === 'FAIL'),
      detailedFindings: this.prepareDetailedFindings(findings.detailedFindings || []),
      
      // Recommendations
      immediateActions: recommendations.immediate || [],
      shortTermActions: recommendations.shortTerm || [],
      longTermActions: recommendations.longTerm || [],
      
      // Security categories
      securityCategories: this.prepareSecurityCategories(categories),
      
      // Security Insights
      hasSecurityInsights: insightsDetails.available && insightsDetails.insights?.length > 0,
      securityInsights: this.prepareSecurityInsights(insightsDetails),
      securityInsightsSummary: overview.securityInsights || {},
      insightsBySeverity: this.prepareInsightsBySeverity(insightsDetails.insights || []),

      // Narrative analysis
      analysisSections: this.prepareAnalysisSections(analysis)
    };
  }

  /**
   * Count findings by severity
   */
  countFindingsBySeverity(findings) {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0
    };
    
    findings.forEach(finding => {
      const severity = finding.severity?.toLowerCase() || 'informational';
      if (counts.hasOwnProperty(severity)) {
        counts[severity]++;
      }
    });
    
    return counts;
  }

  /**
   * Prepare domains data
   */
  /**
   * Calculate actual score for a domain from its findings
   */
  calculateDomainScore(domainName, findings) {
    const weights = { critical: 10, high: 7, medium: 4, low: 2, informational: 1 };
    const domainFindings = findings.filter(f => f.resourceId === domainName || f.resourceId?.endsWith(domainName));
    if (domainFindings.length === 0) return 100;
    let totalWeight = 0;
    let passedWeight = 0;
    domainFindings.forEach(f => {
      const w = weights[f.severity] || 1;
      totalWeight += w;
      if (f.status === 'PASS') passedWeight += w;
    });
    return totalWeight > 0 ? Math.round((passedWeight / totalWeight) * 100) : 0;
  }

  prepareDomains(domains, categories, findings) {
    return domains.map(domain => ({
      name: domain.name,
      status: domain.status,
      statusClass: domain.status === 'active' ? 'pass' : 'warning',
      plan: domain.plan || 'Free',
      score: this.calculateDomainScore(domain.name, findings || [])
    }));
  }

  /**
   * Prepare security categories for display
   */
  prepareSecurityCategories(categories) {
    return Object.entries(categories).map(([name, data]) => ({
      name: this.capitalizeFirst(name),
      score: data.score || 0,
      status: this.capitalizeFirst(data.status || 'unknown'),
      statusClass: data.status || 'unknown',
      findings: data.findings || 0,
      criticalIssues: data.criticalIssues || 0
    }));
  }

  prepareDetailedFindings(findings) {
    return findings
      .filter(finding => ['FAIL', 'WARNING'].includes(finding.status))
      .map(finding => ({
        ...finding,
        severityClass: (finding.severity || 'informational').toLowerCase(),
        resourceDisplay: finding.resourceName || finding.metadata?.resourceName || finding.resourceId || 'N/A',
        evidenceSummary: finding.evidence?.summary || finding.description,
        observed: finding.evidence?.observed ?? 'Unknown',
        expected: finding.evidence?.expected ?? 'Not specified',
        reviewGuidance: finding.evidence?.reviewGuidance || 'Review the affected resources and validate the expected state.',
        counts: this.formatKeyValuePairs(finding.evidence?.counts),
        sourceDetails: this.formatKeyValuePairs(finding.evidence?.source),
        affectedEntities: this.prepareAffectedEntities(finding.evidence?.affectedEntities || [])
      }));
  }

  prepareAffectedEntities(entities) {
    return entities.map(entity => ({
      primary: entity.name || entity.email || entity.id || entity.resource || 'Unknown',
      secondary: [entity.email, entity.type, entity.action, entity.resource]
        .filter(Boolean)
        .join(' | '),
      detail: this.formatKeyValuePairs(entity)
    }));
  }

  prepareAnalysisSections(analysis) {
    const sectionLabels = {
      identityAccess: 'Identity and Access Analysis',
      zoneExposure: 'Zone Exposure Analysis',
      transportTls: 'Transport and TLS Analysis',
      trafficProtection: 'Traffic Protection Analysis',
      loggingForensics: 'Logging and Forensics Analysis'
    };

    return Object.entries(sectionLabels)
      .filter(([key]) => analysis[key])
      .map(([key, label]) => ({
        title: label,
        summary: analysis[key].summary,
        quickWins: analysis[key].quickWins || [],
        affectedEntities: this.prepareAffectedEntities(analysis[key].topAffectedEntities || [])
      }));
  }

  formatKeyValuePairs(value) {
    if (!value || typeof value !== 'object') {
      return [];
    }

    return Object.entries(value).map(([key, entryValue]) => ({
      key: this.capitalizeFirst(String(key).replace(/_/g, ' ')),
      value: Array.isArray(entryValue) ? entryValue.join(', ') : String(entryValue)
    }));
  }

  /**
   * Capitalize first letter
   */
  capitalizeFirst(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  /**
   * Prepare Security Insights for display
   */
  prepareSecurityInsights(insightsDetails) {
    if (!insightsDetails.available || !insightsDetails.insights) {
      return null;
    }

    return {
      available: true,
      totalCount: insightsDetails.summary?.totalInsights || 0,
      criticalCount: insightsDetails.summary?.criticalInsights || 0,
      highCount: insightsDetails.summary?.highInsights || 0,
      accountInsightsCount: insightsDetails.summary?.accountInsights || 0,
      zoneInsightsCount: insightsDetails.summary?.zoneInsights || 0,
      insights: insightsDetails.insights.map(insight => ({
        id: insight.id,
        severity: insight.severity,
        severityClass: (insight.severity || 'moderate').toLowerCase(),
        issueType: this.formatIssueType(insight.issue_type),
        subject: insight.subject || 'Unknown',
        description: insight.subject || insight.issue_type || 'Security issue detected',
        scope: insight.scope === 'account' ? 'Account' : `Zone: ${insight.resourceId}`,
        since: insight.since ? dayjs(insight.since).format('MMM DD, YYYY') : 'Unknown',
        resolveText: insight.resolve_text || 'Follow Cloudflare recommendations',
        resolveLink: insight.resolve_link
      })),
      recommendations: insightsDetails.recommendations || []
    };
  }

  /**
   * Format issue type for display
   */
  formatIssueType(issueType) {
    if (!issueType) return 'Unknown Issue';
    
    const typeMap = {
      'exposed_credentials': 'Exposed Credentials',
      'ssl_certificate_expiring': 'SSL Certificate Expiring',
      'dns_record_exposing_origin': 'Origin IP Exposed',
      'insecure_ssl_tls': 'Insecure SSL/TLS',
      'missing_security_headers': 'Missing Security Headers',
      'vulnerable_software': 'Vulnerable Software'
    };
    
    return typeMap[issueType] || issueType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  /**
   * Prepare insights by severity for charts
   */
  prepareInsightsBySeverity(insights) {
    const bySeverity = {
      Critical: [],
      High: [],
      Moderate: [],
      Low: []
    };

    insights.forEach(insight => {
      const severity = insight.severity || 'Moderate';
      if (bySeverity[severity]) {
        bySeverity[severity].push(insight);
      }
    });

    return bySeverity;
  }
}

module.exports = HTMLExporter;
