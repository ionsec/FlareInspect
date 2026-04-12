/**
 * @fileoverview Contextual Risk Scoring for FlareInspect
 * @description CVSS-style scoring with contextual weighting by zone plan, exposure, and sensitivity
 * @module core/services/contextualScoring
 */

const logger = require('../utils/logger');

class ContextualScoring {
  constructor() {
    this.severityBaseScores = {
      critical: 9.0,
      high: 7.5,
      medium: 5.0,
      low: 3.0,
      informational: 1.0
    };

    this.planMultipliers = {
      'Free': 1.3,        // Missing features are riskier on free plans
      'Pro': 1.1,
      'Business': 1.0,
      'Enterprise': 0.9,  // Enterprise has more built-in protections
      'Enterprise Plus': 0.85
    };

    this.exposureMultipliers = {
      'public': 1.3,      // Public-facing zone
      'internal': 0.8,    // Internal-only zone
      'staging': 0.6,     // Staging/test environment
      'development': 0.5
    };

    this.sensitivityMultipliers = {
      'critical': 1.5,    // PII, financial data, healthcare
      'high': 1.3,        // Business-sensitive data
      'medium': 1.0,      // Standard business data
      'low': 0.8          // Public information
    };

    this.exploitabilityFactors = {
      'exposed_credentials': 1.5,
      'origin_ip_exposed': 1.4,
      'missing_waf': 1.3,
      'weak_ssl': 1.3,
      'no_mfa': 1.2,
      'missing_headers': 1.1,
      'no_dnssec': 1.1,
      'default': 1.0
    };
  }

  calculateScore(finding, context = {}) {
    const baseScore = this.severityBaseScores[finding.severity?.toLowerCase()] || 1.0;
    const planMultiplier = this.planMultipliers[context.plan || 'Free'] || 1.0;
    const exposureMultiplier = this.exposureMultipliers[context.exposure || 'public'] || 1.0;
    const sensitivityMultiplier = this.sensitivityMultipliers[context.sensitivity || 'medium'] || 1.0;
    const exploitabilityFactor = this.getExploitabilityFactor(finding.checkId);

    // CVSS-like formula: Base × Exploitability × Contextual × Exposure
    let score = baseScore * exploitabilityFactor * planMultiplier * exposureMultiplier * sensitivityMultiplier;

    // Cap at 10.0
    score = Math.min(10.0, Math.round(score * 10) / 10);

    return {
      baseScore,
      exploitabilityFactor,
      planMultiplier,
      exposureMultiplier,
      sensitivityMultiplier,
      finalScore: score,
      riskLevel: this.getRiskLevel(score)
    };
  }

  calculateAssessmentScores(assessment, options = {}) {
    const scoredFindings = (assessment.findings || []).map(finding => {
      const zone = (assessment.zones || []).find(z => z.id === finding.resourceId || z.name === finding.resourceId);
      const context = {
        plan: zone?.plan || 'Free',
        exposure: this.inferExposure(finding, zone),
        sensitivity: options.sensitivity || 'medium'
      };

      const scores = this.calculateScore(finding, context);
      return { ...finding, contextualScore: scores };
    });

    const criticalCount = scoredFindings.filter(f => f.contextualScore?.riskLevel === 'critical').length;
    const highCount = scoredFindings.filter(f => f.contextualScore?.riskLevel === 'high').length;

    return {
      findings: scoredFindings,
      contextualSummary: {
        averageScore: this.averageScore(scoredFindings),
        maxScore: this.maxScore(scoredFindings),
        criticalRisk: criticalCount,
        highRisk: highCount,
        overallRiskLevel: this.getOverallRiskLevel(criticalCount, highCount)
      }
    };
  }

  getExploitabilityFactor(checkId) {
    const check = checkId?.toLowerCase() || '';
    for (const [pattern, factor] of Object.entries(this.exploitabilityFactors)) {
      if (check.includes(pattern.replace('_', '')) || check.includes(pattern)) {
        return factor;
      }
    }
    return this.exploitabilityFactors.default;
  }

  inferExposure(finding, zone) {
    if (finding.service === 'account' || finding.service === 'zerotrust') return 'internal';
    if (zone?.name?.includes('staging') || zone?.name?.includes('dev') || zone?.name?.includes('test')) return 'staging';
    if (finding.service === 'dns' || finding.service === 'ssl' || finding.service === 'waf') return 'public';
    return 'public';
  }

  getRiskLevel(score) {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score >= 1.0) return 'low';
    return 'informational';
  }

  getOverallRiskLevel(criticalCount, highCount) {
    if (criticalCount > 0) return 'critical';
    if (highCount > 3) return 'critical';
    if (highCount > 0) return 'high';
    return 'moderate';
  }

  averageScore(findings) {
    const scores = findings.map(f => f.contextualScore?.finalScore || 0).filter(s => s > 0);
    return scores.length > 0 ? Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10 : 0;
  }

  maxScore(findings) {
    return Math.max(...findings.map(f => f.contextualScore?.finalScore || 0), 0);
  }
}

module.exports = ContextualScoring;
