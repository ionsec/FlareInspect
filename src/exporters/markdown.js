/**
 * @fileoverview Markdown Exporter for FlareInspect
 * @description Exports findings in Markdown format for git-friendly reporting
 * @module exporters/markdown
 */

const dayjs = require('dayjs');
const logger = require('../core/utils/logger');
const pkg = require('../../package.json');

class MarkdownExporter {
  escapeInline(value) {
    return String(value ?? '')
      .replace(/\\/g, '\\\\')
      .replace(/\r?\n/g, ' ')
      .replace(/\|/g, '\\|')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  async export(assessment) {
    logger.info('Exporting assessment to Markdown format');

    const lines = [];
    const score = assessment.score || {};
    const summary = assessment.summary || {};
    const findings = assessment.findings || [];
    const analysis = assessment.report?.analysis || {};

    lines.push(`# FlareInspect Security Assessment Report`);
    lines.push('');
    lines.push(`**Assessment ID**: ${this.escapeInline(assessment.assessmentId)}`);
    lines.push(`**Account**: ${this.escapeInline(assessment.account?.name || 'Unknown')}`);
    lines.push(`**Date**: ${dayjs(assessment.startedAt).format('YYYY-MM-DD HH:mm')}`);
    lines.push(`**Duration**: ${assessment.executionTime || 0}ms`);
    lines.push('');

    // Executive Summary
    lines.push('## Executive Summary');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('|--------|-------|');
    lines.push(`| **Security Score** | ${score.overallScore || 0}/100 |`);
    lines.push(`| **Grade** | ${score.grade || 'F'} |`);
    lines.push(`| **Total Checks** | ${summary.totalChecks || 0} |`);
    lines.push(`| **Passed** | ${summary.passedChecks || 0} |`);
    lines.push(`| **Failed** | ${summary.failedChecks || 0} |`);
    lines.push(`| **Critical** | ${summary.criticalFindings || 0} |`);
    lines.push(`| **High** | ${summary.highFindings || 0} |`);
    lines.push(`| **Medium** | ${summary.mediumFindings || 0} |`);
    lines.push(`| **Low** | ${summary.lowFindings || 0} |`);
    lines.push('');

    // Findings by severity
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
    severityOrder.forEach(severity => {
      const severityFindings = findings.filter(f => f.severity === severity && f.status === 'FAIL');
      if (severityFindings.length === 0) return;

      lines.push(`## ${severity.charAt(0).toUpperCase() + severity.slice(1)} Findings`);
      lines.push('');

      severityFindings.forEach(f => {
        lines.push(`### ${this.escapeInline(f.checkTitle)}`);
        lines.push('');
        lines.push('| Field | Value |');
        lines.push('|-------|-------|');
        lines.push(`| Check ID | ${this.escapeInline(f.checkId)} |`);
        lines.push(`| Service | ${this.escapeInline(f.service)} |`);
        lines.push(`| Status | ${this.escapeInline(f.status)} |`);
        lines.push(`| Resource | ${this.escapeInline(f.resourceId || 'N/A')} |`);
        lines.push(`| Description | ${this.escapeInline(f.description)} |`);
        lines.push(`| Remediation | ${this.escapeInline(f.remediation)} |`);
        lines.push(`| Evidence Summary | ${this.escapeInline(f.evidence?.summary || f.description)} |`);
        lines.push(`| Observed | ${this.escapeInline(f.evidence?.observed || f.metadata?.actualValue || 'Unknown')} |`);
        lines.push(`| Expected | ${this.escapeInline(f.evidence?.expected || f.metadata?.expectedValue || 'Not specified')} |`);
        lines.push(`| Review Guidance | ${this.escapeInline(f.evidence?.reviewGuidance || 'Review the affected resources and validate the expected state.')} |`);
        lines.push('');
        this.pushEvidenceDetails(lines, f);
      });
    });

    if (analysis.reviewerSummary || analysis.identityAccess || analysis.zoneExposure || analysis.transportTls || analysis.trafficProtection || analysis.loggingForensics) {
      lines.push('## Full Data Analysis');
      lines.push('');
      this.pushAnalysisSection(lines, 'Identity and Access Analysis', analysis.identityAccess);
      this.pushAnalysisSection(lines, 'Zone Exposure Analysis', analysis.zoneExposure);
      this.pushAnalysisSection(lines, 'Transport and TLS Analysis', analysis.transportTls);
      this.pushAnalysisSection(lines, 'Traffic Protection Analysis', analysis.trafficProtection);
      this.pushAnalysisSection(lines, 'Logging and Forensics Analysis', analysis.loggingForensics);

      if (analysis.reviewerSummary) {
        lines.push('### Reviewer Summary');
        lines.push('');
        lines.push(`- Account: ${this.escapeInline(analysis.reviewerSummary.accountName || 'Unknown')}`);
        lines.push(`- Total failing findings: ${this.escapeInline(analysis.reviewerSummary.totalFailingFindings || 0)}`);
        (analysis.reviewerSummary.topFixes || []).forEach(fix => {
          lines.push(`- ${this.escapeInline(fix.title)} (${this.escapeInline(fix.service)} on ${this.escapeInline(fix.resource || 'N/A')}): ${this.escapeInline(fix.reviewGuidance || '')}`);
        });
        lines.push('');
      }
    }

    // Service breakdown
    const byService = summary.byService || {};
    if (Object.keys(byService).length > 0) {
      lines.push('## Findings by Service');
      lines.push('');
      lines.push('| Service | Issues |');
      lines.push('|---------|--------|');
      Object.entries(byService)
        .filter(([_, count]) => count > 0)
        .sort((a, b) => b[1] - a[1])
        .forEach(([service, count]) => {
          lines.push(`| ${this.escapeInline(service)} | ${count} |`);
        });
      lines.push('');
    }

    // Recommendations
    lines.push('## Recommendations');
    lines.push('');
    const report = assessment.report || {};
    const recs = report.recommendations || {};
    if (recs.immediate?.length > 0) {
      lines.push('### Immediate Actions (0-24 hours)');
      recs.immediate.forEach(r => lines.push(`- ${this.escapeInline(r.title)}: ${this.escapeInline(r.action)}`));
      lines.push('');
    }
    if (recs.shortTerm?.length > 0) {
      lines.push('### Short-term (1-30 days)');
      recs.shortTerm.forEach(r => lines.push(`- ${this.escapeInline(r.title)}: ${this.escapeInline(r.action)}`));
      lines.push('');
    }

    lines.push('---');
    lines.push(`*Generated by FlareInspect v${pkg.version} | IONSEC.IO*`);

    return lines.join('\n');
  }

  pushEvidenceDetails(lines, finding) {
    const evidence = finding.evidence || {};
    const affectedEntities = Array.isArray(evidence.affectedEntities) ? evidence.affectedEntities : [];
    const counts = evidence.counts && typeof evidence.counts === 'object' ? evidence.counts : {};

    if (Object.keys(counts).length > 0) {
      lines.push('**Decision Data**');
      lines.push('');
      Object.entries(counts).forEach(([key, value]) => {
        lines.push(`- ${this.escapeInline(key)}: ${this.escapeInline(value)}`);
      });
      lines.push('');
    }

    if (affectedEntities.length > 0) {
      lines.push('**Affected Entities**');
      lines.push('');
      lines.push('| Name | Email/Identifier | Details |');
      lines.push('|------|------------------|---------|');
      affectedEntities.forEach(entity => {
        const primary = entity.name || entity.email || entity.id || entity.resource || 'Unknown';
        const secondary = entity.email || entity.id || entity.resource || entity.type || '';
        const details = Object.entries(entity)
          .filter(([key]) => !['name', 'email', 'id', 'resource'].includes(key))
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join('; ') : value}`)
          .join(' | ');
        lines.push(`| ${this.escapeInline(primary)} | ${this.escapeInline(secondary)} | ${this.escapeInline(details)} |`);
      });
      lines.push('');
    }
  }

  pushAnalysisSection(lines, title, section) {
    if (!section) return;

    lines.push(`### ${title}`);
    lines.push('');
    lines.push(this.escapeInline(section.summary || 'No analysis available.'));
    lines.push('');

    (section.quickWins || []).forEach(win => {
      lines.push(`- ${this.escapeInline(win.title)}: ${this.escapeInline(win.action)} ${this.escapeInline(win.reviewGuidance || '')}`);
    });

    if ((section.topAffectedEntities || []).length > 0) {
      lines.push('');
      lines.push('Affected entities for review:');
      (section.topAffectedEntities || []).forEach(entity => {
        const name = entity.name || entity.email || entity.id || entity.resource || 'Unknown';
        const detail = Object.entries(entity)
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join('; ') : value}`)
          .join(' | ');
        lines.push(`- ${this.escapeInline(name)}: ${this.escapeInline(detail)}`);
      });
    }

    lines.push('');
  }
}

module.exports = MarkdownExporter;
