/**
 * @fileoverview Diff/Baseline Drift Detection Service for FlareInspect
 * @description Compares two assessments to identify security posture changes
 * @module core/services/diffService
 */

const logger = require('../utils/logger');

class DiffService {
  compare(baseline, current) {
    logger.info('Comparing assessments for drift detection');

    const baselineFindings = baseline.findings || [];
    const currentFindings = current.findings || [];

    const baselineMap = this.buildFindingMap(baselineFindings);
    const currentMap = this.buildFindingMap(currentFindings);

    const newFindings = [];
    const resolvedFindings = [];
    const regressions = [];
    const improvements = [];
    const unchanged = [];

    // Check baseline findings against current
    for (const [key, baselineFinding] of baselineMap) {
      const currentFinding = currentMap.get(key);
      if (!currentFinding) {
        resolvedFindings.push({ ...baselineFinding, delta: 'RESOLVED' });
      } else if (baselineFinding.status !== currentFinding.status) {
        if (baselineFinding.status === 'PASS' && currentFinding.status === 'FAIL') {
          regressions.push({ ...currentFinding, previousStatus: baselineFinding.status, delta: 'REGRESSION' });
        } else if (baselineFinding.status === 'FAIL' && currentFinding.status === 'PASS') {
          improvements.push({ ...currentFinding, previousStatus: baselineFinding.status, delta: 'IMPROVEMENT' });
        } else {
          unchanged.push({ ...currentFinding, delta: 'UNCHANGED' });
        }
      } else {
        unchanged.push({ ...currentFinding, delta: 'UNCHANGED' });
      }
    }

    // Find new findings (in current but not in baseline)
    for (const [key, currentFinding] of currentMap) {
      if (!baselineMap.has(key)) {
        newFindings.push({ ...currentFinding, delta: 'NEW' });
      }
    }

    const baselineScore = baseline.score?.overallScore || 0;
    const currentScore = current.score?.overallScore || 0;
    const scoreDelta = currentScore - baselineScore;

    const summary = {
      baselineScore,
      currentScore,
      scoreDelta,
      baselineGrade: baseline.score?.grade || 'F',
      currentGrade: current.score?.grade || 'F',
      gradeDelta: this.calculateGradeDelta(baseline.score?.grade || 'F', current.score?.grade || 'F'),
      newFindings: newFindings.length,
      resolvedFindings: resolvedFindings.length,
      changedFindings: regressions.length + improvements.length,
      regressions: regressions.length,
      improvements: improvements.length,
      unchanged: unchanged.length
    };

    // Score by service
    const scoreByService = this.calculateServiceScoreDelta(baseline, current);

    return {
      summary,
      newFindings,
      resolvedFindings,
      regressions,
      improvements,
      unchanged,
      scoreByService,
      driftScore: this.calculateDriftScore({ summary, regressions, improvements })
    };
  }

  buildFindingMap(findings) {
    const map = new Map();
    findings.forEach(f => {
      const key = `${f.checkId || f.checkId}::${f.resourceId || 'unknown'}`;
      map.set(key, f);
    });
    return map;
  }

  calculateGradeDelta(baselineGrade, currentGrade) {
    const gradeValues = { 'A': 5, 'B': 4, 'C': 3, 'D': 2, 'F': 1 };
    return (gradeValues[currentGrade] || 0) - (gradeValues[baselineGrade] || 0);
  }

  calculateServiceScoreDelta(baseline, current) {
    const services = new Set([
      ...Object.keys(baseline.summary?.byService || {}),
      ...Object.keys(current.summary?.byService || {})
    ]);

    const delta = {};
    services.forEach(service => {
      const b = baseline.summary?.byService?.[service] || 0;
      const c = current.summary?.byService?.[service] || 0;
      delta[service] = { baseline: b, current: c, delta: c - b };
    });
    return delta;
  }

  hasRegression(diff) {
    return diff.regressions?.length > 0 || (diff.summary?.scoreDelta || 0) < 0;
  }

  calculateDriftScore(diff) {
    const severityWeights = { critical: 10, high: 7, medium: 4, low: 2, informational: 1 };
    let improvementScore = 0;
    let regressionScore = 0;

    (diff.improvements || []).forEach(f => {
      improvementScore += severityWeights[f.severity] || 1;
    });

    (diff.regressions || []).forEach(f => {
      regressionScore += severityWeights[f.severity] || 1;
    });

    // Score from -100 to +100
    const total = improvementScore + regressionScore;
    if (total === 0) return 0;
    return Math.round(((improvementScore - regressionScore) / total) * 100);
  }

  generateDriftReport(diff) {
    const lines = [];
    const s = diff.summary;

    lines.push('═══════════════════════════════════════════════════');
    lines.push('         FlareInspect Drift Detection Report        ');
    lines.push('═══════════════════════════════════════════════════');
    lines.push('');
    lines.push(`Score: ${s.baselineScore} → ${s.currentScore} (${s.scoreDelta >= 0 ? '+' : ''}${s.scoreDelta})`);
    lines.push(`Grade: ${s.baselineGrade} → ${s.currentGrade} (${s.gradeDelta >= 0 ? '+' : ''}${s.gradeDelta})`);
    lines.push(`Drift Score: ${diff.driftScore >= 0 ? '+' : ''}${diff.driftScore}`);
    lines.push('');

    lines.push('Changes Summary:');
    lines.push(`  🆕 New findings:      ${s.newFindings}`);
    lines.push(`  ✅ Resolved:          ${s.resolvedFindings}`);
    lines.push(`  🔴 Regressions:       ${s.regressions}`);
    lines.push(`  🟢 Improvements:      ${s.improvements}`);
    lines.push(`  →  Unchanged:         ${s.unchanged}`);
    lines.push('');

    if (diff.regressions?.length > 0) {
      lines.push('🔴 REGRESSIONS (PASS → FAIL):');
      diff.regressions.forEach(f => {
        lines.push(`  • [${f.severity?.toUpperCase()}] ${f.checkTitle} (${f.resourceId})`);
      });
      lines.push('');
    }

    if (diff.improvements?.length > 0) {
      lines.push('🟢 IMPROVEMENTS (FAIL → PASS):');
      diff.improvements.forEach(f => {
        lines.push(`  • [${f.severity?.toUpperCase()}] ${f.checkTitle} (${f.resourceId})`);
      });
      lines.push('');
    }

    if (diff.newFindings?.length > 0) {
      lines.push('🆕 NEW FINDINGS:');
      diff.newFindings.slice(0, 10).forEach(f => {
        lines.push(`  • [${f.status}] ${f.checkTitle} (${f.resourceId})`);
      });
      if (diff.newFindings.length > 10) {
        lines.push(`  ... and ${diff.newFindings.length - 10} more`);
      }
      lines.push('');
    }

    if (diff.resolvedFindings?.length > 0) {
      lines.push('✅ RESOLVED FINDINGS:');
      diff.resolvedFindings.slice(0, 10).forEach(f => {
        lines.push(`  • ${f.checkTitle} (${f.resourceId})`);
      });
      if (diff.resolvedFindings.length > 10) {
        lines.push(`  ... and ${diff.resolvedFindings.length - 10} more`);
      }
      lines.push('');
    }

    if (this.hasRegression(diff)) {
      lines.push('⚠️  SECURITY POSTURE HAS REGRESSED - Immediate review recommended');
    } else if (diff.driftScore > 0) {
      lines.push('✅ Security posture has improved');
    } else {
      lines.push('→  No significant changes detected');
    }

    return lines.join('\n');
  }
}

module.exports = DiffService;
