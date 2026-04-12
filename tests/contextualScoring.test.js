/**
 * @fileoverview Tests for ContextualScoring
 */

const ContextualScoring = require('../src/core/services/contextualScoring');

describe('ContextualScoring', () => {
  let scoring;

  beforeEach(() => {
    scoring = new ContextualScoring();
  });

  test('calculates base score from severity', () => {
    const finding = { severity: 'critical', checkId: 'CFL-SSL-001' };
    const result = scoring.calculateScore(finding);
    expect(result.baseScore).toBe(9.0);
  });

  test('applies plan multiplier for free tier', () => {
    const finding = { severity: 'high', checkId: 'CFL-SSL-001' };
    const result = scoring.calculateScore(finding, { plan: 'Free' });
    expect(result.planMultiplier).toBe(1.3);
    expect(result.finalScore).toBeGreaterThan(result.baseScore);
  });

  test('applies exposure multiplier for public zones', () => {
    const finding = { severity: 'high', checkId: 'CFL-SSL-001' };
    const result = scoring.calculateScore(finding, { exposure: 'public' });
    expect(result.exposureMultiplier).toBe(1.3);
  });

  test('applies sensitivity multiplier', () => {
    const finding = { severity: 'high', checkId: 'CFL-SSL-001' };
    const result = scoring.calculateScore(finding, { sensitivity: 'critical' });
    expect(result.sensitivityMultiplier).toBe(1.5);
  });

  test('caps score at 10.0', () => {
    const finding = { severity: 'critical', checkId: 'CFL-INSIGHT-001' };
    const result = scoring.calculateScore(finding, { plan: 'Free', exposure: 'public', sensitivity: 'critical' });
    expect(result.finalScore).toBeLessThanOrEqual(10.0);
  });

  test('infers exposure from service type', () => {
    expect(scoring.inferExposure({ service: 'account' }, null)).toBe('internal');
    expect(scoring.inferExposure({ service: 'dns' }, null)).toBe('public');
    expect(scoring.inferExposure({ service: 'ssl' }, { name: 'staging.example.com' })).toBe('staging');
  });

  test('maps risk level correctly', () => {
    expect(scoring.getRiskLevel(9.5)).toBe('critical');
    expect(scoring.getRiskLevel(7.5)).toBe('high');
    expect(scoring.getRiskLevel(4.5)).toBe('medium');
    expect(scoring.getRiskLevel(2.0)).toBe('low');
  });

  test('calculates assessment scores with context', () => {
    const assessment = {
      findings: [
        { checkId: 'CFL-SSL-001', severity: 'high', status: 'FAIL', service: 'ssl', resourceId: 'zone-001' }
      ],
      zones: [{ id: 'zone-001', name: 'example.com', plan: 'Pro' }]
    };

    const result = scoring.calculateAssessmentScores(assessment, { sensitivity: 'high' });
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].contextualScore).toBeDefined();
    expect(result.contextualSummary.overallRiskLevel).toBeDefined();
  });
});
