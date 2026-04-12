/**
 * @fileoverview Tests for DiffService
 */

const DiffService = require('../src/core/services/diffService');
const { v4: uuidv4 } = require('uuid');

describe('DiffService', () => {
  let service;

  beforeEach(() => {
    service = new DiffService();
  });

  const makeFinding = (checkId, status, resourceId = 'zone-001') => ({
    id: uuidv4(),
    checkId,
    checkTitle: `Test ${checkId}`,
    service: 'test',
    severity: 'high',
    status,
    description: 'Test',
    remediation: 'Fix',
    resourceId,
    resourceType: 'zone',
    timestamp: new Date()
  });

  const makeAssessment = (findings, score = 80) => ({
    assessmentId: uuidv4(),
    status: 'completed',
    findings,
    score: { overallScore: score, grade: score >= 80 ? 'B' : 'C' },
    summary: {
      byService: { test: findings.filter(f => f.status === 'FAIL').length },
      totalChecks: findings.length,
      passedChecks: findings.filter(f => f.status === 'PASS').length,
      failedChecks: findings.filter(f => f.status === 'FAIL').length
    }
  });

  test('detects new findings', () => {
    const baseline = makeAssessment([
      makeFinding('CFL-SSL-001', 'PASS')
    ]);
    const current = makeAssessment([
      makeFinding('CFL-SSL-001', 'PASS'),
      makeFinding('CFL-DNS-001', 'FAIL')
    ]);

    const diff = service.compare(baseline, current);
    expect(diff.newFindings.length).toBe(1);
    expect(diff.newFindings[0].delta).toBe('NEW');
  });

  test('detects resolved findings', () => {
    const baseline = makeAssessment([
      makeFinding('CFL-SSL-001', 'FAIL')
    ]);
    const current = makeAssessment([]);

    const diff = service.compare(baseline, current);
    expect(diff.resolvedFindings.length).toBe(1);
    expect(diff.resolvedFindings[0].delta).toBe('RESOLVED');
  });

  test('detects regressions (PASS → FAIL)', () => {
    const baseline = makeAssessment([
      makeFinding('CFL-SSL-001', 'PASS')
    ]);
    const current = makeAssessment([
      makeFinding('CFL-SSL-001', 'FAIL')
    ]);

    const diff = service.compare(baseline, current);
    expect(diff.regressions.length).toBe(1);
    expect(diff.regressions[0].delta).toBe('REGRESSION');
  });

  test('detects improvements (FAIL → PASS)', () => {
    const baseline = makeAssessment([
      makeFinding('CFL-SSL-001', 'FAIL')
    ]);
    const current = makeAssessment([
      makeFinding('CFL-SSL-001', 'PASS')
    ]);

    const diff = service.compare(baseline, current);
    expect(diff.improvements.length).toBe(1);
    expect(diff.improvements[0].delta).toBe('IMPROVEMENT');
  });

  test('detects unchanged findings', () => {
    const baseline = makeAssessment([
      makeFinding('CFL-SSL-001', 'PASS')
    ]);
    const current = makeAssessment([
      makeFinding('CFL-SSL-001', 'PASS')
    ]);

    const diff = service.compare(baseline, current);
    expect(diff.unchanged.length).toBe(1);
  });

  test('calculates score delta', () => {
    const baseline = makeAssessment([], 70);
    const current = makeAssessment([], 85);

    const diff = service.compare(baseline, current);
    expect(diff.summary.scoreDelta).toBe(15);
  });

  test('hasRegression returns true for regressions', () => {
    const baseline = makeAssessment([makeFinding('CFL-SSL-001', 'PASS')]);
    const current = makeAssessment([makeFinding('CFL-SSL-001', 'FAIL')]);

    const diff = service.compare(baseline, current);
    expect(service.hasRegression(diff)).toBe(true);
  });

  test('hasRegression returns true for score decrease', () => {
    const baseline = makeAssessment([], 90);
    const current = makeAssessment([], 50);

    const diff = service.compare(baseline, current);
    expect(service.hasRegression(diff)).toBe(true);
  });

  test('hasRegression returns false when improved', () => {
    const baseline = makeAssessment([makeFinding('CFL-SSL-001', 'FAIL')]);
    const current = makeAssessment([makeFinding('CFL-SSL-001', 'PASS')]);

    const diff = service.compare(baseline, current);
    expect(service.hasRegression(diff)).toBe(false);
  });

  test('generates drift report', () => {
    const baseline = makeAssessment([makeFinding('CFL-SSL-001', 'FAIL')]);
    const current = makeAssessment([makeFinding('CFL-SSL-001', 'PASS')]);

    const diff = service.compare(baseline, current);
    const report = service.generateDriftReport(diff);
    expect(report).toContain('Drift Detection Report');
    expect(report).toContain('IMPROVEMENT');
  });

  test('calculates drift score', () => {
    const baseline = makeAssessment([makeFinding('CFL-SSL-001', 'FAIL')]);
    const current = makeAssessment([makeFinding('CFL-SSL-001', 'PASS')]);

    const diff = service.compare(baseline, current);
    expect(diff.driftScore).toBeGreaterThan(0);
  });
});
