/**
 * @fileoverview Tests for ComplianceEngine
 */

const ComplianceEngine = require('../src/core/services/complianceEngine');
const { randomUUID: uuidv4 } = require('crypto');

describe('ComplianceEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new ComplianceEngine();
  });

  const makeFinding = (checkId, status, severity) => ({
    id: uuidv4(),
    checkId,
    checkTitle: `Test ${checkId}`,
    service: 'test',
    severity: severity || 'high',
    status: status || 'FAIL',
    description: 'Test finding',
    remediation: 'Fix it',
    resourceId: 'test-resource',
    resourceType: 'zone',
    timestamp: new Date()
  });

  test('maps findings to CIS framework', () => {
    const findings = [
      makeFinding('CFL-SSL-001', 'FAIL', 'high'),
      makeFinding('CFL-DNS-001', 'PASS', 'high'),
      makeFinding('CFL-WAF-001', 'FAIL', 'high')
    ];

    const result = engine.mapFindingsToFramework(findings, 'cis');
    expect(result.framework).toBe('cis');
    expect(result.totalControls).toBeGreaterThan(0);
    expect(result.controls.length).toBeGreaterThan(0);
  });

  test('maps findings to SOC2 framework', () => {
    const findings = [
      makeFinding('CFL-ACC-001', 'FAIL', 'critical'),
      makeFinding('CFL-SSL-001', 'PASS', 'high')
    ];

    const result = engine.mapFindingsToFramework(findings, 'soc2');
    expect(result.framework).toBe('soc2');
    expect(result.totalControls).toBeGreaterThan(0);
  });

  test('generates full compliance report', () => {
    const findings = [
      makeFinding('CFL-ACC-001', 'FAIL'),
      makeFinding('CFL-SSL-001', 'PASS'),
      makeFinding('CFL-DNS-001', 'FAIL')
    ];

    const report = engine.getComplianceReport(findings);
    expect(report.cis).toBeDefined();
    expect(report.soc2).toBeDefined();
    expect(report.pci).toBeDefined();
    expect(report.nist).toBeDefined();
  });

  test('gets check compliance mapping', () => {
    const mapping = engine.getCheckCompliance('CFL-SSL-001');
    expect(mapping.cis).toBeDefined();
    expect(mapping.cis.length).toBeGreaterThan(0);
    expect(mapping.soc2.length).toBeGreaterThan(0);
  });

  test('returns empty for unknown check', () => {
    const mapping = engine.getCheckCompliance('UNKNOWN-999');
    expect(mapping.cis).toEqual([]);
  });

  test('gets framework checks', () => {
    const checks = engine.getFrameworkChecks('cis');
    expect(checks.length).toBeGreaterThan(0);
    expect(checks[0].checkId).toBeDefined();
    expect(checks[0].controls.length).toBeGreaterThan(0);
  });

  test('handles unknown framework', () => {
    expect(() => engine.mapFindingsToFramework([], 'unknown-fw')).toThrow();
  });

  test('calculates control pass rate', () => {
    const findings = [
      makeFinding('CFL-SSL-001', 'PASS'),
      makeFinding('CFL-SSL-002', 'FAIL')
    ];

    const result = engine.mapFindingsToFramework(findings, 'cis');
    const sslControl = result.controls.find(c => c.id === '3.1');
    if (sslControl) {
      expect(sslControl.passRate).toBeGreaterThanOrEqual(0);
      expect(sslControl.passRate).toBeLessThanOrEqual(100);
    }
  });
});
