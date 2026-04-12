/**
 * @fileoverview Tests for AssessmentService filtering helpers
 */

jest.mock('p-limit', () => ({
  default: () => async fn => fn()
}));

jest.mock('ora', () => () => ({
  start() {
    return this;
  },
  succeed() {},
  fail() {},
  text: ''
}));

const AssessmentService = require('../src/core/services/assessmentService');

describe('AssessmentService check filtering', () => {
  test('normalizes supported aliases', () => {
    const service = new AssessmentService({ useSpinner: false });
    const result = service.normalizeCheckCategories(['dns', 'zero-trust', 'api-gateway']);

    expect(result.invalid).toEqual([]);
    expect(result.normalized).toEqual(['dns', 'zerotrust', 'api']);
  });

  test('filters findings to requested categories', () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = {
      metadata: {},
      findings: [
        { checkId: 'CFL-DNS-001', service: 'dns' },
        { checkId: 'CFL-SSL-001', service: 'ssl' },
        { checkId: 'CFL-WAF-001', service: 'waf' }
      ]
    };

    service.applyCheckFilter(assessment, ['dns', 'waf']);

    expect(assessment.findings).toEqual([
      { checkId: 'CFL-DNS-001', service: 'dns' },
      { checkId: 'CFL-WAF-001', service: 'waf' }
    ]);
    expect(assessment.metadata.requestedChecks).toEqual(['dns', 'waf']);
    expect(assessment.metadata.filteredFromTotalFindings).toBe(3);
  });

  test('rejects unknown categories', () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = { metadata: {}, findings: [] };

    expect(() => service.applyCheckFilter(assessment, ['made-up-check'])).toThrow(
      'Unknown check categories: made-up-check.'
    );
  });
});
