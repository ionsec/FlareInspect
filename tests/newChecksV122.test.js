/**
 * @fileoverview Tests for v1.2.2 additions: token pre-flight, R2 posture,
 * WAF managed rulesets.
 */

jest.mock('p-limit', () => ({
  default: () => async fn => fn()
}));

jest.mock('ora', () => () => ({
  start() { return this; },
  succeed() {},
  fail() {},
  text: ''
}));

const AssessmentService = require('../src/core/services/assessmentService');
const SecurityBaseline = require('../src/core/services/securityBaseline');

const accountResource = { id: 'acc-1', name: 'TestAccount', type: 'account' };
const zoneResource    = { id: 'z-1', name: 'example.com' };

function makeAssessment() {
  return {
    findings: [],
    configuration: { account: {}, zones: {}, waf: {}, r2: {} },
    summary: { total: 0, passed: 0, failed: 0, warnings: 0, bySeverity: {} }
  };
}

describe('SecurityBaseline new check definitions', () => {
  const baseline = new SecurityBaseline();
  const all = baseline.getAllChecks();

  test('CFL-TOK-001 is registered with critical severity', () => {
    const c = all.find(x => x.id === 'CFL-TOK-001');
    expect(c).toBeTruthy();
    expect(c.category).toBe('token');
    expect(c.severity).toBe('critical');
  });

  test('R2 checks (001/002/003) are registered', () => {
    const ids = ['CFL-R2-001', 'CFL-R2-002', 'CFL-R2-003'];
    for (const id of ids) {
      const c = all.find(x => x.id === id);
      expect(c).toBeTruthy();
      expect(c.category).toBe('r2');
    }
    expect(all.find(x => x.id === 'CFL-R2-001').severity).toBe('high');
  });

  test('WAF managed-ruleset checks (006/007/008) are registered', () => {
    expect(all.find(x => x.id === 'CFL-WAF-006')?.severity).toBe('high');
    expect(all.find(x => x.id === 'CFL-WAF-007')?.severity).toBe('high');
    expect(all.find(x => x.id === 'CFL-WAF-008')?.severity).toBe('medium');
  });
});

describe('assessToken (CFL-TOK-001)', () => {
  test('emits PASS for active, long-lived token', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const future = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    await service.assessToken(accountResource, { status: 'active', expires_on: future }, assessment);
    const finding = assessment.findings.find(f => f.checkId === 'CFL-TOK-001');
    expect(finding).toBeTruthy();
    expect(finding.status).toBe('PASS');
  });

  test('emits FAIL when status is not active', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    await service.assessToken(accountResource, { status: 'disabled' }, assessment);
    const finding = assessment.findings.find(f => f.checkId === 'CFL-TOK-001');
    expect(finding.status).toBe('FAIL');
  });

  test('emits FAIL when token expires within 14 days', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const soon = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString();
    await service.assessToken(accountResource, { status: 'active', expires_on: soon }, assessment);
    const finding = assessment.findings.find(f => f.checkId === 'CFL-TOK-001');
    expect(finding.status).toBe('FAIL');
  });

  test('emits WARNING when verify failed (token info has error)', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    await service.assessToken(accountResource, { error: '403 forbidden' }, assessment);
    const finding = assessment.findings.find(f => f.checkId === 'CFL-TOK-001');
    expect(finding.status).toBe('WARNING');
  });
});

describe('assessR2 (CFL-R2-001/002/003)', () => {
  test('PASS when account has no R2 buckets', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    await service.assessR2(accountResource, [], assessment);
    const access = assessment.findings.find(f => f.checkId === 'CFL-R2-001');
    expect(access.status).toBe('PASS');
  });

  test('FAIL on bucket with public custom domain', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const buckets = [{
      name: 'public-bucket',
      customDomains: [{ domain: 'cdn.example.com', enabled: true }],
      lifecycleRules: [{ id: 'r1' }],
      eventNotifications: [{ queue: 'q1' }],
      corsRules: []
    }];
    await service.assessR2(accountResource, buckets, assessment);
    const access = assessment.findings.find(f => f.checkId === 'CFL-R2-001');
    expect(access.status).toBe('FAIL');
  });

  test('FAIL on bucket with wildcard CORS', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const buckets = [{
      name: 'cors-bucket',
      customDomains: [],
      lifecycleRules: [{ id: 'r1' }],
      eventNotifications: [{ queue: 'q1' }],
      corsRules: [{ allowed: { origins: ['*'] } }]
    }];
    await service.assessR2(accountResource, buckets, assessment);
    const access = assessment.findings.find(f => f.checkId === 'CFL-R2-001');
    expect(access.status).toBe('FAIL');
  });

  test('WARNING on bucket missing lifecycle and event notifications', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const buckets = [{
      name: 'bare-bucket',
      customDomains: [],
      corsRules: [],
      lifecycleRules: [],
      eventNotifications: []
    }];
    await service.assessR2(accountResource, buckets, assessment);
    expect(assessment.findings.find(f => f.checkId === 'CFL-R2-002').status).toBe('WARNING');
    expect(assessment.findings.find(f => f.checkId === 'CFL-R2-003').status).toBe('WARNING');
  });

  test('skips entirely when token lacks R2 read scope', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    await service.assessR2(accountResource, { error: 'R2 fetch not available' }, assessment);
    expect(assessment.findings.find(f => f.checkId?.startsWith('CFL-R2-'))).toBeUndefined();
  });
});

describe('assessWAFManagedRulesets (CFL-WAF-006/007/008)', () => {
  const CF_MANAGED_ID = 'efb7b8c949ac4650a09736fc376e9aee';
  const OWASP_ID      = '4814384a9e5d4991b9815dcfc25d2f1f';

  test('PASS when both Cloudflare Managed and OWASP rulesets are deployed', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const deployments = [
      { rulesetId: CF_MANAGED_ID, enabled: true },
      { rulesetId: OWASP_ID, enabled: true }
    ];
    await service.assessWAFManagedRulesets(zoneResource, deployments, assessment);
    expect(assessment.findings.find(f => f.checkId === 'CFL-WAF-006').status).toBe('PASS');
    expect(assessment.findings.find(f => f.checkId === 'CFL-WAF-007').status).toBe('PASS');
  });

  test('FAIL when neither managed ruleset is deployed', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    await service.assessWAFManagedRulesets(zoneResource, [], assessment);
    expect(assessment.findings.find(f => f.checkId === 'CFL-WAF-006').status).toBe('FAIL');
    expect(assessment.findings.find(f => f.checkId === 'CFL-WAF-007').status).toBe('FAIL');
  });

  test('FAIL CFL-WAF-008 when ruleset is overridden to log-only', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const deployments = [
      { rulesetId: CF_MANAGED_ID, enabled: true, overrides: { action: 'log' } }
    ];
    await service.assessWAFManagedRulesets(zoneResource, deployments, assessment);
    expect(assessment.findings.find(f => f.checkId === 'CFL-WAF-008').status).toBe('FAIL');
  });

  test('PASS CFL-WAF-008 when no log-only overrides present', async () => {
    const service = new AssessmentService({ useSpinner: false });
    const assessment = makeAssessment();
    const deployments = [{ rulesetId: CF_MANAGED_ID, enabled: true, overrides: null }];
    await service.assessWAFManagedRulesets(zoneResource, deployments, assessment);
    expect(assessment.findings.find(f => f.checkId === 'CFL-WAF-008').status).toBe('PASS');
  });
});
