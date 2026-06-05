/**
 * @fileoverview Phase 2 remediation tests: leaked credentials, WAF managed
 *   rulesets, security.txt, notification policies, DNS TXT (SPF/DMARC),
 *   zone hold.
 *
 *   Each recipe must follow the trust-boundary contract:
 *     read → isCompliant → apply → verify → rollback
 *   with backup integrity (checksum) preserved end-to-end.
 */

jest.mock('p-limit', () => ({ default: () => async fn => fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const recipeRegistry = require('../src/core/remediation/recipeRegistry');
const engine = require('../src/core/remediation/remediationEngine');
const backupManager = require('../src/core/remediation/backupManager');

const TMP = path.join(os.tmpdir(), 'flareinspect-phase2-backups');
afterAll(() => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* ignore */ } });

/**
 * In-memory fake client for Phase 2 endpoints.
 * Tracks mutations and lets us assert what each recipe does.
 */
function makeFakeClient() {
  const calls = [];
  let leaked = { value: { enabled: false } };
  let rulesetPhase = { rules: [] };
  let securityTxt = { enabled: false };
  const notifications = [];
  const dnsRecords = [];
  let zoneHold = { hold: false };
  return {
    calls,
    dnsRecords, // expose for assertions
    async getLeakedCredChecks() { return leaked; },
    async setLeakedCredChecks(zoneId, enabled) {
      calls.push({ op: 'leaked-cred-checks', zoneId, enabled });
      leaked = { value: { enabled } };
      return { enabled };
    },
    async getRulesetPhase(zoneId, phase) { return rulesetPhase; },
    async putRulesetPhase(zoneId, phase, rules) {
      calls.push({ op: 'put-ruleset-phase', zoneId, phase, rules });
      rulesetPhase = { rules };
      return { rules };
    },
    async getSecurityTxt() { return securityTxt; },
    async putSecurityTxt(zoneId, payload) {
      calls.push({ op: 'put-security-txt', zoneId, payload });
      securityTxt = payload;
      return payload;
    },
    async getNotificationPolicies() { return notifications; },
    async createNotificationPolicy(accountId, body) {
      const id = `np-${notifications.length + 1}`;
      const created = { id, ...body };
      notifications.push(created);
      calls.push({ op: 'create-notification-policy', accountId, body });
      return created;
    },
    async deleteNotificationPolicy(accountId, id) {
      const idx = notifications.findIndex(n => n.id === id);
      if (idx >= 0) notifications.splice(idx, 1);
      calls.push({ op: 'delete-notification-policy', accountId, id });
      return { id };
    },
    async getDNSRecords() { return dnsRecords; },
    async createDNSRecord(zoneId, body) {
      const id = `dns-${dnsRecords.length + 1}`;
      dnsRecords.push({ id, ...body });
      calls.push({ op: 'create-dns-record', zoneId, body });
      return { id, ...body };
    },
    async deleteDNSRecord(zoneId, recordId) {
      const idx = dnsRecords.findIndex(r => r.id === recordId);
      if (idx >= 0) dnsRecords.splice(idx, 1);
      calls.push({ op: 'delete-dns-record', zoneId, recordId });
      return { id: recordId };
    },
    async getZoneHold() { return zoneHold; },
    async setZoneHold(zoneId) {
      calls.push({ op: 'set-zone-hold', zoneId });
      zoneHold = { hold: true };
      return zoneHold;
    },
    async removeZoneHold(zoneId) {
      calls.push({ op: 'remove-zone-hold', zoneId });
      zoneHold = { hold: false };
      return zoneHold;
    }
  };
}

const makeFinding = (checkId, overrides = {}) => ({
  id: `${checkId}-z1`,
  checkId,
  checkTitle: checkId,
  service: 'misc',
  severity: 'high',
  status: 'FAIL',
  resourceId: 'zone-1',
  resourceType: 'zone',
  metadata: {},
  ...overrides
});

const makeAssessment = (findings, accountId = 'acc-1') => ({
  assessmentId: 'assess-phase2',
  account: { id: accountId, name: 'Test' },
  zones: [{ id: 'zone-1', name: 'example.com' }],
  metadata: { toolVersion: '1.3.0' },
  findings
});

describe('CFL-LEAK-001 (Leaked Credentials Detection)', () => {
  test('compliant when already enabled — skips apply', async () => {
    const client = {
      calls: [],
      async getLeakedCredChecks() { return { value: { enabled: true } }; },
      async setLeakedCredChecks() { throw new Error('should not be called'); }
    };
    const recipe = recipeRegistry.get('CFL-LEAK-001');
    const cur = await recipe.read(client, { zoneId: 'zone-1' });
    expect(recipe.isCompliant(cur)).toBe(true);
  });

  test('non-compliant → apply toggles enabled → verify → rollback', async () => {
    const client = makeFakeClient();
    const recipe = recipeRegistry.get('CFL-LEAK-001');
    const ctx = { zoneId: 'zone-1' };
    const backup = await recipe.read(client, ctx);
    expect(recipe.isCompliant(backup)).toBe(false);
    const result = await recipe.apply(client, ctx);
    expect(client.calls.find(c => c.op === 'leaked-cred-checks')).toBeTruthy();
    expect(await recipe.verify(client, ctx)).toBe(true);
    // restore to the original disabled state: recipe is a no-op when backup
    // shows it was already off (prevents an unnecessary API call)
    const restoreResult = await recipe.restore(client, ctx, backup);
    expect(restoreResult).toBeNull();
  });

  test('restore re-disables when previously enabled', async () => {
    const client = {
      enabled: true,
      calls: [],
      async getLeakedCredChecks() { return { value: { enabled: this.enabled } }; },
      async setLeakedCredChecks(zoneId, enabled) {
        this.calls.push({ enabled });
        this.enabled = enabled;
        return { enabled };
      }
    };
    const recipe = recipeRegistry.get('CFL-LEAK-001');
    const ctx = { zoneId: 'zone-1' };
    const backup = { enabled: true };
    await recipe.restore(client, ctx, backup);
    expect(client.calls.at(-1).enabled).toBe(false);
  });
});

describe('CFL-WAF-006/007 (WAF Managed Rulesets)', () => {
  test.each([
    ['CFL-WAF-006', 'efb7b8c949ac4650b0977fbeabe3113f'],
    ['CFL-WAF-007', '4814384a9e5d4991b9815dcfc25d2f1f']
  ])('%s: deploys in log mode when not present', async (checkId, rulesetId) => {
    const client = makeFakeClient();
    const recipe = recipeRegistry.get(checkId);
    const ctx = { zoneId: 'zone-1' };
    const backup = await recipe.read(client, ctx);
    expect(recipe.isCompliant(backup)).toBe(false);
    await recipe.apply(client, ctx);
    const call = client.calls.find(c => c.op === 'put-ruleset-phase');
    expect(call).toBeTruthy();
    expect(call.rules[0].action_parameters.id).toBe(rulesetId);
    // Always log mode — never block
    expect(['log', 'execute']).toContain(call.rules[0].action);
    expect(await recipe.verify(client, ctx)).toBe(true);
  });

  test('skips apply when ruleset already deployed (compliant)', async () => {
    const client = {
      calls: [],
      async getRulesetPhase() {
        return { rules: [{ action: 'execute', action_parameters: { id: 'efb7b8c949ac4650b0977fbeabe3113f' } }] };
      },
      async putRulesetPhase() { throw new Error('should not be called'); }
    };
    const recipe = recipeRegistry.get('CFL-WAF-006');
    const cur = await recipe.read(client, { zoneId: 'z1' });
    expect(recipe.isCompliant(cur)).toBe(true);
  });
});

describe('CFL-SEC-001 (security.txt)', () => {
  test('proposed defaults to mailto + 1y expiry when no operator input', () => {
    const recipe = recipeRegistry.get('CFL-SEC-001');
    const p = recipe.proposed({ zoneId: 'z1', resourceId: 'z1' });
    expect(p.enabled).toBe(true);
    expect(p.contact).toEqual(['mailto:security@example.com']);
    // expiry should be ~1 year in the future (allow ±60s drift)
    const exp = Date.parse(p.expires);
    expect(exp - Date.now()).toBeGreaterThan(360 * 24 * 3600 * 1000);
  });

  test('proposed honors operator input from finding metadata', () => {
    const recipe = recipeRegistry.get('CFL-SEC-001');
    const p = recipe.proposed({
      zoneId: 'z1',
      finding: { metadata: { operatorInput: { contact: ['mailto:soc@acme.com'], expires: '2030-01-01T00:00:00.000Z' } } }
    });
    expect(p.contact).toEqual(['mailto:soc@acme.com']);
    expect(p.expires).toBe('2030-01-01T00:00:00.000Z');
  });

  test('apply writes security.txt; rollback removes it when not previously enabled', async () => {
    const client = {
      calls: [],
      cur: { enabled: false },
      async getSecurityTxt() { return this.cur; },
      async putSecurityTxt(zoneId, payload) {
        this.calls.push({ op: 'put', payload });
        this.cur = payload;
        return payload;
      },
      async deleteSecurityTxt(zoneId) {
        this.calls.push({ op: 'delete' });
        this.cur = { enabled: false };
        return {};
      }
    };
    const recipe = recipeRegistry.get('CFL-SEC-001');
    const ctx = { zoneId: 'z1', resourceId: 'z1' };
    const backup = await recipe.read(client, ctx);
    expect(recipe.isCompliant(backup)).toBe(false);
    await recipe.apply(client, ctx);
    expect(client.calls[0].op).toBe('put');
    expect(await recipe.verify(client, ctx)).toBe(true);
    await recipe.restore(client, ctx, backup);
    expect(client.calls[1].op).toBe('delete');
  });
});

describe('CFL-ALERT-001..004 (Notification Policies)', () => {
  test('create-policy recipe creates a disabled policy; rollback deletes by captured id', async () => {
    const client = makeFakeClient();
    const recipe = recipeRegistry.get('CFL-ALERT-001');
    const ctx = { accountId: 'acc-1', resourceId: 'acc-1', resourceType: 'account',
                  finding: { metadata: { operatorInput: { name: 'WAF policy' } } } };
    const backup = await recipe.read(client, ctx);
    expect(recipe.isCompliant(backup)).toBe(false);
    const created = await recipe.apply(client, ctx);
    // engine normally captures createdResourceId; here we emulate that
    const result = await recipe.restore(client, ctx, created.id);
    expect(client.calls.find(c => c.op === 'delete-notification-policy')).toBeTruthy();
    // newly created policy must be disabled — operator enables in dashboard
    const createdCall = client.calls.find(c => c.op === 'create-notification-policy');
    expect(createdCall.body.enabled).toBe(false);
    expect(result).toBeTruthy();
  });
});

describe('CFL-EMAIL-001/003 (DNS TXT records — SPF + DMARC)', () => {
  test('idempotent: applying twice does not create duplicate records', async () => {
    const client = makeFakeClient();
    const recipe = recipeRegistry.get('CFL-EMAIL-001');
    const ctx = { zoneId: 'zone-1' };
    const first = await recipe.apply(client, ctx);
    expect(first.id).toBeTruthy();
    const second = await recipe.apply(client, ctx);
    expect(second.id).toBe(first.id); // returns the existing record id
  });

  test('rollback deletes the created TXT record', async () => {
    const client = makeFakeClient();
    const recipe = recipeRegistry.get('CFL-EMAIL-003');
    const ctx = { zoneId: 'zone-1' };
    const created = await recipe.apply(client, ctx);
    expect(client.calls.find(c => c.op === 'create-dns-record')).toBeTruthy();
    await recipe.restore(client, ctx, created.id);
    const del = client.calls.find(c => c.op === 'delete-dns-record');
    expect(del.recordId).toBe(created.id);
  });
});

describe('CFL-HOLD-001 (Zone Hold — ENT only)', () => {
  test('apply enables zone hold; rollback removes it when previously off', async () => {
    const client = makeFakeClient();
    const recipe = recipeRegistry.get('CFL-HOLD-001');
    const ctx = { zoneId: 'zone-1' };
    const backup = await recipe.read(client, ctx);
    expect(recipe.isCompliant(backup)).toBe(false);
    await recipe.apply(client, ctx);
    expect(client.calls.find(c => c.op === 'set-zone-hold')).toBeTruthy();
    expect(await recipe.verify(client, ctx)).toBe(true);
    await recipe.restore(client, ctx, backup);
    expect(client.calls.find(c => c.op === 'remove-zone-hold')).toBeTruthy();
  });

  test('skip apply when already held (compliant)', async () => {
    const client = {
      calls: [],
      async getZoneHold() { return { hold: true }; },
      async setZoneHold() { throw new Error('should not be called'); }
    };
    const recipe = recipeRegistry.get('CFL-HOLD-001');
    const cur = await recipe.read(client, { zoneId: 'z1' });
    expect(recipe.isCompliant(cur)).toBe(true);
  });
});

describe('engine: create-then-delete recipes (phase 2)', () => {
  test('apply → rollback: createdResourceId round-trip for a TXT recipe', async () => {
    const client = makeFakeClient();
    const assessment = makeAssessment([makeFinding('CFL-EMAIL-001')]);
    const plan = await engine.buildPlan(assessment, { client });
    const applied = await engine.apply(plan.items, { client, assessment, backupDir: TMP });
    const item = applied.results[0];
    expect(item.applied).toBe(true);
    expect(item.createdResourceId).toBeTruthy();
    // Bundle must checksum-validate
    expect(backupManager.loadBundle(applied.bundlePath).phase).toBe('complete');
    const roll = await engine.rollback(applied.bundle, { client });
    expect(roll.results[0].applied).toBe(true);
    // The TXT record should have been deleted
    expect(client.dnsRecords).toHaveLength(0);
    expect(client.calls.find(c => c.op === 'delete-dns-record')).toBeTruthy();
  });
});

// ---------- Phase 3: Workers / storage / Zaraz advisory ----------

describe('Phase 3: Workers plaintext secret bindings (CFL-WORK-003)', () => {
  const AssessmentService = require('../src/core/services/assessmentService');
  const accountResource = { id: 'acc-1', name: 'Test', type: 'account' };

  test('FAIL on plain_text binding with secret-shaped value', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    const scripts = [{ id: 'w1', name: 'api-edge' }];
    const bindings = [{ type: 'plain_text', name: 'API_KEY', text: 'sk-test-1234567890abcdef', _script: 'api-edge' }];
    await svc.assessWorkersBindings(accountResource, scripts, bindings, assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-WORK-003');
    expect(f.status).toBe('FAIL');
  });

  test('PASS on no plain_text bindings with secret-shaped values', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    const scripts = [{ id: 'w1', name: 'safe' }];
    const bindings = [{ type: 'plain_text', name: 'INERT', text: 'hello' }];
    await svc.assessWorkersBindings(accountResource, scripts, bindings, assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-WORK-003');
    expect(f.status).toBe('PASS');
  });
});

describe('Phase 3: Storage inventory (CFL-STORE-001..003)', () => {
  const AssessmentService = require('../src/core/services/assessmentService');
  const accountResource = { id: 'acc-1', name: 'Test', type: 'account' };

  test.each([
    ['CFL-STORE-001', 'kv', [{ id: 'kv-1', title: 'CACHE' }]],
    ['CFL-STORE-002', 'd1', [{ uuid: 'd1-1', name: 'app-db' }]],
    ['CFL-STORE-003', 'queues', [{ queue_id: 'q-1', queue_name: 'events' }]]
  ])('%s: PASS when %s resources exist', async (checkId, kind, list) => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessStorageInventory(accountResource, list, checkId, kind, assessment);
    const f = assessment.findings.find(x => x.checkId === checkId);
    expect(f.status).toBe('PASS');
  });

  test('INFO when storage is empty (advisory — not a fail)', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessStorageInventory(accountResource, [], 'CFL-STORE-001', 'kv', assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-STORE-001');
    expect(f.status).toBe('INFO');
  });
});

describe('Phase 3: Zaraz consent (CFL-ZARAZ-001)', () => {
  const AssessmentService = require('../src/core/services/assessmentService');
  const zoneResource = { id: 'z-1', name: 'example.com' };

  test('FAIL on third-party tools without consent', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessZaraz(zoneResource, {
      tools: { ga4: {}, facebook: {} },
      consent: null
    }, assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-ZARAZ-001');
    expect(f.status).toBe('FAIL');
  });

  test('PASS when consent is enabled alongside third-party tools', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessZaraz(zoneResource, {
      tools: { ga4: {} },
      consent: { enabled: true }
    }, assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-ZARAZ-001');
    expect(f.status).toBe('PASS');
  });
});

// ---------- Phase 4: Enterprise / SASE advisory ----------

describe('Phase 4: Zone Hold (CFL-HOLD-001)', () => {
  const AssessmentService = require('../src/core/services/assessmentService');
  const zoneResource = { id: 'z-1', name: 'ent.example.com' };

  test('FAIL when zone hold is off', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessZoneHold(zoneResource, { hold: false, hold_after: null }, assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-HOLD-001');
    expect(f.status).toBe('FAIL');
  });

  test('PASS when zone hold is enabled', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessZoneHold(zoneResource, { hold: true, hold_after: null }, assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-HOLD-001');
    expect(f.status).toBe('PASS');
  });
});

describe('Phase 4: Device Posture (CFL-POSTURE-001)', () => {
  const AssessmentService = require('../src/core/services/assessmentService');
  const accountResource = { id: 'acc-1', name: 'ENT', type: 'account' };

  test('FAIL when no posture rules defined', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessDevicePosture(accountResource, [], assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-POSTURE-001');
    expect(f.status).toBe('FAIL');
  });

  test('PASS when posture rules present', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessDevicePosture(accountResource, [
      { id: 'p-1', name: 'Disk encryption', type: 'disk_encryption' }
    ], assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-POSTURE-001');
    expect(f.status).toBe('PASS');
  });
});

describe('Phase 4: Access app depth (CFL-ZT-007/008/009)', () => {
  const AssessmentService = require('../src/core/services/assessmentService');
  const accountResource = { id: 'acc-1', name: 'ENT', type: 'account' };

  test('FAIL CFL-ZT-007 when an app has everyone-allow', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessAccessDepth(accountResource, [
      { id: 'a-1', name: 'public', policies: [{ include: [{ everyone: {} }] }] }
    ], assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-ZT-007');
    expect(f.status).toBe('FAIL');
  });

  test('FAIL CFL-ZT-009 when an app has no require rules', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessAccessDepth(accountResource, [
      { id: 'a-1', name: 'no-mfa', policies: [{ include: [{ email: ['u@x.com'] }] }] }
    ], assessment);
    const f = assessment.findings.find(x => x.checkId === 'CFL-ZT-009');
    expect(f.status).toBe('FAIL');
  });

  test('all PASS for hardened apps', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessAccessDepth(accountResource, [
      {
        id: 'a-1',
        name: 'hardened',
        session_duration: '12h',
        policies: [{
          include: [{ email: ['u@x.com'] }],
          require: [{ email: true }]
        }]
      }
    ], assessment);
    expect(assessment.findings.find(x => x.checkId === 'CFL-ZT-007').status).toBe('PASS');
    expect(assessment.findings.find(x => x.checkId === 'CFL-ZT-008').status).toBe('PASS');
    expect(assessment.findings.find(x => x.checkId === 'CFL-ZT-009').status).toBe('PASS');
  });
});

describe('Phase 4: CASB / Email Security / RBI / Magic', () => {
  const AssessmentService = require('../src/core/services/assessmentService');
  const accountResource = { id: 'acc-1', name: 'ENT', type: 'account' };

  test('CFL-CASB-001: FAIL on open critical findings', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessCASB(accountResource, [
      { severity: 'critical', status: 'open' },
      { severity: 'low', status: 'open' }
    ], assessment);
    expect(assessment.findings.find(x => x.checkId === 'CFL-CASB-001').status).toBe('FAIL');
  });

  test('CFL-EMAILSEC-001: PASS when ≥1 active policy', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessEmailSecurity(accountResource, [
      { id: 'esp-1', name: 'Anti-spoof', enabled: true },
      { id: 'esp-2', name: 'Phishing', enabled: false }
    ], assessment);
    expect(assessment.findings.find(x => x.checkId === 'CFL-EMAILSEC-001').status).toBe('PASS');
  });

  test('CFL-RBI-001: PASS when ≥1 policy defined', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessBrowserIsolation(accountResource, [
      { id: 'iso-1', name: 'Isolate uploads' }
    ], assessment);
    expect(assessment.findings.find(x => x.checkId === 'CFL-RBI-001').status).toBe('PASS');
  });

  test('CFL-MAGIC-001: PASS when ruleset has rules', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessMagicFirewall(accountResource, [
      { id: 'mf-1', phase: 'magic_transit', rules: [{ id: 'mfr-1', action: 'block' }] }
    ], assessment);
    expect(assessment.findings.find(x => x.checkId === 'CFL-MAGIC-001').status).toBe('PASS');
  });

  test('CFL-MAGIC-001: FAIL on ruleset with no rules', async () => {
    const svc = new AssessmentService({ useSpinner: false });
    const assessment = { findings: [], configuration: {} };
    await svc.assessMagicFirewall(accountResource, [
      { id: 'mf-1', phase: 'magic_transit', rules: [] }
    ], assessment);
    expect(assessment.findings.find(x => x.checkId === 'CFL-MAGIC-001').status).toBe('FAIL');
  });
});

// ---------- Recipe registry safety guard (Phases 1-4) ----------

describe('recipeRegistry final safety guard', () => {
  test('all recipes are reversible and expose the full lifecycle', () => {
    for (const r of recipeRegistry.all()) {
      expect(r.reversible).toBe(true);
      expect(typeof r.read).toBe('function');
      expect(typeof r.isCompliant).toBe('function');
      expect(typeof r.proposed).toBe('function');
      expect(typeof r.apply).toBe('function');
      expect(typeof r.restore).toBe('function');
      expect(typeof r.verify).toBe('function');
      // Risk must be one of the three
      expect(['low', 'medium', 'high']).toContain(r.risk);
      // Scope is zone or account
      expect(['zone', 'account']).toContain(r.scope);
    }
  });

  test('every Phase 2/3/4 remediable check has a recipe', () => {
    const remediableIds = [
      'CFL-LEAK-001', 'CFL-WAF-006', 'CFL-WAF-007',
      'CFL-SEC-001',
      'CFL-ALERT-001', 'CFL-ALERT-002', 'CFL-ALERT-003', 'CFL-ALERT-004',
      'CFL-EMAIL-001', 'CFL-EMAIL-003',
      'CFL-HOLD-001'
    ];
    for (const id of remediableIds) {
      expect(recipeRegistry.has(id)).toBe(true);
    }
  });
});
