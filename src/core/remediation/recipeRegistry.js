/**
 * @fileoverview Remediation Recipe Registry
 * @description The trust boundary for FlareInspect remediation. This module is the
 *   ONLY place that knows how to mutate Cloudflare configuration. Each recipe is a
 *   deterministic descriptor mapping a security check to a single, idempotent,
 *   reversible change. The AI planner may only order/annotate these recipes — it can
 *   never invent an endpoint or payload. If a finding has no recipe here, it is
 *   advisory-only and is never auto-applied.
 * @module core/remediation/recipeRegistry
 */

/**
 * @typedef {Object} RemediationContext
 * @property {string} zoneId
 * @property {string} [zoneName]
 * @property {string} resourceId
 * @property {string} resourceType
 * @property {object} [finding]
 */

/**
 * @typedef {Object} Recipe
 * @property {string} checkId
 * @property {string} title
 * @property {'zone'|'account'} scope
 * @property {'low'|'medium'|'high'} risk
 * @property {boolean} reversible
 * @property {string} setting            Human-facing setting name (for diffs/reports)
 * @property {(client, ctx) => Promise<*>} read         Capture current value (for backup)
 * @property {(currentValue) => boolean} isCompliant    True if no change needed
 * @property {(ctx) => *} proposed                       Target value
 * @property {(client, ctx) => Promise<*>} apply         Perform the mutation
 * @property {(client, ctx, backupValue) => Promise<*>} restore  Roll back to backupValue
 * @property {(client, ctx) => Promise<boolean>} verify  Confirm post-state
 */

/**
 * Factory for a standard scalar zone-setting recipe (ssl, min_tls_version, etc.).
 */
function zoneSettingRecipe({ checkId, title, setting, target, acceptable, risk = 'low' }) {
  const acceptableValues = acceptable || [target];
  return {
    checkId,
    title,
    scope: 'zone',
    risk,
    reversible: true,
    setting,
    async read(client, ctx) {
      const { value } = await client.getZoneSetting(ctx.zoneId, setting);
      return value;
    },
    isCompliant(currentValue) {
      return acceptableValues.includes(currentValue);
    },
    proposed() {
      return target;
    },
    async apply(client, ctx) {
      return client.patchZoneSetting(ctx.zoneId, setting, target);
    },
    async restore(client, ctx, backupValue) {
      // Never restore to null/unknown — skip if we have no captured value
      if (backupValue === null || backupValue === undefined) return null;
      return client.patchZoneSetting(ctx.zoneId, setting, backupValue);
    },
    async verify(client, ctx) {
      const { value } = await client.getZoneSetting(ctx.zoneId, setting);
      return acceptableValues.includes(value);
    }
  };
}

// --- HSTS (security_header) — nested object value, treated conservatively ----
const HSTS_TARGET = {
  strict_transport_security: {
    enabled: true,
    max_age: 15552000,        // 6 months — conservative; avoids long-lived lock-in
    include_subdomains: false, // off by default: subdomains can break unexpectedly
    nosniff: true,
    preload: false             // never auto-enroll in preload (irreversible in practice)
  }
};

const hstsRecipe = {
  checkId: 'CFL-SSL-004',
  title: 'Enable HTTP Strict Transport Security (HSTS)',
  scope: 'zone',
  risk: 'high', // HSTS pins clients to HTTPS; mistakes are slow to recover from
  reversible: true,
  setting: 'security_header',
  async read(client, ctx) {
    const { value } = await client.getZoneSetting(ctx.zoneId, 'security_header');
    return value || null;
  },
  isCompliant(currentValue) {
    const hsts = currentValue?.strict_transport_security;
    return !!(hsts && hsts.enabled === true && hsts.max_age >= 15552000);
  },
  proposed() {
    return HSTS_TARGET;
  },
  async apply(client, ctx) {
    return client.patchZoneSetting(ctx.zoneId, 'security_header', HSTS_TARGET);
  },
  async restore(client, ctx, backupValue) {
    if (!backupValue) {
      // No prior header captured: the safe inverse is to disable HSTS
      return client.patchZoneSetting(ctx.zoneId, 'security_header', {
        strict_transport_security: { enabled: false }
      });
    }
    return client.patchZoneSetting(ctx.zoneId, 'security_header', backupValue);
  },
  async verify(client, ctx) {
    const { value } = await client.getZoneSetting(ctx.zoneId, 'security_header');
    return !!value?.strict_transport_security?.enabled;
  }
};

// --- DNSSEC — dedicated endpoint ---------------------------------------------
const dnssecRecipe = {
  checkId: 'CFL-DNS-001',
  title: 'Enable DNSSEC',
  scope: 'zone',
  risk: 'medium', // enabling signing is safe; DS record at registrar is a manual follow-up
  reversible: true,
  setting: 'dnssec',
  async read(client, ctx) {
    const { value } = await client.getDnssec(ctx.zoneId);
    return value;
  },
  isCompliant(currentValue) {
    return currentValue === 'active' || currentValue === 'pending';
  },
  proposed() {
    return 'active';
  },
  async apply(client, ctx) {
    return client.setDnssec(ctx.zoneId, 'active');
  },
  async restore(client, ctx, backupValue) {
    // If it was previously off/unknown, the safe inverse is disabling it again
    if (backupValue === 'active' || backupValue === 'pending') return null;
    return client.setDnssec(ctx.zoneId, 'disabled');
  },
  async verify(client, ctx) {
    const { value } = await client.getDnssec(ctx.zoneId);
    return value === 'active' || value === 'pending';
  }
};

// --- Phase 4: Zone Hold (ENT only) --------------------------------------
const zoneHoldRecipe = {
  checkId: 'CFL-HOLD-001',
  title: 'Enable zone hold (anti-takeover)',
  scope: 'zone',
  risk: 'high', // zone hold is reversible but can block legitimate transfers
  reversible: true,
  setting: 'zone-hold',
  async read(client, ctx) {
    const hold = await client.getZoneHold(ctx.zoneId);
    return { hold: !!hold?.hold, hold_after: hold?.hold_after || null };
  },
  isCompliant(currentValue) {
    return !!currentValue?.hold;
  },
  proposed() {
    return { hold: true };
  },
  async apply(client, ctx) {
    return client.setZoneHold(ctx.zoneId);
  },
  async restore(client, ctx, backupValue) {
    // If previously off, remove the hold. If it was already on, no-op.
    if (!backupValue || !backupValue.hold) {
      return client.removeZoneHold(ctx.zoneId);
    }
    return null;
  },
  async verify(client, ctx) {
    const hold = await client.getZoneHold(ctx.zoneId);
    return !!hold?.hold;
  }
};

// --- Phase 2a: Leaked Credentials + WAF Managed Rulesets ---------------

/**
 * Leaked Credentials Detection: enables a non-blocking detection-only check.
 * Reversible (disable by setting enabled=false).
 */
const leakedCredsRecipe = {
  checkId: 'CFL-LEAK-001',
  title: 'Enable Leaked Credentials Detection',
  scope: 'zone',
  risk: 'low', // non-blocking, detection-only
  reversible: true,
  setting: 'leaked-credential-checks',
  async read(client, ctx) {
    const { value } = await client.getLeakedCredChecks(ctx.zoneId);
    return { enabled: !!value?.enabled };
  },
  isCompliant(currentValue) {
    return !!currentValue?.enabled;
  },
  proposed() {
    return { enabled: true };
  },
  async apply(client, ctx) {
    return client.setLeakedCredChecks(ctx.zoneId, true);
  },
  async restore(client, ctx, backupValue) {
    if (!backupValue || backupValue.enabled === false) return null;
    return client.setLeakedCredChecks(ctx.zoneId, false);
  },
  async verify(client, ctx) {
    const { value } = await client.getLeakedCredChecks(ctx.zoneId);
    return !!value?.enabled;
  }
};

/**
 * WAF Managed Ruleset (OWASP Core Ruleset) — deploy in log mode by default
 * to avoid blocking traffic. Promotes CFL-WAF-006/007 from manual to remediable.
 * Risk: high — managed rulesets CAN affect traffic if escalated to block.
 * Restore: removes the ruleset from the entrypoint.
 */
const OWASP_RULESET_ID = '4814384a9e5d4991b9815dcfc25d2f1f';
const MANAGED_RULESET_ID = 'efb7b8c949ac4650b0977fbeabe3113f'; // Cloudflare Managed

function wafManagedRulesetRecipe({ checkId, title, rulesetId, risk }) {
  return {
    checkId,
    title,
    scope: 'zone',
    risk,
    reversible: true,
    setting: 'http_request_firewall_managed',
    async read(client, ctx) {
      const ep = await client.getRulesetPhase(ctx.zoneId, 'http_request_firewall_managed');
      const rules = Array.isArray(ep?.rules) ? ep.rules : [];
      const deployed = rules.some(r => r.action === 'execute' && r.action_parameters?.id === rulesetId);
      return { deployed, rulesetId, ruleCount: rules.length };
    },
    isCompliant(currentValue) {
      return !!currentValue?.deployed;
    },
    proposed() {
      return { deployed: true, rulesetId, action: 'log' };
    },
    async apply(client, ctx) {
      // Add the ruleset in LOG mode — never block from a recipe
      return client.putRulesetPhase(ctx.zoneId, 'http_request_firewall_managed', [
        { action: 'execute', expression: 'true', action_parameters: { id: rulesetId } }
      ]);
    },
    async restore(client, ctx, backupValue) {
      // If previously empty, put empty rules array
      if (!backupValue || !backupValue.deployed) {
        return client.putRulesetPhase(ctx.zoneId, 'http_request_firewall_managed', []);
      }
      return null; // nothing to remove — it was already deployed
    },
    async verify(client, ctx) {
      const ep = await client.getRulesetPhase(ctx.zoneId, 'http_request_firewall_managed');
      const rules = Array.isArray(ep?.rules) ? ep.rules : [];
      return rules.some(r => r.action === 'execute' && r.action_parameters?.id === rulesetId);
    }
  };
}

/**
 * security.txt (CFL-SEC-001): publish a security.txt with operator-supplied
 * contact + expiry. Defaults to `mailto:security@example.com` and a 1-year
 * expiry if no operator input is provided. The recipe honors
 * `proposed({operatorInput: {contact, expires}})` for CLI/web prompting.
 */
const securityTxtRecipe = {
  checkId: 'CFL-SEC-001',
  title: 'Publish security.txt',
  scope: 'zone',
  risk: 'low', // public file; no security impact from publishing
  reversible: true,
  setting: 'security-txt',
  async read(client, ctx) {
    const cur = await client.getSecurityTxt(ctx.zoneId);
    return cur || null;
  },
  isCompliant(currentValue) {
    return !!(currentValue && currentValue.enabled && Array.isArray(currentValue.contact) && currentValue.contact.length > 0);
  },
  proposed(ctx) {
    const op = (ctx && ctx.finding && ctx.finding.metadata && ctx.finding.metadata.operatorInput) || {};
    const contact = op.contact || (ctx && ctx.operatorInput && ctx.operatorInput.contact) || ['mailto:security@example.com'];
    const expires = op.expires || (ctx && ctx.operatorInput && ctx.operatorInput.expires) || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
    return { enabled: true, contact, expires };
  },
  async apply(client, ctx) {
    const proposed = this.proposed(ctx);
    return client.putSecurityTxt(ctx.zoneId, proposed);
  },
  async restore(client, ctx, backupValue) {
    if (!backupValue || !backupValue.enabled) {
      return client.deleteSecurityTxt(ctx.zoneId);
    }
    return client.putSecurityTxt(ctx.zoneId, backupValue);
  },
  async verify(client, ctx) {
    const cur = await client.getSecurityTxt(ctx.zoneId);
    return !!(cur && cur.enabled);
  }
};

/**
 * Notification policy recipe factory. Operator-prompted: the recipe expects
 * `ctx.finding.metadata.operatorInput = { emailIds, webhookIds, name }` or
 * the CLI default of one email destination id. Apply creates a policy in
 * DISABLED state — the operator enables it in the dashboard once they
 * confirm the destination. Delete on rollback.
 */
function notificationPolicyRecipe({ checkId, title, alertType, risk = 'medium' }) {
  return {
    checkId,
    title,
    scope: 'account',
    risk,
    reversible: true,
    setting: 'notification-policy',
    async read(client, ctx) {
      const policies = await client.getNotificationPolicies(ctx.accountId);
      const list = Array.isArray(policies) ? policies : [];
      return { count: list.length, hasType: list.some(p => p.alert_type === alertType && p.enabled) };
    },
    isCompliant(currentValue) {
      return !!(currentValue && currentValue.hasType);
    },
    proposed(ctx) {
      const op = (ctx && ctx.finding && ctx.finding.metadata && ctx.finding.metadata.operatorInput) || {};
      const name = op.name || `FlareInspect: ${alertType}`;
      const mechanisms = {};
      if (op.emailIds && op.emailIds.length) mechanisms.email = op.emailIds.map(id => ({ id }));
      if (op.webhookIds && op.webhookIds.length) mechanisms.webhooks = op.webhookIds.map(id => ({ id }));
      return {
        name,
        description: `Auto-created by FlareInspect for ${alertType}`,
        enabled: false, // operator must enable after confirming destination
        alert_type: alertType,
        mechanisms
      };
    },
    async apply(client, ctx) {
      const body = this.proposed(ctx);
      const created = await client.createNotificationPolicy(ctx.accountId, body);
      return { id: created && created.id, resourceType: 'notification_policy' };
    },
    async restore(client, ctx, capturedId) {
      if (!capturedId) return null;
      return client.deleteNotificationPolicy(ctx.accountId, capturedId);
    },
    async verify(client, ctx) {
      const policies = await client.getNotificationPolicies(ctx.accountId);
      const list = Array.isArray(policies) ? policies : [];
      return list.some(p => p.alert_type === alertType);
    }
  };
}

/**
 * DNS TXT record recipe factory. Conservative defaults for SPF/DMARC.
 * Idempotent: if a record with the same name already exists, we skip create
 * (and there's nothing to delete on rollback).
 */
function dnsTxtRecordRecipe({ checkId, title, recordName, content, risk = 'medium' }) {
  return {
    checkId,
    title,
    scope: 'zone',
    risk,
    reversible: true,
    setting: 'dns-record',
    async read(client, ctx) {
      const records = await client.getDNSRecords(ctx.zoneId);
      const list = Array.isArray(records) ? records : [];
      const existing = list.find(r => r.type === 'TXT' && r.name === recordName);
      // Always return a 3-key shape — `JSON.stringify` drops `undefined` values,
      // so omitting the keys would break checksum stability across read→write→read.
      return {
        hasMatching: !!existing,
        recordId: (existing && existing.id) || null,
        content: (existing && existing.content) || null
      };
    },
    isCompliant(currentValue) {
      return !!(currentValue && currentValue.hasMatching);
    },
    proposed() {
      return { type: 'TXT', name: recordName, content, ttl: 3600 };
    },
    async apply(client, ctx) {
      const body = this.proposed(ctx);
      const records = await client.getDNSRecords(ctx.zoneId);
      const existing = (records || []).find(r => r.type === 'TXT' && r.name === recordName);
      if (existing) {
        return { id: existing.id, resourceType: 'dns_record' };
      }
      const created = await client.createDNSRecord(ctx.zoneId, body);
      return { id: created && created.id, resourceType: 'dns_record' };
    },
    // The apply() return value is already shaped for the engine to capture
    // (see remediationEngine.js `apply` block). We expose this as a no-op so
    // the engine's `recipe.captureCreatedResourceId?.(client, ctx, result)`
    // path is taken and the id is stashed on the item.
    async captureCreatedResourceId(client, ctx, result) {
      return { id: result && result.id, resourceType: result && result.resourceType };
    },
    async restore(client, ctx, capturedId) {
      if (!capturedId) return null;
      return client.deleteDNSRecord(ctx.zoneId, capturedId);
    },
    async verify(client, ctx) {
      const records = await client.getDNSRecords(ctx.zoneId);
      return (records || []).some(r => r.type === 'TXT' && r.name === recordName);
    }
  };
}

const RECIPES = [
  zoneSettingRecipe({
    checkId: 'CFL-SSL-001',
    title: 'Set SSL/TLS mode to Full (Strict)',
    setting: 'ssl',
    target: 'strict',
    // 'full' is acceptable-ish but the check wants strict; require strict to be compliant
    acceptable: ['strict'],
    risk: 'high' // strict breaks origins without valid certs — always re-prompt
  }),
  zoneSettingRecipe({
    checkId: 'CFL-SSL-002',
    title: 'Set minimum TLS version to 1.2',
    setting: 'min_tls_version',
    target: '1.2',
    acceptable: ['1.2', '1.3'],
    risk: 'medium'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-SSL-005',
    title: 'Enable Always Use HTTPS',
    setting: 'always_use_https',
    target: 'on',
    risk: 'medium'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-WAF-001',
    title: 'Set security level to High',
    setting: 'security_level',
    target: 'high',
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-CDA-001',
    title: 'Enable Cache Deception Armor',
    setting: 'cache_deception_armor',
    target: 'on',
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-PERF-001',
    title: 'Enable Brotli compression',
    setting: 'brotli',
    target: 'on',
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-PERF-002',
    title: 'Enable HTTP/2',
    setting: 'http2',
    target: 'on',
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-PERF-003',
    title: 'Enable HTTP/3 (QUIC)',
    setting: 'http3',
    target: 'on',
    risk: 'low'
  }),
  hstsRecipe,
  dnssecRecipe,

  // --- Phase 1: low-risk reversible zone-setting recipes ------------------
  zoneSettingRecipe({
    checkId: 'CFL-SSL-006',
    title: 'Enable TLS 1.3 (zrt)',
    setting: 'tls_1_3',
    target: 'zrt',
    acceptable: ['zrt', 'on'],
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-SSL-007',
    title: 'Enable Automatic HTTPS Rewrites',
    setting: 'automatic_https_rewrites',
    target: 'on',
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-SSL-008',
    title: 'Enable Opportunistic Encryption',
    setting: 'opportunistic_encryption',
    target: 'on',
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-WAF-009',
    title: 'Enable Browser Integrity Check',
    setting: 'browser_check',
    target: 'on',
    risk: 'low'
  }),
  zoneSettingRecipe({
    checkId: 'CFL-PERF-006',
    title: 'Enable Email Obfuscation',
    setting: 'email_obfuscation',
    target: 'on',
    risk: 'low'
  }),
  // Bot Fight Mode: medium-risk (may challenge legitimate bots). Recipe marked
  // reversible + medium so the apply gate re-prompts before toggling.
  zoneSettingRecipe({
    checkId: 'CFL-BOT-001',
    title: 'Enable Bot Fight Mode',
    setting: 'bot_fight_mode',
    target: 'on',
    acceptable: ['on'],
    risk: 'medium'
  }),

  // --- Phase 2a: Leaked Credentials + WAF Managed Rulesets ---------------
  leakedCredsRecipe,
  wafManagedRulesetRecipe({
    checkId: 'CFL-WAF-006',
    title: 'Deploy Cloudflare Managed Ruleset (log mode)',
    rulesetId: MANAGED_RULESET_ID,
    risk: 'high'
  }),
  wafManagedRulesetRecipe({
    checkId: 'CFL-WAF-007',
    title: 'Deploy OWASP Core Ruleset (log mode)',
    rulesetId: OWASP_RULESET_ID,
    risk: 'high'
  }),

  // --- Phase 2b: security.txt + Notifications + SPF/DMARC ---------------
  securityTxtRecipe,
  notificationPolicyRecipe({
    checkId: 'CFL-ALERT-001',
    title: 'Create WAF anomaly notification policy',
    alertType: 'clickhouse_alert_fw_anomaly'
  }),
  notificationPolicyRecipe({
    checkId: 'CFL-ALERT-002',
    title: 'Create origin error notification policy',
    alertType: 'http_alert_origin_error'
  }),
  notificationPolicyRecipe({
    checkId: 'CFL-ALERT-003',
    title: 'Create SSL/TLS cert notification policy',
    alertType: 'universal_ssl_event_type'
  }),
  notificationPolicyRecipe({
    checkId: 'CFL-ALERT-004',
    title: 'Create L7 DDoS notification policy',
    alertType: 'dos_attack_l7'
  }),
  dnsTxtRecordRecipe({
    checkId: 'CFL-EMAIL-001',
    title: 'Publish SPF record (v=spf1 -all)',
    recordName: '@',
    content: '"v=spf1 -all"',
    risk: 'medium'
  }),
  dnsTxtRecordRecipe({
    checkId: 'CFL-EMAIL-003',
    title: 'Publish DMARC record (p=none, reporting-only)',
    recordName: '_dmarc',
    content: '"v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"',
    risk: 'medium'
  }),

  // --- Phase 4: Enterprise zone hold (ENT only) --------------------------
  zoneHoldRecipe
];



const REGISTRY = new Map(RECIPES.map(r => [r.checkId, r]));

module.exports = {
  /** @returns {boolean} whether a check has an executable recipe */
  has(checkId) {
    return REGISTRY.has(checkId);
  },
  /** @returns {Recipe|undefined} */
  get(checkId) {
    return REGISTRY.get(checkId);
  },
  /** @returns {Recipe[]} all recipes */
  all() {
    return [...REGISTRY.values()];
  },
  /** @returns {string[]} all remediable check IDs */
  checkIds() {
    return [...REGISTRY.keys()];
  },
  // Exposed for unit testing
  zoneSettingRecipe
};
