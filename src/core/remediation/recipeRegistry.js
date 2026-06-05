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
  })
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
