/**
 * @fileoverview Mocked Cloudflare API responses for testing
 * @module tests/mocks/cloudflareResponses
 */

const mockAccount = {
  id: 'test-account-001',
  name: 'Test Account',
  type: 'standard'
};

const mockZones = [
  { id: 'zone-001', name: 'example.com', status: 'active', plan: { name: 'Pro' } },
  { id: 'zone-002', name: 'staging.example.com', status: 'active', plan: { name: 'Free' } }
];

const mockMembers = [
  { id: 'member-001', user: { email: 'admin@example.com', two_factor_authentication_enabled: true }, roles: [{ name: 'Administrator' }] },
  { id: 'member-002', user: { email: 'user@example.com', two_factor_authentication_enabled: false }, roles: [{ name: 'Editor' }] }
];

const mockAuditLogs = [
  { id: 'log-001', action: 'login', actor: { email: 'admin@example.com' }, when: new Date().toISOString() }
];

const mockDNSRecords = [
  { id: 'dns-001', type: 'A', name: 'example.com', content: '1.2.3.4', proxied: true },
  { id: 'dns-002', type: 'A', name: 'direct.example.com', content: '5.6.7.8', proxied: false },
  { id: 'dns-003', type: 'MX', name: 'example.com', content: 'mail.example.com', proxied: false }
];

const mockDNSSECSettings = { status: 'active' };

const mockSSLSettings = {
  settings: { value: 'strict' },
  certificates: [{ id: 'cert-001', status: 'active', expires_on: new Date(Date.now() + 90 * 86400000).toISOString() }]
};

const mockZoneSettings = {
  security_level: { value: 'high' },
  always_use_https: { value: 'on' },
  min_tls_version: { value: '1.2' },
  security_header: { value: { strict_transport_security: { enabled: true, max_age: 31536000, include_subdomains: true } } }
};

const mockWAFSettings = { security_level: 'high' };
const mockFirewallRules = [{ id: 'fw-001', action: 'block', filter: { expression: 'ip eq 1.2.3.4' } }];
const mockRateLimitRules = [{ id: 'rl-001', threshold: 100, period: 60, action: 'block' }];
const mockRulesets = [{ id: 'rs-001', phase: 'http_request_firewall', rules: [] }];

const mockBotManagement = { enabled: true, fight_mode: true };

const mockZeroTrustSettings = {
  identity_providers: [{ id: 'idp-001', type: 'okta', name: 'Corporate Okta' }],
  access_policies: [{ id: 'pol-001', name: 'Default Policy', action: 'allow' }],
  device_rules: { enabled: true, rules: [] },
  dlp: { enabled: true, profiles: [] },
  gateway: { dns: [{ id: 'gw-001', action: 'block' }], http: [] }
};

const mockWorkers = { workers: [{ id: 'worker-001', name: 'api-proxy' }] };
const mockPages = { projects: [{ id: 'page-001', name: 'marketing-site' }] };

const mockSecurityInsights = {
  insights: [],
  summary: { total: 0, bySeverity: { critical: 0, high: 0, moderate: 0, low: 0 } }
};

const mockDLP = { profiles: [{ id: 'dlp-001', name: 'PII Detection' }], rules: [{ id: 'dlp-rule-001', action: 'block' }] };
const mockTunnels = [{ id: 'tunnel-001', name: 'production', status: 'active' }];
const mockGatewayPolicies = { dns: [{ id: 'gw-001' }], http: [{ id: 'gw-002' }], l4: [] };
const mockAIGateway = [{ id: 'aigw-001', name: 'llm-proxy' }];
const mockDevicePolicy = { enabled: true, require_posture: true };

const mockPageShield = { enabled: true, status: 'active' };
const mockCacheDeceptionArmor = { enabled: true, status: 'active' };
const mockSnippets = [];
const mockCustomHostnames = [{ id: 'ch-001', hostname: 'app.example.com', status: 'active', ssl: { status: 'active' } }];
const mockOriginCertificates = [{ id: 'oc-001', expires_on: new Date(Date.now() + 180 * 86400000).toISOString() }];

const mockAPIShield = { enabled: true, source: 'legacy' };
const mockAPIGateway = { enabled: true, schemas: [{ id: 'schema-001' }], operations: [], schemaValidation: { enabled: true } };
const mockSecurityTxt = { enabled: true };
const mockLogpushJobs = [{ id: 'lp-001', dataset: 'firewall_events', enabled: true }];
const mockAccessCertificates = [{ id: 'ac-001', expires_on: new Date(Date.now() + 365 * 86400000).toISOString() }];
const mockMtlsCertificates = [{ id: 'mtls-001', expires_on: new Date(Date.now() + 300 * 86400000).toISOString() }];
const mockAttackSurface = { issues: [], count: 0 };
const mockTurnstileWidgets = [{ id: 'ts-001', name: 'Login Widget' }];
const mockDNSFirewall = [{ id: 'df-001' }];
const mockLoadBalancers = { load_balancers: [{ id: 'lb-001', enabled: true }] };
const mockEmailRouting = [{ id: 'er-001', match: 'catch-all', action: 'forward' }];

module.exports = {
  mockAccount,
  mockZones,
  mockMembers,
  mockAuditLogs,
  mockDNSRecords,
  mockDNSSECSettings,
  mockSSLSettings,
  mockZoneSettings,
  mockWAFSettings,
  mockFirewallRules,
  mockRateLimitRules,
  mockRulesets,
  mockBotManagement,
  mockZeroTrustSettings,
  mockWorkers,
  mockPages,
  mockSecurityInsights,
  mockDLP,
  mockTunnels,
  mockGatewayPolicies,
  mockAIGateway,
  mockDevicePolicy,
  mockPageShield,
  mockCacheDeceptionArmor,
  mockSnippets,
  mockCustomHostnames,
  mockOriginCertificates,
  mockAPIShield,
  mockAPIGateway,
  mockSecurityTxt,
  mockLogpushJobs,
  mockAccessCertificates,
  mockMtlsCertificates,
  mockAttackSurface,
  mockTurnstileWidgets,
  mockDNSFirewall,
  mockLoadBalancers,
  mockEmailRouting
};
