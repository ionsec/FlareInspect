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

// ---- Phase 2-4 mocks --------------------------------------------------------

const mockLeakedCredChecks = { enabled: false };

const mockRulesetFirewallManaged = {
  id: 'ruleset-001',
  name: 'default',
  kind: 'zone',
  phase: 'http_request_firewall_managed',
  rules: [
    { id: 'rule-001', action: 'execute', expression: 'true', action_parameters: { id: '4814384a9e5d4991b9815dcfc25d2f1f' } }
  ]
};

const mockRulesetFirewallManagedEmpty = {
  id: 'ruleset-002',
  name: 'default',
  kind: 'zone',
  phase: 'http_request_firewall_managed',
  rules: []
};

const mockDDoSL7Ruleset = {
  id: 'ruleset-003',
  name: 'default',
  phase: 'ddos_l7',
  rules: [{ id: 'rule-001', action: 'execute', expression: 'true', action_parameters: { id: 'managed-l7' } }]
};

const mockAccountRulesets = [
  { id: 'acct-ruleset-001', name: 'shared-corp', kind: 'custom', phase: 'http_request_firewall_custom' },
  { id: 'acct-ruleset-002', name: 'shared-rate', kind: 'custom', phase: 'http_ratelimit' }
];

const mockNotificationPolicies = [
  { id: 'np-001', name: 'WAF spike', enabled: true, alert_type: 'clickhouse_alert_fw_anomaly', mechanisms: { email: [{ id: 'me-001' }] } },
  { id: 'np-002', name: 'Origin error', enabled: true, alert_type: 'http_alert_origin_error', mechanisms: { email: [{ id: 'me-001' }] } }
];

const mockAvailableAlerts = [
  { id: 'clickhouse_alert_fw_anomaly', name: 'WAF anomalies', category: 'security' },
  { id: 'http_alert_origin_error', name: 'Origin errors', category: 'availability' },
  { id: 'universal_ssl_event_type', name: 'Universal SSL events', category: 'ssl' },
  { id: 'dos_attack_l7', name: 'L7 DDoS attack', category: 'security' }
];

const mockZoneHold = { hold: false, hold_after: null, include_subdomains: null };

const mockWorkersScripts = [
  { id: 'worker-001', name: 'api-edge', created_on: '2025-01-15T10:00:00Z', modified_on: '2025-06-01T10:00:00Z' },
  { id: 'worker-002', name: 'image-resizer', created_on: '2025-02-15T10:00:00Z', modified_on: '2025-06-02T10:00:00Z' }
];

const mockWorkersBindingsApiEdge = [
  { type: 'plain_text', name: 'API_KEY', text: 'sk-test-1234567890abcdef' },
  { type: 'secret_text', name: 'DB_PASS', text: '' },
  { type: 'kv_namespace', name: 'CACHE', namespace_id: 'kv-001' }
];

const mockWorkersRoutes = [
  { id: 'route-001', pattern: 'api.example.com/*', script: 'api-edge' }
];

const mockKVNamespaces = [
  { id: 'kv-001', title: 'CACHE', supports_url_encoding: true },
  { id: 'kv-002', title: 'SESSIONS', supports_url_encoding: false }
];

const mockD1Databases = [
  { uuid: 'd1-001', name: 'app-db', created_at: '2025-01-01T00:00:00Z', version: 'production' }
];

const mockQueues = [
  { queue_id: 'q-001', queue_name: 'events', created_on: '2025-01-01T00:00:00Z', consumers_total_count: 1, producers_total_count: 1 }
];

const mockZarazConfig = {
  settings: { autoInjectScript: true },
  tools: { ga4: { name: 'GA4' } },
  triggers: { pageview: { name: 'Page view' } },
  consent: { enabled: false }
};

const mockZarazConfigNoConsent = {
  settings: { autoInjectScript: true },
  tools: { ga4: { name: 'GA4' }, facebook: { name: 'Facebook Pixel' } },
  triggers: { pageview: { name: 'Page view' } }
};

const mockDevicePosture = [
  { id: 'posture-001', name: 'Disk encryption', type: 'disk_encryption' },
  { id: 'posture-002', name: 'OS version', type: 'os_version' }
];

const mockAccessApplications = [
  {
    id: 'app-001',
    name: 'Admin Console',
    type: 'self_hosted',
    session_duration: '24h',
    policies: [{ id: 'pol-001', name: 'Admins', decision: 'allow', include: [{ email: ['admin@example.com'] }], require: [{ email: true }] }]
  },
  {
    id: 'app-002',
    name: 'Internal Wiki',
    type: 'self_hosted',
    session_duration: '24h',
    policies: [{ id: 'pol-002', name: 'Everyone', decision: 'allow', include: [{ everyone: {} }] }]
  }
];

const mockCASBFindings = [
  { id: 'casb-001', integration: 'gsuite', severity: 'high', status: 'open', type: 'misconfigured_2fa' },
  { id: 'casb-002', integration: 'gsuite', severity: 'medium', status: 'open', type: 'public_file_share' }
];

const mockEmailSecurityPolicies = [
  { id: 'esp-001', name: 'Anti-spoof', enabled: true },
  { id: 'esp-002', name: 'Phishing protection', enabled: true }
];

const mockBrowserIsolationPolicies = [
  { id: 'iso-001', name: 'Isolate uncat uploads', action: 'isolate', filters: ['uploads'] }
];

const mockMagicFirewallRulesets = [
  { id: 'mf-001', name: 'default', phase: 'magic_transit', rules: [{ id: 'mfr-001', action: 'block' }] }
];

const mockEntAccount = { id: 'ent-account-001', name: 'Enterprise Test Account', type: 'standard', plan: { name: 'Enterprise' } };
const mockEntZones = [{ id: 'ent-zone-001', name: 'ent.example.com', status: 'active', plan: { name: 'Enterprise' } }];

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
  mockEmailRouting,
  mockLeakedCredChecks,
  mockRulesetFirewallManaged,
  mockRulesetFirewallManagedEmpty,
  mockDDoSL7Ruleset,
  mockAccountRulesets,
  mockNotificationPolicies,
  mockAvailableAlerts,
  mockZoneHold,
  mockWorkersScripts,
  mockWorkersBindingsApiEdge,
  mockWorkersRoutes,
  mockKVNamespaces,
  mockD1Databases,
  mockQueues,
  mockZarazConfig,
  mockZarazConfigNoConsent,
  mockDevicePosture,
  mockAccessApplications,
  mockCASBFindings,
  mockEmailSecurityPolicies,
  mockBrowserIsolationPolicies,
  mockMagicFirewallRulesets,
  mockEntAccount,
  mockEntZones
};
