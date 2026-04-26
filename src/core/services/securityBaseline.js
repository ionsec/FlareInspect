/**
 * @fileoverview Security Baseline Service for FlareInspect
 * @description Defines security checks and baselines for Cloudflare assessments
 * @module core/services/securityBaseline
 */

const { randomUUID: uuidv4 } = require('crypto');

class SecurityBaseline {
  constructor() {
    this.checks = this.initializeChecks();
  }

  /**
   * Initialize all security checks
   */
  initializeChecks() {
    return [
      // Account Security Checks
      {
        id: 'CFL-ACC-001',
        category: 'account',
        title: 'Multi-Factor Authentication (MFA) Enforcement',
        description: 'Ensure all account members have MFA enabled',
        severity: 'critical',
        compliance: ['SOC2', 'ISO27001', 'NIST']
      },
      {
        id: 'CFL-ACC-002',
        category: 'account',
        title: 'API Token Security',
        description: 'Regular audit and rotation of API tokens',
        severity: 'high',
        compliance: ['SOC2', 'ISO27001']
      },
      {
        id: 'CFL-ACC-003',
        category: 'account',
        title: 'Admin Access Control',
        description: 'Limit number of admin users',
        severity: 'high',
        compliance: ['SOC2', 'ISO27001', 'NIST']
      },
      {
        id: 'CFL-ACC-004',
        category: 'account',
        title: 'Audit Log Monitoring',
        description: 'Enable and monitor audit logs',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001', 'PCI-DSS']
      },
      {
        id: 'CFL-ACC-005',
        category: 'account',
        title: 'Account Takeover Protection',
        description: 'Enable Super Administrator protection',
        severity: 'high',
        compliance: ['SOC2', 'NIST']
      },

      // DNS Security Checks
      {
        id: 'CFL-DNS-001',
        category: 'dns',
        title: 'DNSSEC Enablement',
        description: 'Enable DNSSEC for all zones',
        severity: 'high',
        compliance: ['NIST', 'CIS']
      },
      {
        id: 'CFL-DNS-002',
        category: 'dns',
        title: 'DNS Proxy Status',
        description: 'Enable proxy for security-sensitive records',
        severity: 'medium',
        compliance: ['CIS']
      },
      {
        id: 'CFL-DNS-003',
        category: 'dns',
        title: 'Wildcard DNS Records',
        description: 'Minimize use of wildcard DNS records',
        severity: 'low',
        compliance: ['CIS']
      },
      {
        id: 'CFL-DNS-004',
        category: 'dns',
        title: 'CAA Records',
        description: 'Configure CAA records for certificate authority authorization',
        severity: 'medium',
        compliance: ['CIS', 'NIST']
      },

      // SSL/TLS Security Checks
      {
        id: 'CFL-SSL-001',
        category: 'ssl',
        title: 'SSL Mode Configuration',
        description: 'Use Full or Strict SSL mode',
        severity: 'high',
        compliance: ['SOC2', 'PCI-DSS', 'NIST']
      },
      {
        id: 'CFL-SSL-002',
        category: 'ssl',
        title: 'Minimum TLS Version',
        description: 'Set minimum TLS version to 1.2 or higher',
        severity: 'high',
        compliance: ['PCI-DSS', 'NIST', 'CIS']
      },
      {
        id: 'CFL-SSL-003',
        category: 'ssl',
        title: 'Certificate Validity',
        description: 'Monitor SSL certificate expiration',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001']
      },
      {
        id: 'CFL-SSL-004',
        category: 'ssl',
        title: 'HSTS Configuration',
        description: 'Enable HTTP Strict Transport Security',
        severity: 'high',
        compliance: ['NIST', 'CIS', 'OWASP']
      },
      {
        id: 'CFL-SSL-005',
        category: 'ssl',
        title: 'Always Use HTTPS',
        description: 'Enable automatic HTTPS rewrites',
        severity: 'medium',
        compliance: ['PCI-DSS', 'NIST']
      },

      // WAF Security Checks
      {
        id: 'CFL-WAF-001',
        category: 'waf',
        title: 'WAF Security Level',
        description: 'Set appropriate WAF security level',
        severity: 'high',
        compliance: ['PCI-DSS', 'OWASP']
      },
      {
        id: 'CFL-WAF-002',
        category: 'waf',
        title: 'Custom Firewall Rules',
        description: 'Implement custom firewall rules for protection',
        severity: 'medium',
        compliance: ['SOC2', 'OWASP']
      },
      {
        id: 'CFL-WAF-003',
        category: 'waf',
        title: 'Rate Limiting',
        description: 'Configure rate limiting rules',
        severity: 'medium',
        compliance: ['OWASP', 'CIS']
      },
      {
        id: 'CFL-WAF-004',
        category: 'waf',
        title: 'Bot Management',
        description: 'Enable bot management features',
        severity: 'medium',
        compliance: ['OWASP']
      },
      {
        id: 'CFL-WAF-005',
        category: 'waf',
        title: 'OWASP Rule Set',
        description: 'Enable OWASP ModSecurity Core Rule Set',
        severity: 'high',
        compliance: ['OWASP', 'PCI-DSS']
      },

      // Zero Trust Security Checks
      {
        id: 'CFL-ZT-001',
        category: 'zerotrust',
        title: 'Identity Provider Configuration',
        description: 'Configure identity providers for authentication',
        severity: 'high',
        compliance: ['SOC2', 'NIST']
      },
      {
        id: 'CFL-ZT-002',
        category: 'zerotrust',
        title: 'Access Policies',
        description: 'Define granular access policies',
        severity: 'high',
        compliance: ['SOC2', 'NIST', 'ISO27001']
      },
      {
        id: 'CFL-ZT-003',
        category: 'zerotrust',
        title: 'Device Enrollment Rules',
        description: 'Configure device enrollment rules for Zero Trust',
        severity: 'medium',
        compliance: ['SOC2', 'NIST']
      },
      {
        id: 'CFL-ZT-004',
        category: 'zerotrust',
        title: 'Gateway Firewall Rules',
        description: 'Configure Gateway filtering rules for network security',
        severity: 'medium',
        compliance: ['SOC2', 'NIST']
      },
      {
        id: 'CFL-ZT-005',
        category: 'zerotrust',
        title: 'Data Loss Prevention',
        description: 'Configure DLP profiles to prevent data leakage',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001', 'PCI-DSS']
      },
      {
        id: 'CFL-ZT-006',
        category: 'zerotrust',
        title: 'Service Token Rotation',
        description: 'Regular rotation of service tokens',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001']
      },

      // Performance Security Checks
      {
        id: 'CFL-PERF-001',
        category: 'performance',
        title: 'Brotli Compression',
        description: 'Enable Brotli compression for better performance',
        severity: 'medium',
        compliance: ['CIS']
      },
      {
        id: 'CFL-PERF-002',
        category: 'performance',
        title: 'HTTP/2 Protocol',
        description: 'Enable HTTP/2 for improved performance',
        severity: 'medium',
        compliance: ['CIS']
      },
      {
        id: 'CFL-PERF-003',
        category: 'performance',
        title: 'HTTP/3 Protocol',
        description: 'Enable HTTP/3 (QUIC) for optimal performance',
        severity: 'low',
        compliance: ['CIS']
      },
      {
        id: 'CFL-PERF-004',
        category: 'performance',
        title: 'Content Minification',
        description: 'Enable minification for JS, CSS, and HTML',
        severity: 'low',
        compliance: ['CIS']
      },
      {
        id: 'CFL-PERF-005',
        category: 'performance',
        title: 'Rocket Loader',
        description: 'Consider enabling Rocket Loader for JavaScript optimization',
        severity: 'informational',
        compliance: ['CIS']
      },

      // Workers Security Checks
      {
        id: 'CFL-WORK-001',
        category: 'workers',
        title: 'Worker Error Handling',
        description: 'Implement proper error handling in Workers',
        severity: 'medium',
        compliance: ['OWASP']
      },
      {
        id: 'CFL-WORK-002',
        category: 'workers',
        title: 'Worker Rate Limiting',
        description: 'Implement rate limiting in Workers',
        severity: 'medium',
        compliance: ['OWASP']
      },

      // Bot Management Checks
      {
        id: 'CFL-BOT-001',
        category: 'bot',
        title: 'Bot Fight Mode',
        description: 'Enable Bot Fight Mode to protect against malicious bots',
        severity: 'medium',
        compliance: ['OWASP']
      },

      // API Shield Checks
      {
        id: 'CFL-API-001',
        category: 'api',
        title: 'API Shield Configuration',
        description: 'Configure API Shield for API endpoint protection',
        severity: 'medium',
        compliance: ['OWASP']
      },
      {
        id: 'CFL-API-002',
        category: 'api',
        title: 'API Schema Validation',
        description: 'Upload API schemas for request validation',
        severity: 'low',
        compliance: ['OWASP']
      },

      // Load Balancing Checks
      {
        id: 'CFL-LB-001',
        category: 'loadbalancing',
        title: 'Health Check Configuration',
        description: 'Configure health checks for load balancer pools',
        severity: 'high',
        compliance: ['CIS']
      },
      {
        id: 'CFL-LB-002',
        category: 'loadbalancing',
        title: 'Session Affinity',
        description: 'Configure session affinity when needed',
        severity: 'low',
        compliance: ['CIS']
      },

      // Pages Security Checks
      {
        id: 'CFL-PAGE-001',
        category: 'pages',
        title: 'Environment Variable Security',
        description: 'Secure sensitive data in environment variables',
        severity: 'high',
        compliance: ['OWASP', 'SOC2']
      },
      {
        id: 'CFL-PAGE-002',
        category: 'pages',
        title: 'Build Configuration',
        description: 'Configure appropriate build commands',
        severity: 'low',
        compliance: ['CIS']
      },

      // Email Security Checks
      {
        id: 'CFL-EMAIL-001',
        category: 'email',
        title: 'SPF Record',
        description: 'Configure SPF record for email authentication',
        severity: 'high',
        compliance: ['CIS', 'NIST']
      },
      {
        id: 'CFL-EMAIL-002',
        category: 'email',
        title: 'DKIM Records',
        description: 'Configure DKIM records for email authentication',
        severity: 'medium',
        compliance: ['CIS', 'NIST']
      },
      {
        id: 'CFL-EMAIL-003',
        category: 'email',
        title: 'DMARC Record',
        description: 'Configure DMARC record for email policy enforcement',
        severity: 'high',
        compliance: ['CIS', 'NIST']
      },

      // security.txt Checks
      {
        id: 'CFL-SEC-001',
        category: 'securitytxt',
        title: 'security.txt Enabled',
        description: 'Publish a security.txt file for vulnerability disclosure',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001', 'NIST']
      },
      {
        id: 'CFL-SEC-002',
        category: 'securitytxt',
        title: 'security.txt Required Fields',
        description: 'security.txt should include contact, policy, and expires fields',
        severity: 'low',
        compliance: ['SOC2', 'ISO27001']
      },

      // Turnstile Checks
      {
        id: 'CFL-TURN-001',
        category: 'turnstile',
        title: 'Turnstile Widget Configuration',
        description: 'Configure Turnstile widgets for human verification',
        severity: 'low',
        compliance: ['OWASP']
      },

      // DNS Firewall Checks
      {
        id: 'CFL-DNS-005',
        category: 'dns-firewall',
        title: 'DNS Firewall Policies',
        description: 'Configure DNS Firewall policies to protect upstream resolvers',
        severity: 'medium',
        compliance: ['NIST', 'CIS']
      },

      // Logpush Checks
      {
        id: 'CFL-LOG-001',
        category: 'logpush',
        title: 'Security Logpush Datasets',
        description: 'Stream security-relevant logs for monitoring and response',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001', 'NIST']
      },

      // mTLS Checks
      {
        id: 'CFL-MTLS-001',
        category: 'mtls',
        title: 'mTLS Certificate Configuration',
        description: 'Configure mTLS or Access certificates for sensitive services',
        severity: 'medium',
        compliance: ['SOC2', 'NIST']
      },
      {
        id: 'CFL-MTLS-002',
        category: 'mtls',
        title: 'mTLS Certificate Expiry',
        description: 'Monitor mTLS certificates for upcoming expiration',
        severity: 'high',
        compliance: ['SOC2', 'ISO27001']
      },

      // Attack Surface Report Checks
      {
        id: 'CFL-ASM-001',
        category: 'attack-surface',
        title: 'Critical Attack Surface Issues',
        description: 'No critical attack surface issues should be present',
        severity: 'critical',
        compliance: ['SOC2', 'ISO27001', 'NIST']
      },
      {
        id: 'CFL-ASM-002',
        category: 'attack-surface',
        title: 'Moderate Attack Surface Issues',
        description: 'Minimize moderate and low attack surface issues',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001']
      },

      // Security Insights Checks
      {
        id: 'CFL-INSIGHT-001',
        category: 'security-insights',
        title: 'Critical Security Insights',
        description: 'No critical security insights should be present',
        severity: 'critical',
        compliance: ['SOC2', 'ISO27001', 'NIST']
      },
      {
        id: 'CFL-INSIGHT-002',
        category: 'security-insights',
        title: 'High Security Insights',
        description: 'Minimize high severity security insights',
        severity: 'high',
        compliance: ['SOC2', 'ISO27001', 'NIST']
      },
      {
        id: 'CFL-INSIGHT-003',
        category: 'security-insights',
        title: 'Security Center Monitoring',
        description: 'Actively monitor and address Security Center insights',
        severity: 'medium',
        compliance: ['SOC2', 'ISO27001']
      },
      {
        id: 'CFL-INSIGHT-004',
        category: 'security-insights',
        title: 'Exposed Credentials',
        description: 'No exposed credentials should be detected',
        severity: 'critical',
        compliance: ['SOC2', 'PCI-DSS', 'NIST']
      },
      {
        id: 'CFL-INSIGHT-005',
        category: 'security-insights',
        title: 'Origin IP Exposure',
        description: 'Origin IP addresses should not be exposed',
        severity: 'high',
        compliance: ['SOC2', 'NIST']
      },
      {
        id: 'CFL-DLP-001',
        category: 'dlp',
        title: 'DLP Configuration',
        description: 'Configure Data Loss Prevention profiles and rules',
        severity: 'high',
        compliance: ['SOC2', 'PCI-DSS', 'NIST']
      },
      {
        id: 'CFL-PAGESHIELD-001',
        category: 'page-shield',
        title: 'Page Shield Enablement',
        description: 'Enable Page Shield to monitor JavaScript dependencies',
        severity: 'high',
        compliance: ['OWASP', 'NIST']
      },
      {
        id: 'CFL-TUNNEL-001',
        category: 'tunnels',
        title: 'Cloudflare Tunnel Configuration',
        description: 'Use Cloudflare Tunnels to expose services without open ingress ports',
        severity: 'high',
        compliance: ['CIS', 'NIST']
      },
      {
        id: 'CFL-GW-001',
        category: 'gateway',
        title: 'Gateway Policy Configuration',
        description: 'Configure DNS and HTTP gateway policies for Zero Trust filtering',
        severity: 'high',
        compliance: ['SOC2', 'NIST']
      },
      {
        id: 'CFL-SPECTRUM-001',
        category: 'spectrum',
        title: 'Spectrum Application Protection',
        description: 'Secure Spectrum applications with proper TLS and access controls',
        severity: 'medium',
        compliance: ['CIS']
      },
      {
        id: 'CFL-AIGW-001',
        category: 'ai-gateway',
        title: 'AI Gateway Security',
        description: 'Configure AI Gateway to monitor and control LLM API calls',
        severity: 'medium',
        compliance: ['NIST']
      },
      {
        id: 'CFL-CDA-001',
        category: 'cache',
        title: 'Cache Deception Armor',
        description: 'Enable Cache Deception Armor to prevent web cache deception attacks',
        severity: 'high',
        compliance: ['OWASP']
      },
      {
        id: 'CFL-SNIPPET-001',
        category: 'snippets',
        title: 'Snippets Security Review',
        description: 'Review edge snippets for security-sensitive code patterns',
        severity: 'medium',
        compliance: ['SOC2']
      },
      {
        id: 'CFL-CH-001',
        category: 'custom-hostnames',
        title: 'Custom Hostname Validation',
        description: 'Validate custom hostname certificates and ownership',
        severity: 'medium',
        compliance: ['PCI-DSS']
      },
      {
        id: 'CFL-ORIGCERT-001',
        category: 'ssl',
        title: 'Origin Certificate Expiry',
        description: 'Monitor origin certificates for impending expiration',
        severity: 'critical',
        compliance: ['PCI-DSS', 'SOC2']
      },
      {
        id: 'CFL-CFRULE-001',
        category: 'rules',
        title: 'Configuration Rules Review',
        description: 'Review configuration rules for unintended security overrides',
        severity: 'medium',
        compliance: ['SOC2']
      },
      {
        id: 'CFL-TXRULE-001',
        category: 'rules',
        title: 'Transform Rules Security',
        description: 'Review URL rewrite and header modification rules for security implications',
        severity: 'medium',
        compliance: ['OWASP']
      },
      {
        id: 'CFL-DEVICE-001',
        category: 'zerotrust',
        title: 'Device Enrollment Policy',
        description: 'Configure device enrollment and posture checks for Zero Trust',
        severity: 'high',
        compliance: ['SOC2', 'NIST']
      },

      // API Token Pre-flight (1.2.2)
      {
        id: 'CFL-TOK-001',
        category: 'token',
        title: 'API Token Active and Valid',
        description: 'Verify the API token used for the assessment is active and not expired',
        severity: 'critical',
        compliance: ['SOC2', 'ISO27001']
      },

      // R2 Object Storage (1.2.2)
      {
        id: 'CFL-R2-001',
        category: 'r2',
        title: 'R2 Bucket Public Access',
        description: 'Detect R2 buckets exposed via public custom domains or permissive CORS policies',
        severity: 'high',
        compliance: ['SOC2', 'PCI-DSS', 'ISO27001']
      },
      {
        id: 'CFL-R2-002',
        category: 'r2',
        title: 'R2 Bucket Lifecycle Policies',
        description: 'Verify object lifecycle rules are configured for retention and cost control',
        severity: 'low',
        compliance: ['SOC2']
      },
      {
        id: 'CFL-R2-003',
        category: 'r2',
        title: 'R2 Bucket Event Notifications',
        description: 'Verify event notifications are configured so writes/deletes are auditable',
        severity: 'low',
        compliance: ['SOC2', 'NIST']
      },

      // WAF Managed Rulesets (1.2.2)
      {
        id: 'CFL-WAF-006',
        category: 'waf',
        title: 'Cloudflare Managed Ruleset Enabled',
        description: 'Ensure the Cloudflare Managed Ruleset is deployed at zone scope',
        severity: 'high',
        compliance: ['OWASP', 'CIS', 'NIST']
      },
      {
        id: 'CFL-WAF-007',
        category: 'waf',
        title: 'OWASP Core Ruleset Enabled',
        description: 'Ensure the Cloudflare OWASP Core Ruleset is deployed at zone scope',
        severity: 'high',
        compliance: ['OWASP', 'CIS']
      },
      {
        id: 'CFL-WAF-008',
        category: 'waf',
        title: 'WAF Managed Rulesets Not in Log-Only Mode',
        description: 'Detect production zones where managed rulesets are still in log-only mode (drift)',
        severity: 'medium',
        compliance: ['OWASP', 'NIST']
      }

    ];
  }

  /**
   * Get all security checks
   */
  getAllChecks() {
    return this.checks;
  }

  /**
   * Get checks by category
   */
  getChecksByCategory(category) {
    return this.checks.filter(check => check.category === category);
  }

  /**
   * Get checks by severity
   */
  getChecksBySeverity(severity) {
    return this.checks.filter(check => check.severity === severity);
  }

  /**
   * Get checks by compliance framework
   */
  getChecksByCompliance(framework) {
    return this.checks.filter(check => 
      check.compliance && check.compliance.includes(framework)
    );
  }

  /**
   * Create a finding from a check
   */
  createFinding(check, status, actualValue, expectedValue, resource, options = {}) {
    const metadata = {
      actualValue,
      expectedValue,
      resourceName: resource?.name,
      ...(options.metadata || {})
    };

    const evidence = this.normalizeEvidence({
      summary: options.evidence?.summary || `${check.title}: expected ${expectedValue}, observed ${actualValue}.`,
      expected: options.evidence?.expected ?? expectedValue,
      observed: options.evidence?.observed ?? actualValue,
      affectedEntities: options.evidence?.affectedEntities,
      counts: options.evidence?.counts,
      source: options.evidence?.source || {
        category: check.category,
        checkId: check.id,
        resourceType: resource?.type || 'resource'
      },
      raw: options.evidence?.raw,
      reviewGuidance: options.evidence?.reviewGuidance
    });

    return {
      id: uuidv4(),
      checkId: check.id,
      checkTitle: check.title,
      service: check.category,
      severity: check.severity,
      status: status,
      description: `${check.description}. Expected: ${expectedValue}, Actual: ${actualValue}`,
      remediation: this.getRemediation(check.id),
      resourceId: resource?.id,
      resourceType: resource?.type,
      timestamp: new Date(),
      compliance: check.compliance,
      metadata,
      evidence
    };
  }

  normalizeEvidence(evidence = {}) {
    return {
      summary: evidence.summary || 'No detailed evidence captured.',
      expected: evidence.expected ?? null,
      observed: evidence.observed ?? null,
      affectedEntities: Array.isArray(evidence.affectedEntities) ? evidence.affectedEntities : [],
      counts: evidence.counts && typeof evidence.counts === 'object' ? evidence.counts : {},
      source: evidence.source && typeof evidence.source === 'object' ? evidence.source : {},
      raw: evidence.raw && typeof evidence.raw === 'object' ? evidence.raw : {},
      reviewGuidance: evidence.reviewGuidance || 'Review the affected resource and compare the observed state with the expected baseline.'
    };
  }

  /**
   * Get remediation guidance for a check
   */
  getRemediation(checkId) {
    const remediations = {
      'CFL-ACC-001': 'Navigate to Manage Account > Members and ensure all users have 2FA enabled. Consider using SSO with MFA.',
      'CFL-ACC-002': 'Review API tokens in My Profile > API Tokens. Rotate tokens regularly and use scoped tokens.',
      'CFL-ACC-003': 'Review admin users in Manage Account > Members. Follow principle of least privilege.',
      'CFL-ACC-004': 'Enable audit log export to SIEM or configure alerts for critical actions.',
      'CFL-ACC-005': 'Enable Super Administrator in Manage Account > Configurations.',
      
      'CFL-DNS-001': 'Enable DNSSEC in DNS > Settings for each zone.',
      'CFL-DNS-002': 'Enable proxy (orange cloud) for A, AAAA, and CNAME records where appropriate.',
      'CFL-DNS-003': 'Review wildcard records and replace with specific records where possible.',
      'CFL-DNS-004': 'Add CAA records to specify authorized certificate authorities.',
      
      'CFL-SSL-001': 'Set SSL mode to Full (Strict) in SSL/TLS > Overview.',
      'CFL-SSL-002': 'Set minimum TLS version to 1.2 in SSL/TLS > Edge Certificates.',
      'CFL-SSL-003': 'Monitor certificate expiration in SSL/TLS > Edge Certificates.',
      'CFL-SSL-004': 'Enable HSTS in SSL/TLS > Edge Certificates.',
      'CFL-SSL-005': 'Enable Always Use HTTPS in SSL/TLS > Edge Certificates.',
      
      'CFL-WAF-001': 'Set security level to High in Security > Settings.',
      'CFL-WAF-002': 'Create custom firewall rules in Security > WAF.',
      'CFL-WAF-003': 'Configure rate limiting in Security > Rate Limiting.',
      'CFL-WAF-004': 'Enable Bot Fight Mode in Security > Bots.',
      'CFL-WAF-005': 'Enable managed rulesets in Security > WAF.',
      
      'CFL-ZT-001': 'Configure identity providers in Zero Trust > Settings > Authentication.',
      'CFL-ZT-002': 'Create access policies in Zero Trust > Access > Applications.',
      'CFL-ZT-003': 'Configure device enrollment rules in Zero Trust > Settings > Device enrollment.',
      'CFL-ZT-004': 'Configure Gateway rules in Zero Trust > Gateway > Firewall policies.',
      'CFL-ZT-005': 'Configure DLP profiles in Zero Trust > Data Loss Prevention.',
      'CFL-ZT-006': 'Rotate service tokens regularly in Zero Trust > Access > Service Auth.',
      
      'CFL-PERF-001': 'Enable Brotli compression in Speed > Optimization > Content Optimization.',
      'CFL-PERF-002': 'Enable HTTP/2 in Network settings.',
      'CFL-PERF-003': 'Enable HTTP/3 (QUIC) in Network settings.',
      'CFL-PERF-004': 'Enable minification for JS, CSS, and HTML in Speed > Optimization.',
      'CFL-PERF-005': 'Enable Rocket Loader in Speed > Optimization > Content Optimization.',
      
      'CFL-WORK-001': 'Add try-catch blocks and proper error handling to Workers scripts.',
      'CFL-WORK-002': 'Implement rate limiting logic in Workers using KV or Durable Objects.',
      
      'CFL-BOT-001': 'Enable Bot Fight Mode in Security > Bots.',
      
      'CFL-API-001': 'Configure API Shield in Security > API Shield.',
      'CFL-API-002': 'Upload OpenAPI schemas in Security > API Shield > Schema Validation.',
      
      'CFL-LB-001': 'Configure health checks in Traffic > Load Balancing > Manage Pools.',
      'CFL-LB-002': 'Enable session affinity in Traffic > Load Balancing > Load Balancers.',
      
      'CFL-PAGE-001': 'Use Cloudflare Pages encrypted environment variables for sensitive data.',
      'CFL-PAGE-002': 'Configure build commands in Pages > Settings > Builds & deployments.',
      
      'CFL-EMAIL-001': 'Add SPF TXT record with "v=spf1 include:_spf.mx.cloudflare.net ~all".',
      'CFL-EMAIL-002': 'Configure DKIM in Email > Email Routing > DKIM keys.',
      'CFL-EMAIL-003': 'Add DMARC TXT record at _dmarc subdomain with appropriate policy.',

      'CFL-SEC-001': 'Enable security.txt in Cloudflare Security Center > security.txt.',
      'CFL-SEC-002': 'Add contact, policy, and expires fields to your security.txt.',
      'CFL-TURN-001': 'Create Turnstile widgets in the Cloudflare dashboard and integrate them with your apps.',
      'CFL-DNS-005': 'Configure DNS Firewall policies in Cloudflare Gateway to protect upstream resolvers.',
      'CFL-LOG-001': 'Create Logpush jobs for firewall events, HTTP requests, and DNS logs.',
      'CFL-MTLS-001': 'Configure mTLS certificates in Zero Trust or Access to protect sensitive services.',
      'CFL-MTLS-002': 'Rotate or renew mTLS certificates before expiration.',
      'CFL-ASM-001': 'Address critical attack surface issues reported in Security Center > Attack Surface.',
      'CFL-ASM-002': 'Reduce moderate and low attack surface issues by hardening exposed assets.',
      
      // Security Insights remediations
      'CFL-INSIGHT-001': 'Immediately address all critical security insights in the Cloudflare Security Center dashboard.',
      'CFL-INSIGHT-002': 'Review and resolve high severity insights within 24-48 hours to maintain security posture.',
      'CFL-INSIGHT-003': 'Set up regular reviews of Security Center insights and create processes to address them promptly.',
      'CFL-INSIGHT-004': 'Rotate exposed credentials immediately, review access logs, and implement credential scanning in CI/CD.',
      'CFL-INSIGHT-005': 'Enable Cloudflare proxy (orange cloud) for all DNS records that point to origin servers.',

      // New Cloudflare technology checks
      'CFL-DLP-001': 'Configure DLP profiles and rules in Zero Trust > Data Loss Prevention to detect and prevent sensitive data exfiltration.',
      'CFL-PAGESHIELD-001': 'Enable Page Shield in Security > Page Shield to monitor JavaScript dependencies and detect supply chain attacks.',
      'CFL-TUNNEL-001': 'Replace open ingress ports with Cloudflare Tunnels in Zero Trust > Networks > Tunnels for secure origin connectivity.',
      'CFL-GW-001': 'Configure DNS and HTTP gateway policies in Zero Trust > Gateway to filter and inspect traffic.',
      'CFL-SPECTRUM-001': 'Ensure Spectrum applications use TLS 1.2+ and restrict access with IP allowlists or Access policies.',
      'CFL-AIGW-001': 'Configure AI Gateway to log, rate-limit, and monitor LLM API calls for data leakage and prompt injection.',
      'CFL-CDA-001': 'Enable Cache Deception Armor in Caching > Configuration to prevent web cache deception attacks.',
      'CFL-SNIPPET-001': 'Review edge snippets for hardcoded secrets, insecure redirects, and security-impacting logic.',
      'CFL-CH-001': 'Validate custom hostname certificates and enable hostname fallback origin in SSL/TLS > Custom Hostnames.',
      'CFL-ORIGCERT-001': 'Monitor origin certificate expiration and set up renewal alerts. Expired certificates break Full(Strict) SSL.',
      'CFL-CFRULE-001': 'Review configuration rules to ensure they do not override security settings like WAF or SSL enforcement.',
      'CFL-TXRULE-001': 'Audit URL rewrite and header modification rules for security implications such as removing security headers.',
      'CFL-DEVICE-001': 'Configure device enrollment and posture checks in Zero Trust > Devices to ensure only compliant devices can access resources.',

    };

    return remediations[checkId] || 'Review Cloudflare documentation for remediation steps.';
  }

  /**
   * Calculate security score based on findings
   */
  calculateScore(findings) {
    if (!findings || findings.length === 0) {
      return {
        overallScore: 0,
        grade: 'F',
        breakdown: {}
      };
    }

    const weights = {
      critical: 10,
      high: 7,
      medium: 4,
      low: 2,
      informational: 1
    };

    let totalWeight = 0;
    let passedWeight = 0;
    const breakdown = {};

    // Calculate by category
    const categories = [...new Set(findings.map(f => f.service))];
    
    categories.forEach(category => {
      const categoryFindings = findings.filter(f => f.service === category);
      let categoryTotalWeight = 0;
      let categoryPassedWeight = 0;

      categoryFindings.forEach(finding => {
        const weight = weights[finding.severity] || 1;
        categoryTotalWeight += weight;
        
        if (finding.status === 'PASS') {
          categoryPassedWeight += weight;
        }
      });

      breakdown[category] = {
        score: categoryTotalWeight > 0 ? Math.round((categoryPassedWeight / categoryTotalWeight) * 100) : 0,
        total: categoryFindings.length,
        passed: categoryFindings.filter(f => f.status === 'PASS').length,
        failed: categoryFindings.filter(f => f.status === 'FAIL').length
      };

      totalWeight += categoryTotalWeight;
      passedWeight += categoryPassedWeight;
    });

    const overallScore = totalWeight > 0 ? Math.round((passedWeight / totalWeight) * 100) : 0;
    
    // Calculate grade
    let grade = 'F';
    if (overallScore >= 90) grade = 'A';
    else if (overallScore >= 80) grade = 'B';
    else if (overallScore >= 70) grade = 'C';
    else if (overallScore >= 60) grade = 'D';

    return {
      overallScore,
      grade,
      breakdown,
      totalChecks: findings.length,
      passedChecks: findings.filter(f => f.status === 'PASS').length,
      failedChecks: findings.filter(f => f.status === 'FAIL').length
    };
  }

  /**
   * Get security recommendations based on findings
   */
  getRecommendations(findings) {
    const recommendations = [];
    const failedFindings = findings.filter(f => f.status === 'FAIL');
    
    // Group by severity
    const critical = failedFindings.filter(f => f.severity === 'critical');
    const high = failedFindings.filter(f => f.severity === 'high');
    const medium = failedFindings.filter(f => f.severity === 'medium');

    if (critical.length > 0) {
      recommendations.push({
        priority: 'IMMEDIATE',
        title: 'Critical Security Issues',
        description: `Address ${critical.length} critical security issues immediately`,
        findings: critical
      });
    }

    if (high.length > 0) {
      recommendations.push({
        priority: 'HIGH',
        title: 'High Priority Improvements',
        description: `Fix ${high.length} high severity issues within 7 days`,
        findings: high
      });
    }

    if (medium.length > 0) {
      recommendations.push({
        priority: 'MEDIUM',
        title: 'Security Enhancements',
        description: `Implement ${medium.length} medium severity improvements within 30 days`,
        findings: medium
      });
    }

    // Add category-specific recommendations
    const categories = [...new Set(failedFindings.map(f => f.service))];
    
    categories.forEach(category => {
      const categoryFailures = failedFindings.filter(f => f.service === category);
      if (categoryFailures.length >= 3) {
        recommendations.push({
          priority: 'HIGH',
          title: `${category.toUpperCase()} Security Review`,
          description: `Multiple ${category} security issues detected. Consider a comprehensive review.`,
          findings: categoryFailures
        });
      }
    });

    return recommendations;
  }
}

module.exports = SecurityBaseline;
