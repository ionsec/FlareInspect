# Security Checks

FlareInspect runs **40+ security checks** across **21 categories** against your
Cloudflare account and zones. Each check produces a finding with:

- **Check ID** — unique identifier (e.g., `CFL-SSL-001`)
- **Category** — the assessment area
- **Title** — what is being evaluated
- **Severity** — critical, high, medium, low, or informational
- **Status** — PASS, FAIL, or WARNING
- **Evidence** — observed vs expected values, affected entities
- **Remediation** — how to fix the issue
- **Compliance** — mapped control IDs for CIS, SOC 2, PCI-DSS, NIST

## Filtering Checks

Use `--checks` to run only specific categories:

```bash
flareinspect assess --token $TOKEN --checks dns,ssl,waf
```

## Check Catalog

### Account

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-ACC-001 | MFA Enforcement | critical |
| CFL-ACC-002 | API Token Security | high |
| CFL-ACC-003 | Admin Access Control | high |
| CFL-ACC-004 | Audit Log Monitoring | medium |
| CFL-ACC-005 | Account Takeover Protection | high |

### DNS

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-DNS-001 | DNSSEC Enablement | high |
| CFL-DNS-002 | DNS Proxy Status | medium |
| CFL-DNS-003 | Wildcard DNS Records | low |
| CFL-DNS-004 | CAA Records | medium |
| CFL-DNS-005 | DNS over HTTPS | low |

### SSL/TLS

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-SSL-001 | SSL Mode Configuration | high |
| CFL-SSL-002 | Minimum TLS Version | high |
| CFL-SSL-003 | Certificate Validity | medium |
| CFL-SSL-004 | HSTS Configuration | high |
| CFL-SSL-005 | Always Use HTTPS | medium |

### WAF

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-WAF-001 | WAF Security Level | high |
| CFL-WAF-002 | Custom Firewall Rules | medium |
| CFL-WAF-003 | Rate Limiting | medium |
| CFL-WAF-004 | Bot Management | medium |
| CFL-WAF-005 | OWASP Rule Set | high |

### Zero Trust

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-ZT-001 | Identity Provider Configuration | high |
| CFL-ZT-002 | Access Policies | high |
| CFL-ZT-003 | Device Enrollment Rules | medium |
| CFL-ZT-004 | Tunnel Configuration | medium |
| CFL-ZT-005 | DNS Filtering | high |
| CFL-ZT-006 | Gateway Logging | medium |

### Workers & Pages

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-WORK-001 | Worker Route Security | high |
| CFL-WORK-002 | Worker Resource Limits | medium |
| CFL-PAGE-001 | Pages Project Security | high |
| CFL-PAGE-002 | Pages Deployment Protection | medium |

### API Gateway

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-API-001 | API Shield | high |
| CFL-API-002 | API Discovery | medium |

### Bot Management

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-BOT-001 | Bot Fight Mode | medium |
| CFL-TURN-001 | Turnstile Widget Security | medium |

### Email Security

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-EMAIL-001 | Email Routing Security | high |
| CFL-EMAIL-002 | SPF/DKIM/DMARC | medium |
| CFL-EMAIL-003 | Email Encryption | medium |

### Load Balancing

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-LB-001 | Load Balancer Health Checks | medium |
| CFL-LB-002 | Load Balancer Failover | medium |

### Security Center

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-SEC-001 | Security Center Insights | high |
| CFL-SEC-002 | Security Events | high |

### Logpush

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-LOG-001 | Logpush Configuration | medium |

### mTLS

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-MTLS-001 | mTLS Enforcement | high |
| CFL-MTLS-002 | mTLS Certificate Rotation | medium |

### security.txt

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-SECTXT-001 | security.txt Presence | low |

### Attack Surface & Security Insights

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-ASM-001 | Attack Surface Monitoring | high |
| CFL-ASM-002 | Security Recommendations | medium |
| CFL-INSIGHT-001 | Exposed Credentials | critical |
| CFL-INSIGHT-002 | Origin IP Exposure | high |
| CFL-INSIGHT-003 | Malware Domains | high |
| CFL-INSIGHT-004 | Exposed API Keys | critical |
| CFL-INSIGHT-005 | Unproxied DNS Records | medium |

### Modern Cloudflare Features

| Check ID | Title | Severity |
|----------|-------|----------|
| CFL-DLP-001 | Data Loss Prevention | high |
| CFL-PAGESHIELD-001 | Page Shield Monitoring | high |
| CFL-TUNNEL-001 | Cloudflare Tunnels | high |
| CFL-GW-001 | Gateway Policies | high |
| CFL-SPECTRUM-001 | Spectrum TLS | high |
| CFL-AIGW-001 | AI Gateway Configuration | medium |
| CFL-CDA-001 | Cache Deception Armor | medium |
| CFL-SNIPPET-001 | Edge Snippet Security | medium |
| CFL-CH-001 | Custom Hostname Validation | medium |
| CFL-ORIGCERT-001 | Origin Certificate Expiry | medium |
| CFL-CFRULE-001 | Configuration Rule Security | medium |
| CFL-TXRULE-001 | Transform Rule Audit | medium |
| CFL-DEVICE-001 | Device Enrollment Policy | medium |
