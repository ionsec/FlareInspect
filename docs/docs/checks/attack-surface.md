# Attack Surface Management Checks

Checks that evaluate Cloudflare Security Center findings including attack
surface monitoring, security recommendations, and security insights.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-ASM-001 | Attack Surface Monitoring | high | CIS 11.3, SOC2 CC7.1/CC7.2, NIST ID.RA-1/DE.CM-8 |
| CFL-ASM-002 | Security Recommendations | medium | CIS 11.4, SOC2 CC7.1, NIST ID.RA-1 |
| CFL-INSIGHT-001 | Exposed Credentials | critical | CIS 11.5, SOC2 CC7.1, PCI 6.5, NIST DE.CM-8 |
| CFL-INSIGHT-002 | Origin IP Exposure | high | CIS 11.6, SOC2 CC7.1, NIST DE.CM-8 |
| CFL-INSIGHT-003 | Malware Domains | high | CIS 11.7, SOC2 CC7.2, NIST DE.CM-1 |
| CFL-INSIGHT-004 | Exposed API Keys | critical | SOC2 CC6.1/CC6.7, PCI 8.6, NIST PR.DS-5 |
| CFL-INSIGHT-005 | Unproxied DNS Records | medium | CIS 2.6, SOC2 CC6.6, NIST PR.DS-5 |

## Individual Checks

### CFL-ASM-001: Attack Surface Monitoring

**Severity:** high | **Category:** attack-surface

Cloudflare Security Center identifies exposed services and potential attack
vectors. FlareInspect surfaces these findings in the assessment.

**Remediation:** Review Cloudflare Security Center attack surface findings and remediate exposed services.

### CFL-ASM-002: Security Recommendations

**Severity:** medium | **Category:** attack-surface

The Security Center provides prioritized security recommendations based on
your account configuration.

**Remediation:** Review and implement Security Center recommendations for your account.

### CFL-INSIGHT-001: Exposed Credentials

**Severity:** critical | **Category:** attack-surface

Cloudflare Security Insights may detect credentials from your domains in public
data breaches or leak repositories.

**Remediation:** Rotate exposed credentials immediately and implement secret scanning in CI/CD.

### CFL-INSIGHT-002: Origin IP Exposure

**Severity:** high | **Category:** attack-surface

If origin server IP addresses are discoverable (via DNS history, misconfigured
records, or information leakage), attackers can bypass Cloudflare protection.

**Remediation:** Configure origin server to deny direct IP access. Enable Cloudflare proxy for all records.

### CFL-INSIGHT-003: Malware Domains

**Severity:** high | **Category:** attack-surface

Security Center may flag domains associated with malware distribution or
command-and-control infrastructure.

**Remediation:** Review and block malware domains identified by Cloudflare Security Center.

### CFL-INSIGHT-004: Exposed API Keys

**Severity:** critical | **Category:** attack-surface

Cloudflare may detect API keys or tokens from your domains in public code
repositories or paste sites.

**Remediation:** Rotate exposed credentials immediately, review access logs, and implement credential scanning in CI/CD.

### CFL-INSIGHT-005: Unproxied DNS Records

**Severity:** medium | **Category:** attack-surface

DNS records pointing to origin IPs without Cloudflare proxy expose the origin
server address.

**Remediation:** Enable Cloudflare proxy (orange cloud) for all DNS records that point to origin servers.
