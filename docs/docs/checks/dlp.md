# Data Loss Prevention Checks

Checks for Cloudflare DLP configuration.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-DLP-001 | Data Loss Prevention | high | CIS 5.7, SOC2 CC6.1/CC6.7, PCI 3.4/4.2, NIST PR.DS-5 |

## Individual Checks

### CFL-DLP-001: Data Loss Prevention

**Severity:** high | **Category:** dlp

Cloudflare DLP profiles detect and prevent sensitive data such as PII, credit
card numbers, and health records from leaving the organization via HTTP
uploads. FlareInspect checks whether any DLP profiles are configured.

**Remediation:** Configure DLP profiles and rules in Zero Trust → Data Loss Prevention to detect and prevent sensitive data exfiltration.
