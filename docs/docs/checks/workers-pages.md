# Workers & Pages Security Checks

Checks for Cloudflare Workers and Pages deployments.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-WORK-001 | Worker Route Security | high | CIS 7.1, SOC2 CC8.1, NIST PR.IP-1 |
| CFL-WORK-002 | Worker Resource Limits | medium | CIS 7.2, SOC2 CC6.6, NIST PR.IP-1 |
| CFL-PAGE-001 | Pages Project Security | high | CIS 7.3, SOC2 CC6.1, NIST PR.DS-5 |
| CFL-PAGE-002 | Pages Deployment Protection | medium | CIS 7.4, SOC2 CC6.1, NIST PR.IP-1 |

## Individual Checks

### CFL-WORK-001: Worker Route Security

**Severity:** high | **Category:** workers

Worker routes that handle sensitive endpoints should be protected with Access
policies. FlareInspect checks for Workers routes that lack authentication.

**Remediation:** Review Worker routes and ensure sensitive endpoints are protected with Access policies.

### CFL-WORK-002: Worker Resource Limits

**Severity:** medium | **Category:** workers

Workers without appropriate CPU and memory limits can be exploited for resource
exhaustion.

**Remediation:** Set appropriate CPU and memory limits for Workers to prevent resource exhaustion.

### CFL-PAGE-001: Pages Project Security

**Severity:** high | **Category:** pages

Pages projects may expose environment variables or secrets in build output.

**Remediation:** Review Pages project deployments for exposed environment variables and secrets.

### CFL-PAGE-002: Pages Deployment Protection

**Severity:** medium | **Category:** pages

Preview deployments on Pages can be publicly accessible without authentication.

**Remediation:** Enable Pages deployment protection to restrict preview deployments.
