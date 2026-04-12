# Edge Snippets Checks

Checks for Cloudflare Edge Snippets security.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-SNIPPET-001 | Edge Snippet Security | medium | SOC2 CC6.1/CC8.1, NIST PR.IP-1 |

## Individual Checks

### CFL-SNIPPET-001: Edge Snippet Security

**Severity:** medium | **Category:** snippets

Edge snippets execute code at the Cloudflare edge. Snippets containing
hardcoded secrets, passwords, or API keys pose a security risk. FlareInspect
scans snippet content for sensitive patterns.

**Remediation:** Review edge snippets for hardcoded secrets, insecure redirects, and security-impacting logic.
