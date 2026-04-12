# AI Gateway Checks

Checks for Cloudflare AI Gateway configuration.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-AIGW-001 | AI Gateway Configuration | medium | SOC2 CC6.7, NIST PR.DS-5 |

## Individual Checks

### CFL-AIGW-001: AI Gateway Configuration

**Severity:** medium | **Category:** ai-gateway

AI Gateway provides logging, rate limiting, and monitoring for LLM API calls.
Without it, organizations using AI services lack visibility into data leakage
and prompt injection attempts. FlareInspect checks whether any AI Gateways are
configured.

**Remediation:** Configure AI Gateway to log, rate-limit, and monitor LLM API calls for data leakage and prompt injection.
