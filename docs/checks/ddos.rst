==================
DDoS and Account-WAF
==================

Detects whether the account has DDoS protection rules and reusable
account-level WAF rulesets.

Check Summary
-------------

==============  ======================================  ========  ============
Check ID        Title                                   Severity  Compliance
==============  ======================================  ========  ============
CFL-DDOS-001    L7 DDoS Managed Ruleset Deployed        medium    SOC2, NIST
CFL-ACCTWAF-001 Account-level WAF Ruleset Coverage      medium    SOC2, PCI, NIST
==============  ======================================  ========  ============

CFL-DDOS-001: L7 DDoS Managed Ruleset Deployed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** ddos

Cloudflare's L7 DDoS managed ruleset inspects incoming HTTP traffic
and applies adaptive thresholds to detect and mitigate application-layer
DDoS attacks.

**Remediation:** Review the L7 DDoS ruleset posture in *Security →
DDoS*. FlareInspect does not auto-modify DDoS rulesets.

CFL-ACCTWAF-001: Account-level WAF Ruleset Coverage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** account-waf

Account-scoped custom WAF rulesets allow you to share a single rule
across many zones. The check verifies that at least one custom or
managed ruleset is present at the account level.

**Remediation:** Create a shared custom ruleset in *Account → WAF →
Custom Rulesets* and reference it from each zone's ruleset phase.
