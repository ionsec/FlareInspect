===================
WAF Security Checks
===================

Checks that evaluate Web Application Firewall configuration including
security level, custom rules, rate limiting, and managed rulesets
(Cloudflare Managed and OWASP Core).

Check Summary
-------------

==============  ======================================  ========  ============
Check ID        Title                                   Severity  Compliance
==============  ======================================  ========  ============
CFL-WAF-001     Security Level                          low       CIS, SOC2, PCI, NIST
CFL-WAF-006     Cloudflare Managed Ruleset Deployed    high      CIS, SOC2, PCI, NIST
CFL-WAF-007     OWASP Core Ruleset Deployed            high      CIS, SOC2, PCI, NIST
CFL-WAF-008     Managed Ruleset Override Posture       medium    CIS, SOC2
CFL-WAF-009     Browser Integrity Check                low       SOC2
==============  ======================================  ========  ============

CFL-WAF-006: Cloudflare Managed Ruleset Deployed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Cloudflare Managed Ruleset is curated by Cloudflare security
engineers and updated continuously as new CVEs are disclosed.

**Remediation:** Deploy the ruleset via FlareInspect's recipe
(deploys in log mode by default — promote to block after reviewing
false positives).

CFL-WAF-007: OWASP Core Ruleset Deployed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The OWASP ModSecurity Core Rule Set (CRS) is the industry baseline
for WAF coverage against the OWASP Top 10.

**Remediation:** Same as CFL-WAF-006 — deploy in log mode first.

CFL-WAF-008: Managed Ruleset Override Posture
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Ruleset overrides that downgrade the action to *log* (or skip rules)
are useful for tuning but weaken the default posture if left
indefinitely.

**Remediation:** Review any log-only overrides — promote to block
once false-positive traffic has been ruled out.

CFL-WAF-009: Browser Integrity Check
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Browser Integrity Check challenges requests that exhibit suspicious
client headers (e.g. headless browsers, bot UAs).

**Remediation:** Use FlareInspect's recipe, or toggle the setting in
*Security → Settings → Browser Integrity Check*.
