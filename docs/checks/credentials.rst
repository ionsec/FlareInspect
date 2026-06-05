==========================
Leaked Credentials Checks
==========================

Detects whether Leaked Credentials Detection is enabled. When enabled,
Cloudflare will non-blockingly inspect incoming requests for credentials
known to be leaked in public breach corpora and surface matches in WAF
analytics.

Check Summary
-------------

==============  ====================================  ========  ============
Check ID        Title                                 Severity  Compliance
==============  ====================================  ========  ============
CFL-LEAK-001    Leaked Credentials Detection          high      CIS, SOC2, PCI, NIST
==============  ====================================  ========  ============

CFL-LEAK-001: Leaked Credentials Detection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** credentials

Enabling Leaked Credentials Detection gives the WAF visibility into
credential-stuffing attempts using breached passwords, with no impact
on legitimate traffic (it does not block — it only logs).

**Remediation:** Use FlareInspect to apply the recipe, or enable the
feature manually in *Security → WAF → Managed Rules* and toggle
*Leaked Credentials Check* to on.
