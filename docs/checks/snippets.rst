========================
Snippets Security Checks
========================

Checks for Cloudflare Snippets configuration.

Check Summary
-------------

===================  ===================  ========  ========================
Check ID          T  itle                 Severity  Compliance              
===================  ===================  ========  ========================
CFL-TXRULE-001    T  ransform Rule Audit  low       SOC2 CC6.1, NIST PR.IP-1
===================  ===================  ========  ========================

CFL-TXRULE-001: Transform Rule Audit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** low | **Category:** snippets | **Compliance:** SOC2 CC6.1

Transform rules and snippets modify HTTP request and response headers. Unreviewed rules may introduce security misconfigurations.

**Remediation:** Audit transform rules and snippets regularly to ensure they do not introduce security weaknesses.
