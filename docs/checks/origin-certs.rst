=================================

Origin Certificate & Rules Checks

=================================




Checks for origin certificate expiry, configuration rules, and transform rules.



Check Summary


----


  ==================  =============================  ==========  ================================================

   Check ID            Title                          Severity    Compliance

  ==================  =============================  ==========  ================================================

   CFL-ORIGCERT-001    Origin Certificate Expiry      medium      CIS 3.9, SOC2 CC6.7, PCI 4.1/4.2, NIST PR.DS-2

   CFL-CFRULE-001      Configuration Rule Security    medium      SOC2 CC6.1, NIST PR.IP-1

   CFL-TXRULE-001      Transform Rule Audit           medium      CIS 4.9, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1

  ==================  =============================  ==========  ================================================


Individual Checks


----


.. rubric:: CFL-ORIGCERT-001: Origin Certificate Expiry



**Severity:** medium | **Category:** origin-certs


Origin certificates expiring within 30 days can break Full (Strict) SSL mode.

FlareInspect checks the expiration date of all origin certificates.


**Remediation:** Monitor origin certificate expiration and set up renewal alerts. Expired certificates break Full(Strict) SSL.



.. rubric:: CFL-CFRULE-001: Configuration Rule Security



**Severity:** medium | **Category:** origin-certs


Configuration rules can override security settings such as WAF or SSL

enforcement. FlareInspect reviews active configuration rules for potential

security overrides.


**Remediation:** Review configuration rules to ensure they do not override security settings like WAF or SSL enforcement.



.. rubric:: CFL-TXRULE-001: Transform Rule Audit



**Severity:** medium | **Category:** origin-certs


URL rewrite and header modification rules can remove security headers such as

HSTS or CSP. FlareInspect audits transform rules for security implications.


**Remediation:** Audit URL rewrite and header modification rules for security implications such as removing security headers.

