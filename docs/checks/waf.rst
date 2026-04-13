===================

WAF Security Checks

===================




Checks that evaluate Web Application Firewall configuration including security

level, custom rules, rate limiting, and OWASP coverage.



Check Summary


----


  =============  =======================  ==========  ==================================================

   Check ID       Title                    Severity    Compliance

  =============  =======================  ==========  ==================================================

   CFL-WAF-001    WAF Security Level       high        CIS 4.1, SOC2 CC6.1, PCI 6.5/6.6, NIST PR.IP-1

   CFL-WAF-002    Custom Firewall Rules    medium      CIS 4.2, SOC2 CC6.1/CC6.6, PCI 6.5, NIST PR.IP-1

   CFL-WAF-003    Rate Limiting            medium      CIS 4.3, SOC2 CC6.6, PCI 6.5, NIST PR.IP-1

   CFL-WAF-004    Bot Management           medium      CIS 4.4, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1

   CFL-WAF-005    OWASP Rule Set           high        CIS 4.5, SOC2 CC6.1, PCI 6.5/6.6, NIST PR.IP-1

  =============  =======================  ==========  ==================================================


Individual Checks


----


.. rubric:: CFL-WAF-001: WAF Security Level



**Severity:** high | **Category:** waf


The WAF security level controls the sensitivity of the managed rules. A level

that is too low (Essentially Off or Low) may miss attack patterns.


**Remediation:** Set WAF security level to "Medium" or higher in Security → WAF.



.. rubric:: CFL-WAF-002: Custom Firewall Rules



**Severity:** medium | **Category:** waf


Custom firewall rules provide application-specific protection beyond managed

rules. FlareInspect checks whether any custom rules are configured.


**Remediation:** Implement custom firewall rules for application-specific protection.



.. rubric:: CFL-WAF-003: Rate Limiting



**Severity:** medium | **Category:** waf


Rate limiting protects against brute force and DDoS attacks by throttling

excessive requests.


**Remediation:** Configure rate limiting rules to prevent abuse and DDoS attacks.



.. rubric:: CFL-WAF-004: Bot Management



**Severity:** medium | **Category:** waf


Bot management detects and mitigates automated traffic including credential

stuffing and content scraping.


**Remediation:** Enable Bot Fight Mode or Bot Management for automated traffic protection.



.. rubric:: CFL-WAF-005: OWASP Rule Set



**Severity:** high | **Category:** waf


The OWASP ModSecurity Core Rule Set (CRS) provides broad protection against

the OWASP Top 10 vulnerabilities.


**Remediation:** Enable the OWASP ModSecurity Core Rule Set in Security → WAF → Managed Rules.

