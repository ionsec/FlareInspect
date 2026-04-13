===================
WAF Security Checks
===================
===================

Checks that evaluate Web Application Firewall configuration including security level, custom rules, rate limiting, and OWASP rule sets.

Check Summary
-------------

===========  =====================  ========  ==========================================
Check ID     Title                  Severity  Compliance                                
===========  =====================  ========  ==========================================
CFL-WAF-001  WAF Security Level     high      CIS 4.1, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1
CFL-WAF-002  Custom Firewall Rules  high      CIS 4.2, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1
CFL-WAF-003  Rate Limiting          high      CIS 4.3, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1
CFL-WAF-004  Bot Management         medium    CIS 4.4, SOC2 CC6.1, NIST PR.IP-1         
CFL-WAF-005  OWASP Rule Set         high      CIS 4.5, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1
===========  =====================  ========  ==========================================

CFL-WAF-001: WAF Security Level
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** waf | **Compliance:** CIS 4.1

WAF should be set to an appropriate security level (medium or higher) to protect against common attacks.

**Remediation:** Set WAF security level to "Medium" or "High" in Security → WAF → Settings.

---

CFL-WAF-002: Custom Firewall Rules
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** waf | **Compliance:** CIS 4.2

Custom firewall rules provide targeted protection for application-specific attack patterns.

**Remediation:** Create custom WAF rules to protect against application-specific threats.

---

CFL-WAF-003: Rate Limiting
^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** waf | **Compliance:** CIS 4.3

Rate limiting protects against brute force and DDoS attacks by throttling excessive requests.

**Remediation:** Configure rate limiting rules to prevent abuse and DDoS attacks.

---

CFL-WAF-004: Bot Management
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** waf | **Compliance:** CIS 4.4

Bot management detects and mitigates automated traffic including credential stuffing and content scraping.

**Remediation:** Enable Bot Fight Mode or Bot Management for automated traffic protection.

---

CFL-WAF-005: OWASP Rule Set
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** waf | **Compliance:** CIS 4.5

The OWASP ModSecurity Core Rule Set (CRS) provides broad protection against the OWASP Top 10 vulnerabilities.

**Remediation:** Enable the OWASP ModSecurity Core Rule Set in Security → WAF → Managed Rules.
