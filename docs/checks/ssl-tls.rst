=======================

SSL/TLS Security Checks

=======================




Checks that evaluate SSL/TLS configuration including encryption mode, TLS

version, and HTTP security headers.



Check Summary


----


=============  ========================  ==========  ==============================================================

   Check ID       Title                     Severity    Compliance

=============  ========================  ==========  ==============================================================

   CFL-SSL-001    SSL Mode Configuration    high        CIS 3.1, SOC2 CC6.1/CC6.7, PCI 4.1/4.2, NIST PR.DS-1/PR.DS-2

   CFL-SSL-002    Minimum TLS Version       high        CIS 3.2, SOC2 CC6.7, PCI 4.1/8.2, NIST PR.DS-2

   CFL-SSL-003    Certificate Validity      medium      CIS 3.3, SOC2 CC6.7, PCI 4.1, NIST PR.DS-2

   CFL-SSL-004    HSTS Configuration        high        CIS 3.4, SOC2 CC6.7, PCI 4.1/6.1, NIST PR.DS-2

   CFL-SSL-005    Always Use HTTPS          medium      CIS 3.5, SOC2 CC6.7, PCI 4.1, NIST PR.DS-2

=============  ========================  ==========  ==============================================================


Individual Checks


----


.. rubric:: CFL-SSL-001: SSL Mode Configuration



**Severity:** high | **Category:** ssl | **Compliance:** CIS 3.1, SOC2 CC6.1/CC6.7, PCI 4.1/4.2, NIST PR.DS-1/PR.DS-2


FlareInspect verifies that zones use **Full (Strict)** SSL mode, which

requires a valid certificate on the origin. Flexible mode exposes traffic

between Cloudflare and the origin in plaintext.


**Remediation:** Set SSL mode to Full (Strict) in SSL/TLS → Overview.



.. rubric:: CFL-SSL-002: Minimum TLS Version



**Severity:** high | **Category:** ssl | **Compliance:** CIS 3.2, SOC2 CC6.7, PCI 4.1/8.2, NIST PR.DS-2


TLS 1.0 and 1.1 have known vulnerabilities and are deprecated by PCI-DSS.

FlareInspect checks that the minimum TLS version is 1.2 or higher.


**Remediation:** Set minimum TLS version to 1.2 or higher in SSL/TLS → Edge Certificates.



.. rubric:: CFL-SSL-003: Certificate Validity



**Severity:** medium | **Category:** ssl | **Compliance:** CIS 3.3, SOC2 CC6.7, PCI 4.1, NIST PR.DS-2


Expired or expiring certificates cause browser errors and can break Full

(Strict) SSL mode. FlareInspect monitors certificate expiration dates.


**Remediation:** Monitor certificate expiration and enable automatic renewal.



.. rubric:: CFL-SSL-004: HSTS Configuration



**Severity:** high | **Category:** ssl | **Compliance:** CIS 3.4, SOC2 CC6.7, PCI 4.1/6.1, NIST PR.DS-2


HTTP Strict Transport Security (HSTS) forces browsers to always use HTTPS,

preventing protocol downgrade and cookie hijacking attacks.


**Remediation:** Enable HSTS in SSL/TLS → Edge Certificates. Set max-age to at least 6 months.



.. rubric:: CFL-SSL-005: Always Use HTTPS



**Severity:** medium | **Category:** ssl | **Compliance:** CIS 3.5, SOC2 CC6.7, PCI 4.1, NIST PR.DS-2


The "Always Use HTTPS" feature automatically redirects HTTP requests to HTTPS

at the edge.


**Remediation:** Enable "Always Use HTTPS" in SSL/TLS → Edge Certificates.

