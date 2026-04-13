=======================
SSL/TLS Security Checks
=======================

Checks that evaluate SSL/TLS configuration including mode, minimum TLS version, HSTS, and certificate validity.

Check Summary
-------------

===========  =============================  ============  ==========================================
Check ID     Title                          Severity      Compliance                                
===========  =============================  ============  ==========================================
CFL-SSL-001  SSL Mode Configuration      h  igh        C  IS 3.1, SOC2 CC6.1, PCI 3.4, NIST PR.DS-5 
CFL-SSL-002  Minimum TLS Version            high          CIS 3.2, SOC2 CC6.7, PCI 3.4, NIST PR.DS-5
CFL-SSL-003  Certificate Validity           high          CIS 3.3, SOC2 CC6.1, PCI 3.4, NIST PR.DS-5
CFL-SSL-004  HSTS Configuration          h  igh        C  IS 3.4, SOC2 CC6.7, PCI 3.4, NIST PR.DS-5 
CFL-SSL-005  Always Use HTTPS               medium        CIS 3.5, SOC2 CC6.1, NIST PR.DS-5         
===========  =============================  ============  ==========================================

CFL-SSL-001: SSL Mode Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** ssl | **Compliance:** CIS 3.1

SSL mode should be set to ``full`` or ``full (strict)`` to prevent downgrade attacks and ensure origin connections are encrypted.

**Remediation:** Set SSL mode to ``full (strict)`` in Cloudflare Dashboard → SSL/TLS → Overview.

---

CFL-SSL-002: Minimum TLS Version
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** ssl | **Compliance:** CIS 3.2

TLS 1.2 should be the minimum version. TLS 1.0 and 1.1 have known vulnerabilities and are deprecated.

**Remediation:** Set minimum TLS version to 1.2 in Cloudflare Dashboard → SSL/TLS → Edge Certificates.

---

CFL-SSL-003: Certificate Validity
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** ssl | **Compliance:** CIS 3.3

Expired or soon-to-expire certificates cause browser errors and service disruptions.

**Remediation:** Renew certificates before expiry. Enable automatic certificate rotation.

---

CFL-SSL-004: HSTS Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** ssl | **Compliance:** CIS 3.4

HTTP Strict Transport Security (HSTS) forces browsers to always use HTTPS connections, preventing protocol downgrade and cookie hijacking.

**Remediation:** Enable HSTS in Cloudflare Dashboard → SSL/TLS → Edge Certificates → HTTP Strict Transport Security.

---

CFL-SSL-005: Always Use HTTPS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** ssl | **Compliance:** CIS 3.5

The "Always Use HTTPS" feature redirects all HTTP requests to HTTPS.

**Remediation:** Enable Always Use HTTPS in Cloudflare Dashboard → SSL/TLS → Edge Certificates.
