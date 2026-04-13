===================
DNS Security Checks
===================

Checks that evaluate DNS record security including DNSSEC, proxy status, wildcards, CAA, and DNS over HTTPS.

Check Summary
-------------

===========  =============================  ============  =========================================
Check ID     Title                          Severity      Compliance                               
===========  =============================  ============  =========================================
CFL-DNS-001  DNSSEC Enablement           h  igh        C  IS 2.1, SOC2 CC6.1, PCI 3.4, NIST PR.DS-5
CFL-DNS-002  DNS Proxy Status            h  igh        C  IS 2.2, SOC2 CC6.1, NIST PR.DS-5         
CFL-DNS-003  Wildcard DNS Records           medium        CIS 2.3, SOC2 CC6.1, NIST PR.DS-5        
CFL-DNS-004  CAA Records                    medium        CIS 2.4, SOC2 CC6.1, NIST PR.DS-5        
CFL-DNS-005  DNS over HTTPS                 medium        CIS 2.5, SOC2 CC6.7, NIST PR.DS-5        
===========  =============================  ============  =========================================

CFL-DNS-001: DNSSEC Enablement
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** dns | **Compliance:** CIS 2.1

DNSSEC protects DNS responses from tampering. Without it, DNS records are vulnerable to spoofing and cache poisoning attacks.

**Remediation:** Enable DNSSEC for all zones in the Cloudflare dashboard under DNS → DNSSEC.

---

CFL-DNS-002: DNS Proxy Status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** dns | **Compliance:** CIS 2.2

DNS records should be proxied through Cloudflare to benefit from DDoS protection, WAF, and traffic analytics.

**Remediation:** Enable the proxy (orange cloud) for DNS records that should be protected.

---

CFL-DNS-003: Wildcard DNS Records
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** dns | **Compliance:** CIS 2.3

Wildcard DNS records (``*``) can expose unintended subdomains. FlareInspect flags zones containing wildcard records.

**Remediation:** Replace wildcard records with explicit subdomain records.

---

CFL-DNS-004: CAA Records
^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** dns | **Compliance:** CIS 2.4

CAA records specify which certificate authorities are allowed to issue certificates for a domain. Without CAA, any CA can issue certificates.

**Remediation:** Add CAA records to restrict certificate issuance to authorized CAs.

---

CFL-DNS-005: DNS over HTTPS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** dns | **Compliance:** CIS 2.5

DNS over HTTPS (DoH) encrypts DNS queries, preventing eavesdropping and manipulation by network intermediaries.

**Remediation:** Enable DNS over HTTPS in the Cloudflare dashboard under your zone settings.
