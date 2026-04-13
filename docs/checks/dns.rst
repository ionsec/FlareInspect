===================

DNS Security Checks

===================




Checks that evaluate DNS configuration including DNSSEC, proxy status, and

record hygiene.



Check Summary


----


  =============  ======================  ==========  ============================================

   Check ID       Title                   Severity    Compliance

  =============  ======================  ==========  ============================================

   CFL-DNS-001    DNSSEC Enablement       high        CIS 2.1, SOC2 CC6.1, PCI 4.1, NIST PR.DS-5

   CFL-DNS-002    DNS Proxy Status        medium      CIS 2.2, SOC2 CC6.6, PCI 4.1, NIST PR.DS-5

   CFL-DNS-003    Wildcard DNS Records    low         CIS 2.3, SOC2 CC6.6, NIST PR.DS-5

   CFL-DNS-004    CAA Records             medium      CIS 2.4, SOC2 CC6.1, PCI 4.1, NIST PR.DS-5

   CFL-DNS-005    DNS over HTTPS          low         CIS 2.5, SOC2 CC6.6, PCI 4.1, NIST PR.DS-5

  =============  ======================  ==========  ============================================


Individual Checks


----


.. rubric:: CFL-DNS-001: DNSSEC Enablement



**Severity:** high | **Category:** dns | **Compliance:** CIS 2.1, SOC2 CC6.1, PCI 4.1, NIST PR.DS-5


DNSSEC protects against DNS spoofing and cache poisoning by cryptographically

signing DNS responses. FlareInspect checks whether DNSSEC is enabled for each

zone.


**Remediation:** Enable DNSSEC for all zones in DNS → DNSSEC in the Cloudflare dashboard.



.. rubric:: CFL-DNS-002: DNS Proxy Status



**Severity:** medium | **Category:** dns | **Compliance:** CIS 2.2, SOC2 CC6.6, NIST PR.DS-5


Security-sensitive DNS records should be proxied through Cloudflare (orange

cloud) to benefit from DDoS protection and IP masking.


**Remediation:** Enable Cloudflare proxy (orange cloud) for security-sensitive DNS records.



.. rubric:: CFL-DNS-003: Wildcard DNS Records



**Severity:** low | **Category:** dns | **Compliance:** CIS 2.3, NIST PR.DS-5


Wildcard records (``*``) can inadvertently expose subdomains and increase the

attack surface.


**Remediation:** Remove wildcard DNS records and create explicit A/CNAME records for each subdomain.



.. rubric:: CFL-DNS-004: CAA Records



**Severity:** medium | **Category:** dns | **Compliance:** CIS 2.4, SOC2 CC6.1, PCI 4.1, NIST PR.DS-5


CAA records specify which certificate authorities are allowed to issue

certificates for the domain, preventing unauthorized certificate issuance.


**Remediation:** Add CAA records to restrict which certificate authorities can issue certificates for your domain.



.. rubric:: CFL-DNS-005: DNS over HTTPS



**Severity:** low | **Category:** dns | **Compliance:** CIS 2.5, SOC2 CC6.6, PCI 4.1, NIST PR.DS-5


DNS over HTTPS (DoH) encrypts DNS queries to prevent eavesdropping and

tampering.


**Remediation:** Enable DNS over HTTPS (DoH) via Cloudflare Gateway to encrypt DNS queries.

