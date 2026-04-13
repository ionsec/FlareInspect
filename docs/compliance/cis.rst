=====================

CIS Benchmark Mapping

=====================




FlareInspect maps findings to Center for Internet Security (CIS) controls for

Cloudflare.



Usage


----


.. code-block:: bash


    flareinspect assess --token $TOKEN --compliance cis




Control Mapping


----


.. rubric:: 1. Account Security



=============  ===========================================

   CIS Control    Check IDs

=============  ===========================================

   CIS 1.1        CFL-ACC-001 — MFA Enforcement

   CIS 1.2        CFL-ACC-002 — API Token Security

   CIS 1.3        CFL-ACC-003 — Admin Access Control

   CIS 1.4        CFL-ACC-004 — Audit Log Monitoring

   CIS 1.5        CFL-ACC-005 — Account Takeover Protection

=============  ===========================================


.. rubric:: 2. DNS Security



=============  =========================================

   CIS Control    Check IDs

=============  =========================================

   CIS 2.1        CFL-DNS-001 — DNSSEC Enablement

   CIS 2.2        CFL-DNS-002 — DNS Proxy Status

   CIS 2.3        CFL-DNS-003 — Wildcard DNS Records

   CIS 2.4        CFL-DNS-004 — CAA Records

   CIS 2.5        CFL-DNS-005 — DNS over HTTPS

   CIS 2.6        CFL-INSIGHT-005 — Unproxied DNS Records

=============  =========================================


.. rubric:: 3. SSL/TLS



=============  ==============================================

   CIS Control    Check IDs

=============  ==============================================

   CIS 3.1        CFL-SSL-001 — SSL Mode Configuration

   CIS 3.2        CFL-SSL-002 — Minimum TLS Version

   CIS 3.3        CFL-SSL-003 — Certificate Validity

   CIS 3.4        CFL-SSL-004 — HSTS Configuration

   CIS 3.5        CFL-SSL-005 — Always Use HTTPS

   CIS 3.6        CFL-MTLS-001 — mTLS Enforcement

   CIS 3.7        CFL-MTLS-002 — mTLS Certificate Rotation

   CIS 3.8        CFL-CH-001 — Custom Hostname Validation

   CIS 3.9        CFL-ORIGCERT-001 — Origin Certificate Expiry

=============  ==============================================


.. rubric:: 4. WAF & Traffic Protection



=============  ============================================

   CIS Control    Check IDs

=============  ============================================

   CIS 4.1        CFL-WAF-001 — WAF Security Level

   CIS 4.2        CFL-WAF-002 — Custom Firewall Rules

   CIS 4.3        CFL-WAF-003 — Rate Limiting

   CIS 4.4        CFL-WAF-004 / CFL-BOT-001 — Bot Management

   CIS 4.5        CFL-WAF-005 — OWASP Rule Set

   CIS 4.6        CFL-TURN-001 — Turnstile Widget

   CIS 4.7        CFL-PAGESHIELD-001 — Page Shield

   CIS 4.8        CFL-CDA-001 — Cache Deception Armor

   CIS 4.9        CFL-TXRULE-001 — Transform Rule Audit

=============  ============================================


.. rubric:: 5. Zero Trust



=============  ===========================================

   CIS Control    Check IDs

=============  ===========================================

   CIS 5.1        CFL-ZT-001 — Identity Provider

   CIS 5.2        CFL-ZT-002 — Access Policies

   CIS 5.3        CFL-ZT-003 — Device Enrollment

   CIS 5.4        CFL-ZT-004 — Tunnel Configuration

   CIS 5.5        CFL-ZT-005 — DNS Filtering

   CIS 5.6        CFL-ZT-006 — Gateway Logging

   CIS 5.7        CFL-DLP-001 — Data Loss Prevention

   CIS 5.8        CFL-TUNNEL-001 — Cloudflare Tunnels

   CIS 5.9        CFL-GW-001 — Gateway Policies

   CIS 5.10       CFL-DEVICE-001 — Device Enrollment Policy

=============  ===========================================


.. rubric:: 6–12. Additional Controls



CIS 6.1–6.5 cover performance, CIS 7.1–7.4 cover Workers/Pages,

CIS 8.1–8.2 cover API Gateway, CIS 9.1–9.3 cover load balancing and Spectrum,

CIS 10.1–10.3 cover email, CIS 11.1–11.7 cover Security Center,

and CIS 12.1 covers Logpush.

