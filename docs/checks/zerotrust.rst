==========================

Zero Trust Security Checks

==========================




Checks that evaluate Zero Trust configuration including identity providers,

access policies, device enrollment, tunnels, and gateway policies.



Check Summary


----


============  =================================  ==========  ==========================================================

   Check ID      Title                              Severity    Compliance

============  =================================  ==========  ==========================================================

   CFL-ZT-001    Identity Provider Configuration    high        CIS 5.1, SOC2 CC6.1/CC6.2, PCI 8.3, NIST PR.AC-1/PR.AC-7

   CFL-ZT-002    Access Policies                    high        CIS 5.2, SOC2 CC6.1/CC6.3, PCI 8.3, NIST PR.AC-4

   CFL-ZT-003    Device Enrollment Rules            medium      CIS 5.3, SOC2 CC6.1, NIST PR.AC-3

   CFL-ZT-004    Tunnel Configuration               medium      CIS 5.4, SOC2 CC6.6, PCI 1.3, NIST PR.AC-5

   CFL-ZT-005    DNS Filtering                      high        CIS 5.5, SOC2 CC6.1/CC6.7, PCI 3.4, NIST PR.DS-5

   CFL-ZT-006    Gateway Logging                    medium      CIS 5.6, SOC2 CC6.1, PCI 8.6, NIST PR.AC-1

============  =================================  ==========  ==========================================================


Individual Checks


----


.. rubric:: CFL-ZT-001: Identity Provider Configuration



**Severity:** high | **Category:** zerotrust


Verifies that at least one identity provider (IdP) is configured for Zero Trust

authentication. Without an IdP, Cloudflare Access cannot enforce identity-based

policies.


**Remediation:** Configure identity providers in Zero Trust → Settings → Authentication.



.. rubric:: CFL-ZT-002: Access Policies



**Severity:** high | **Category:** zerotrust


Checks whether granular access policies are defined. Without access policies,

applications may be publicly accessible.


**Remediation:** Define granular access policies in Zero Trust → Access → Applications.



.. rubric:: CFL-ZT-003: Device Enrollment Rules



**Severity:** medium | **Category:** zerotrust


Device enrollment ensures only managed devices can access protected resources.


**Remediation:** Configure device enrollment rules in Zero Trust → Devices.



.. rubric:: CFL-ZT-004: Tunnel Configuration



**Severity:** medium | **Category:** zerotrust


Cloudflare Tunnels provide secure outbound connections from origins, eliminating

the need for open inbound ports.


**Remediation:** Use Cloudflare Tunnels instead of opening inbound ports to origins.



.. rubric:: CFL-ZT-005: DNS Filtering



**Severity:** high | **Category:** zerotrust


DNS filtering blocks access to malicious domains and enforces acceptable use

policies.


**Remediation:** Enable DNS filtering via Cloudflare Gateway.



.. rubric:: CFL-ZT-006: Gateway Logging



**Severity:** medium | **Category:** zerotrust


Gateway logging provides visibility into DNS and HTTP traffic for forensics and

compliance.


**Remediation:** Enable gateway logging for visibility into DNS and HTTP traffic.

