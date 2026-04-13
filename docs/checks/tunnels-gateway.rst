========================

Tunnels & Gateway Checks

========================




Checks for Cloudflare Tunnels, Gateway policies, and Spectrum.



Check Summary


----


  ==================  ====================  ==========  ============================================

   Check ID            Title                 Severity    Compliance

  ==================  ====================  ==========  ============================================

   CFL-TUNNEL-001      Cloudflare Tunnels    high        CIS 5.8, SOC2 CC6.6, PCI 1.3, NIST PR.AC-5

   CFL-GW-001          Gateway Policies      high        CIS 5.9, SOC2 CC6.6, PCI 1.3, NIST PR.AC-5

   CFL-SPECTRUM-001    Spectrum TLS          high        CIS 9.3, SOC2 CC6.1, NIST PR.DS-2

  ==================  ====================  ==========  ============================================


Individual Checks


----


.. rubric:: CFL-TUNNEL-001: Cloudflare Tunnels



**Severity:** high | **Category:** tunnels


Cloudflare Tunnels create secure outbound connections from origins, removing

the need for open inbound ports. FlareInspect checks whether tunnels are

configured for the account.


**Remediation:** Replace open ingress ports with Cloudflare Tunnels in Zero Trust → Networks → Tunnels for secure origin connectivity.



.. rubric:: CFL-GW-001: Gateway Policies



**Severity:** high | **Category:** gateway


Gateway policies filter and inspect DNS, HTTP, and L4 traffic. FlareInspect

checks for the presence of DNS, HTTP, and L4 gateway policies.


**Remediation:** Configure DNS and HTTP gateway policies in Zero Trust → Gateway to filter and inspect traffic.



.. rubric:: CFL-SPECTRUM-001: Spectrum TLS



**Severity:** high | **Category:** tunnels


Spectrum applications that handle non-HTTP traffic should enforce TLS 1.2+ and

restrict access with IP allowlists or Access policies.


**Remediation:** Ensure Spectrum applications use TLS 1.2+ and restrict access with IP allowlists or Access policies.

