=================================
Tunnels & Gateway Security Checks
=================================
=================================

Checks for Cloudflare Tunnels and Secure Web Gateway configuration.

Check Summary
-------------

==============  ========================  ========  ==========================================
Check ID        Title                     Severity  Compliance                                
==============  ========================  ========  ==========================================
CFL-TUNNEL-001  Cloudflare Tunnels        medium    CIS 5.8, SOC2 CC6.6, PCI 1.3, NIST PR.AC-5
CFL-GW-001      Gateway Policies          high      CIS 5.9, SOC2 CC6.1, PCI 3.4, NIST PR.DS-5
CFL-DEVICE-001  Device Enrollment Policy  medium    CIS 5.10, SOC2 CC6.1, NIST PR.AC-3        
==============  ========================  ========  ==========================================

CFL-TUNNEL-001: Cloudflare Tunnels
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** tunnels

Cloudflare Tunnels provide secure outbound connections from origins, eliminating the need for open inbound ports.

**Remediation:** Use Cloudflare Tunnels for origin connections instead of exposing inbound ports.

---

CFL-GW-001: Gateway Policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** gateway

Secure Web Gateway policies enforce acceptable use and block access to malicious destinations.

**Remediation:** Configure Gateway policies to block malicious traffic and enforce acceptable use.

---

CFL-DEVICE-001: Device Enrollment Policy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** gateway

Device enrollment policies ensure only managed and compliant devices can access protected resources.

**Remediation:** Configure device enrollment rules in Zero Trust → Devices.
