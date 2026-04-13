====================
mTLS Security Checks
====================

Checks for mutual TLS enforcement and certificate rotation.

Check Summary
-------------

============  =========================  ========  ==========================================
Check ID      Title                      Severity  Compliance                                
============  =========================  ========  ==========================================
CFL-MTLS-001  mTLS Enforcement           high      CIS 3.6, SOC2 CC6.7, PCI 3.4, NIST PR.DS-5
CFL-MTLS-002  mTLS Certificate Rotation  medium    SOC2 CC6.7, NIST PR.DS-5                  
============  =========================  ========  ==========================================

CFL-MTLS-001: mTLS Enforcement
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** mtls | **Compliance:** CIS 3.6

Mutual TLS ensures both the client and server authenticate. Without mTLS, any client can connect to the origin.

**Remediation:** Enable mTLS for sensitive API endpoints and origin connections.

---

CFL-MTLS-002: mTLS Certificate Rotation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** mtls

mTLS client certificates should be rotated regularly. Expired or stale certificates undermine the mTLS trust model.

**Remediation:** Implement a certificate rotation schedule and monitor certificate expiry dates.
