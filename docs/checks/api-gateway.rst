===========================
API Gateway Security Checks
===========================

Checks for Cloudflare API Shield and API Discovery.

Check Summary
-------------

===========  =============  ========  ==========================================
Check ID     Title          Severity  Compliance                                
===========  =============  ========  ==========================================
CFL-API-001  API Shield     high      CIS 8.1, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1
CFL-API-002  API Discovery  medium    CIS 8.2, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1
===========  =============  ========  ==========================================

CFL-API-001: API Shield
^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** api

API Shield provides schema validation and mTLS for API endpoints. Without it, APIs are vulnerable to injection and unauthorized access.

**Remediation:** Enable API Shield for API endpoints that handle sensitive data.

---

CFL-API-002: API Discovery
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** api

API Discovery identifies undocumented or shadow APIs. Without discovery, organizations may not know the full attack surface of their API infrastructure.

**Remediation:** Enable API Discovery to inventory all API endpoints.
