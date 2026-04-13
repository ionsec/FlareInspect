===========================

API Gateway Security Checks

===========================




Checks for Cloudflare API Shield and API Discovery.



Check Summary


----


=============  ===============  ==========  ============================================

   Check ID       Title            Severity    Compliance

=============  ===============  ==========  ============================================

   CFL-API-001    API Shield       high        CIS 8.1, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1

   CFL-API-002    API Discovery    medium      CIS 8.2, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1

=============  ===============  ==========  ============================================


Individual Checks


----


.. rubric:: CFL-API-001: API Shield



**Severity:** high | **Category:** api


API Shield provides schema validation, bot protection, and mTLS for API

endpoints. FlareInspect checks whether API Shield is enabled for the zone.


**Remediation:** Enable API Shield for schema validation and bot protection on API endpoints.



.. rubric:: CFL-API-002: API Discovery



**Severity:** medium | **Category:** api


API Discovery identifies shadow APIs and undocumented endpoints that may lack

proper security controls.


**Remediation:** Enable API Discovery to detect shadow APIs and undocumented endpoints.

