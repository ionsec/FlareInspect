===============================
Cache Deception Security Checks
===============================

Checks for Cloudflare Cache Deception Armor configuration.

Check Summary
-------------

===========  =====================  ========  =================================
Check ID     Title                  Severity  Compliance                       
===========  =====================  ========  =================================
CFL-CDA-001  Cache Deception Armor  medium    CIS 4.8, SOC2 CC6.1, NIST PR.DS-5
===========  =====================  ========  =================================

CFL-CDA-001: Cache Deception Armor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** cache | **Compliance:** CIS 4.8

Cache Deception Armor prevents attackers from tricking Cloudflare into caching sensitive content by appending cacheable file extensions to URLs.

**Remediation:** Enable Cache Deception Armor in Cache → Configuration → Cache Deception Armor.
