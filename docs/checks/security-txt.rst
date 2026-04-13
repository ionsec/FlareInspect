============================
security.txt Security Checks
============================
============================

Checks for the presence and validity of a ``security.txt`` file.

Check Summary
-------------

==============  =====================  ========  ============
Check ID        Title                  Severity  Compliance  
==============  =====================  ========  ============
CFL-SECTXT-001  security.txt Presence  low       NIST PR.IP-1
==============  =====================  ========  ============

CFL-SECTXT-001: security.txt Presence
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** low | **Category:** securitytxt

A ``security.txt`` file provides security researchers with contact information and vulnerability disclosure policies.

**Remediation:** Create a ``security.txt`` file at the well-known path (``/.well-known/security.txt``) specifying your security contact and disclosure policy.
