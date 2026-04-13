=======================
Logpush Security Checks
=======================
=======================

Checks for Cloudflare Logpush destination and coverage.

Check Summary
-------------

===========  ===================  ========  ============================================
Check ID     Title                Severity  Compliance                                  
===========  ===================  ========  ============================================
CFL-LOG-001  Logpush Destination  high      CIS 12.1, SOC2 CC7.2, PCI 10.1, NIST DE.CM-1
===========  ===================  ========  ============================================

CFL-LOG-001: Logpush Destination
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** logpush | **Compliance:** CIS 12.1

Logpush sends request logs to external storage or SIEM systems. Without a Logpush destination, forensic and compliance log data is lost after Cloudflare's retention period.

**Remediation:** Configure Logpush to send logs to a SIEM or long-term storage destination.
