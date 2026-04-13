==========================
Origin Certificates Checks
==========================

Checks for origin certificate expiry monitoring.

Check Summary
--------------

=====================  ========================  ========  =================================
Check ID            T  itle                      Severity  Compliance                       
=====================  ========================  ========  =================================
CFL-ORIGCERT-001    O  rigin Certificate Expiry  high      CIS 3.9, SOC2 CC6.7, NIST PR.DS-5
=====================  ========================  ========  =================================

CFL-ORIGCERT-001: Origin Certificate Expiry
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** origin-certs | **Compliance:** CIS 3.9

Origin certificates that are expired or nearing expiry cause service disruptions and browser trust errors.

**Remediation:** Monitor origin certificate expiry dates. Renew certificates before they expire and enable automatic rotation where possible.
