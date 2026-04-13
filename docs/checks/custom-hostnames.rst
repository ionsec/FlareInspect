================================
Custom Hostnames Security Checks
================================
================================

Checks for custom hostname validation and security.

Check Summary
-------------

==========  ==========================  ========  =================================
Check ID    Title                       Severity  Compliance                       
==========  ==========================  ========  =================================
CFL-CH-001  Custom Hostname Validation  medium    CIS 3.8, SOC2 CC6.7, NIST PR.DS-5
==========  ==========================  ========  =================================

CFL-CH-001: Custom Hostname Validation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** custom-hostnames | **Compliance:** CIS 3.8

Custom hostnames should have proper validation methods (HTTP, email, or TXT) configured. Hostnames without validation can be claimed by unauthorized parties.

**Remediation:** Ensure all custom hostnames use a validation method and regularly review hostname ownership.
