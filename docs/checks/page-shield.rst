==================

Page Shield Checks

==================




Checks for Cloudflare Page Shield JavaScript monitoring.



Check Summary


----


  ====================  ========================  ==========  ============================================

   Check ID              Title                     Severity    Compliance

  ====================  ========================  ==========  ============================================

   CFL-PAGESHIELD-001    Page Shield Monitoring    high        CIS 4.7, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1

  ====================  ========================  ==========  ============================================


Individual Checks


----


.. rubric:: CFL-PAGESHIELD-001: Page Shield Monitoring



**Severity:** high | **Category:** page-shield


Page Shield monitors JavaScript dependencies loaded by your website and alerts

on new, changed, or suspicious scripts that may indicate a supply chain

attack. FlareInspect checks whether Page Shield is enabled.


**Remediation:** Enable Page Shield in Security → Page Shield to monitor JavaScript dependencies and detect supply chain attacks.

