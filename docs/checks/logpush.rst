=======================

Logpush Security Checks

=======================




Checks for Cloudflare Logpush configuration.



Check Summary


----


=============  =======================  ==========  ===========================================================

   Check ID       Title                    Severity    Compliance

=============  =======================  ==========  ===========================================================

   CFL-LOG-001    Logpush Configuration    medium      CIS 12.1, SOC2 CC7.2, PCI 10.1/10.5, NIST DE.CM-1/DE.AE-3

=============  =======================  ==========  ===========================================================


Individual Checks


----


.. rubric:: CFL-LOG-001: Logpush Configuration



**Severity:** medium | **Category:** logpush


Logpush sends Cloudflare logs (HTTP requests, firewall events, audit logs) to

external destinations for long-term retention and SIEM integration. Without

Logpush, forensic data may be lost after the Cloudflare retention period.


**Remediation:** Configure Logpush to send audit, firewall, and HTTP request logs to your SIEM or storage destination.

