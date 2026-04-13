===============
PCI-DSS Mapping
===============

FlareInspect maps findings to Payment Card Industry Data Security Standard v4.0 controls.

Usage
-----

.. code-block:: bash

   flareinspect assess --token $TOKEN --compliance pci

Control Mapping
---------------

===============  =======================================================================
PCI Requirement  Check IDs                                                              
===============  =======================================================================
3.4              CFL-SSL-001, CFL-SSL-004, CFL-MTLS-001 — Protect stored cardholder data
6.5              CFL-WAF-001–005, CFL-API-001 — Secure application development          
8.1              CFL-ACC-003 — User identification                                      
8.3              CFL-ACC-001, CFL-ACC-005, CFL-ZT-001 — MFA                             
8.6              CFL-ACC-002, CFL-ZT-006 — Secure authentication                        
10.1             CFL-ACC-004, CFL-LOG-001 — Audit logging                               
===============  =======================================================================
