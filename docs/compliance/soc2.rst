=============
SOC 2 Mapping
=============

FlareInspect maps findings to SOC 2 Trust Services Criteria.

Usage
-----

.. code-block:: bash

   flareinspect assess --token $TOKEN --compliance soc2

Control Mapping
---------------

.. rubric:: Common Criteria

=============  =====================================================================
SOC 2 Control  Check IDs                                                            
=============  =====================================================================
CC3.1          CFL-SEC-001, CFL-INSIGHT-003 — Risk assessment                       
CC6.1          CFL-ACC-001, CFL-ACC-003, CFL-ZT-001, CFL-ZT-002 — Logical access    
CC6.2          CFL-ACC-003, CFL-ZT-001 — Role-based access                          
CC6.3          CFL-ZT-002 — Access policies                                         
CC6.6          CFL-ZT-004, CFL-WORK-002 — Network security                          
CC6.7          CFL-SSL-001, CFL-DNS-001, CFL-MTLS-001, CFL-DLP-001 — Data protection
CC7.2          CFL-ACC-004, CFL-LOG-001, CFL-ZT-006 — Monitoring                    
CC8.1          CFL-WORK-001 — Change management                                     
=============  =====================================================================

.. rubric:: Additional Criteria

===================  ===============================================================
SOC 2 Control        Check IDs                                                      
===================  ===============================================================
P1.1              C  FL-WAF-001, CFL-WAF-003, CFL-INSIGHT-004 — Processing integrity
P2.1              C  FL-SSL-002, CFL-SSL-004 — Processing controls                  
C1.1              C  FL-DLP-001, CFL-INSIGHT-002 — Confidentiality                  
C2.1              C  FL-SSL-001, CFL-MTLS-001 — Confidentiality controls            
===================  ===============================================================
