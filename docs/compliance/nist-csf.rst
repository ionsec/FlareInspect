================
NIST CSF Mapping
================

FlareInspect maps findings to NIST Cybersecurity Framework controls.

Usage
-----

.. code-block:: bash

   flareinspect assess --token $TOKEN --compliance nist

Control Mapping
---------------

.. rubric:: Identify (ID)

============  =====================================================
NIST Control  Check IDs                                            
============  =====================================================
ID.RA-1       CFL-SEC-001/002, CFL-ASM-001/002, CFL-INSIGHT-001/002
============  =====================================================

.. rubric:: Protect (PR)

============  ===================================================================================================================================
NIST Control  Check IDs                                                                                                                          
============  ===================================================================================================================================
PR.AC-1       CFL-ACC-002, CFL-ZT-001, CFL-ZT-006                                                                                                
PR.AC-3       CFL-ZT-003, CFL-DEVICE-001                                                                                                         
PR.AC-4       CFL-ACC-003, CFL-ZT-002                                                                                                            
PR.AC-5       CFL-ZT-004, CFL-TUNNEL-001                                                                                                         
PR.AC-7       CFL-ACC-001, CFL-ACC-005                                                                                                           
PR.DS-5       CFL-SSL-001–005, CFL-DNS-001, CFL-MTLS-001, CFL-INSIGHT-002, CFL-DLP-001, CFL-PAGESHIELD-001, CFL-CDA-001, CFL-CH-001, CFL-AIGW-001
PR.IP-1       CFL-WAF-001–005, CFL-API-001/002, CFL-WORK-001/002, CFL-PAGE-001/002, CFL-TXRULE-001                                               
============  ===================================================================================================================================

.. rubric:: Detect (DE)

============  =========================================
NIST Control  Check IDs                                
============  =========================================
DE.CM-1       CFL-ACC-004, CFL-LOG-001, CFL-INSIGHT-003
DE.CM-8       CFL-ASM-001, CFL-INSIGHT-001/002/004     
============  =========================================

.. rubric:: Respond (RS) and Recover (RC)

NIST RS and RC controls are primarily procedural and are not directly mapped to technical checks. FlareInspect findings that support incident response include audit log availability and Logpush configuration.
