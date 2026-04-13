================

NIST CSF Mapping

================




FlareInspect maps findings to NIST Cybersecurity Framework controls.



Usage


----


.. code-block:: bash


    flareinspect assess --token $TOKEN --compliance nist




Control Mapping


----


.. rubric:: Identify (ID)



  ==============  =======================================================

   NIST Control    Check IDs

  ==============  =======================================================

   ID.RA-1         CFL-SEC-001/002, CFL-ASM-001/002, CFL-INSIGHT-001/002

   DE.CM-1         CFL-ACC-004, CFL-LOG-001, CFL-INSIGHT-003

   DE.CM-8         CFL-ASM-001, CFL-INSIGHT-001/002/004

  ==============  =======================================================


.. rubric:: Protect (PR)



  ==============  ========================================================================================================================================================================================================

   NIST Control    Check IDs

  ==============  ========================================================================================================================================================================================================

   PR.AC-1         CFL-ACC-002, CFL-ZT-006

   PR.AC-3         CFL-ZT-003, CFL-DEVICE-001

   PR.AC-4         CFL-ACC-003, CFL-ZT-002

   PR.AC-5         CFL-ZT-004, CFL-TUNNEL-001, CFL-GW-001

   PR.AC-7         CFL-ACC-001, CFL-ACC-005, CFL-ZT-001

   PR.DS-1         CFL-SSL-001

   PR.DS-2         CFL-SSL-001/002/003/004/005, CFL-MTLS-001/002, CFL-CH-001, CFL-ORIGCERT-001, CFL-SPECTRUM-001, CFL-AIGW-001

   PR.DS-4         CFL-LB-001/002

   PR.DS-5         CFL-DNS-001/002/003/004/005, CFL-ZT-005, CFL-PAGE-001, CFL-EMAIL-001/002/003, CFL-DLP-001, CFL-INSIGHT-004/005

   PR.IP-1         CFL-WAF-001/002/003/004/005, CFL-API-001/002, CFL-BOT-001, CFL-TURN-001, CFL-WORK-001/002, CFL-PAGE-002, CFL-LOG-001, CFL-PAGESHIELD-001, CFL-CDA-001, CFL-SNIPPET-001, CFL-CFRULE-001, CFL-TXRULE-001

  ==============  ========================================================================================================================================================================================================


.. rubric:: Detect (DE)



  ==============  ===========================================

   NIST Control    Check IDs

  ==============  ===========================================

   DE.CM-1         CFL-ACC-004, CFL-LOG-001, CFL-INSIGHT-003

   DE.AE-3         CFL-LOG-001

   DE.CM-8         CFL-ASM-001, CFL-INSIGHT-001/002/004

  ==============  ===========================================
