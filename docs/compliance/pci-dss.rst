===============

PCI-DSS Mapping

===============




FlareInspect maps findings to Payment Card Industry Data Security Standard

(PCI-DSS) requirements.



Usage


----


.. code-block:: bash


    flareinspect assess --token $TOKEN --compliance pci




Key Control Mappings


----


=================  ==========================================================================================================================

   PCI-DSS Control    Check IDs

=================  ==========================================================================================================================

   1.3                CFL-ZT-004, CFL-TUNNEL-001, CFL-GW-001

   3.4                CFL-ZT-005, CFL-DLP-001, CFL-PAGESHIELD-001

   4.1                CFL-DNS-001/002/004/005, CFL-SSL-001/002/003/004/005, CFL-MTLS-001/002, CFL-CH-001, CFL-ORIGCERT-001

   4.2                CFL-SSL-001/002/004, CFL-DLP-001, CFL-ORIGCERT-001

   6.1                CFL-SSL-004

   6.5                CFL-WAF-001/002/003/004/005, CFL-API-001/002, CFL-BOT-001, CFL-TURN-001, CFL-PAGESHIELD-001, CFL-CDA-001, CFL-TXRULE-001

   6.6                CFL-WAF-001, CFL-WAF-005

   8.1                CFL-ACC-003

   8.2                CFL-SSL-002, CFL-MTLS-001

   8.3                CFL-ACC-001, CFL-ACC-005, CFL-ZT-001, CFL-DEVICE-001

   8.6                CFL-ACC-002, CFL-ZT-006, CFL-INSIGHT-004

   10.1               CFL-ACC-004, CFL-LOG-001

   10.5               CFL-LOG-001

=================  ==========================================================================================================================
