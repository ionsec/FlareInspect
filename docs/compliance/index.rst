Compliance Mapping
==================

.. toctree::
   :maxdepth: 1
   :hidden:

   cis
   soc2
   pci-dss
   nist-csf

FlareInspect maps security findings to four industry-standard compliance frameworks.

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Framework
     - Description
   * - CIS Benchmark
     - Center for Internet Security Controls v8
   * - SOC 2
     - Service Organization Control 2 (Trust Services Criteria)
   * - PCI-DSS
     - Payment Card Industry Data Security Standard v4.0
   * - NIST CSF
     - NIST Cybersecurity Framework 2.0

Compliance reports are generated from assessment findings. Run an assessment and use
the ``--compliance`` flag:

.. code-block:: bash

   flareinspect assess --token $TOKEN --compliance cis -o cis-report.json
