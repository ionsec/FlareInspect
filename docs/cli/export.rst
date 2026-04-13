==============
export Command
==============

Export a saved assessment to a different file format. This is useful for generating human-readable reports, integrating with security tools, or uploading to compliance platforms.

Usage
-----

.. code-block:: bash

   flareinspect export [options]

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 24 62 14

   * - Option
     - Description
     - Default
   * - ``-i, --input <file>``
     - Input assessment file (JSON) *(required)*
     - —
   * - ``-o, --output <file>``
     - Output file path *(required)*
     - —
   * - ``-f, --format <format>``
     - Export format: ``json``, ``html``, ``ocsf``, ``sarif``, ``markdown``, ``csv``, or ``asff``
     - ``json``

Formats
-------

============  =======================================================================
Format        Use Case                                                               
============  =======================================================================
``json``      Machine-readable, re-importable full results                           
``html``      Shareable interactive report for browsers                              
``ocsf``      OCSF (Open Cybersecurity Schema Framework) normalized JSON             
``sarif``     Static Analysis Results Interchange Format for GitHub Advanced Security
``markdown``  Text-based report for wikis and documentation                          
``csv``       Tabular findings for spreadsheet analysis                              
``asff``      AWS Security Finding Format for Security Hub integration               
============  =======================================================================

Examples
--------

.. rubric:: Export to HTML

.. code-block:: bash

   flareinspect export -i assessment.json -f html -o report.html

.. rubric:: Export to SARIF for GitHub Advanced Security

.. code-block:: bash

   flareinspect export -i assessment.json -f sarif -o results.sarif

.. rubric:: Export to CSV for Spreadsheet Analysis

.. code-block:: bash

   flareinspect export -i assessment.json -f csv -o findings.csv

.. rubric:: Export to OCSF

.. code-block:: bash

   flareinspect export -i assessment.json -f ocsf -o assessment-ocsf.json

.. rubric:: Export to ASFF (AWS Security Finding Format)

.. code-block:: bash

   flareinspect export -i assessment.json -f asff -o findings-asff.json

.. rubric:: Export to Markdown

.. code-block:: bash

   flareinspect export -i assessment.json -f markdown -o report.md
