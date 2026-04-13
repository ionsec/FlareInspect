Export Formats
==============

.. toctree::
   :maxdepth: 1
   :hidden:

   json
   html
   ocsf
   sarif
   markdown
   csv
   asff

FlareInspect can export assessment results in seven formats.

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Format
     - Extension
     - Use Case
   * - JSON
     - ``.json``
     - Programmatic processing, SIEM ingestion
   * - HTML
     - ``.html``
     - Human review, sharing with non-technical stakeholders
   * - OCSF
     - ``.ocsf.json``
     - Open Cybersecurity Schema Framework — SIEM/SOAR platforms
   * - SARIF
     - ``.sarif.json``
     - CI/CD pipelines, GitHub Advanced Security
   * - Markdown
     - ``.md``
     - Documentation, issue tracking
   * - CSV
     - ``.csv``
     - Spreadsheets, data analysis
   * - ASFF
     - ``.asff.json``
     - AWS Security Hub, AWS Config

Example export:

.. code-block:: bash

   flareinspect export -i assessment.json -f html -o report.html
