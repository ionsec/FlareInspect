==============
Export Formats
==============

.. toctree::
   :maxdepth: 1
   :hidden:

   json
   html
   sarif
   markdown
   csv
   ocsf
   asff

FlareInspect can export assessment results to multiple formats for different audiences and integrations.

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - Format
     - Use Case
     - Command
   * - ``json``
     - Machine-readable, re-importable full results
     - ``flareinspect export -i a.json -f json -o out.json``
   * - ``html``
     - Shareable interactive report for browsers
     - ``flareinspect export -i a.json -f html -o report.html``
   * - ``sarif``
     - GitHub Advanced Security integration
     - ``flareinspect export -i a.json -f sarif -o results.sarif``
   * - ``markdown``
     - Text-based report for wikis and documentation
     - ``flareinspect export -i a.json -f markdown -o report.md``
   * - ``csv``
     - Tabular findings for spreadsheet analysis
     - ``flareinspect export -i a.json -f csv -o findings.csv``
   * - ``ocsf``
     - OCSF normalized JSON for SIEM integration
     - ``flareinspect export -i a.json -f ocsf -o ocsf.json``
   * - ``asff``
     - AWS Security Finding Format for Security Hub
     - ``flareinspect export -i a.json -f asff -o findings-asff.json``
