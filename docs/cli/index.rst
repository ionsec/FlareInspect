=============
CLI Reference
=============
=============

.. toctree::
   :maxdepth: 1
   :hidden:

   assess
   export
   diff
   interactive-mode
   global-options

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Command
     - Description
   * - ``assess``
     - Run a comprehensive Cloudflare security assessment
   * - ``export``
     - Export a saved assessment to HTML, JSON, SARIF, Markdown, CSV, or ASFF
   * - ``diff``
     - Compare two assessment runs and report posture drift
   * - ``interactive``
     - Step-by-step guided assessment via an interactive prompt

Quick Reference
---------------

.. code-block:: bash

   # Run assessment
   flareinspect assess --token $TOKEN

   # Export results
   flareinspect export -i report.json -f html -o report.html

   # Compare two runs
   flareinspect diff --baseline old.json --current new.json
