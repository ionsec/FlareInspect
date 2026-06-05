=============
CLI Reference
=============

.. toctree::
   :maxdepth: 1
   :hidden:

   assess
   export
   diff
   ship
   notify
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
     - Export a saved assessment to HTML, JSON, SARIF, Markdown, CSV, OCSF, ECS, or HEC
   * - ``diff``
     - Compare two assessment runs and report posture drift
   * - ``ship`` *(v2.0)*
     - Push an assessment to Elasticsearch, Splunk, or both — or write NDJSON to disk
   * - ``notify`` *(v2.0)*
     - Dispatch a summary to Slack, Microsoft Teams, or a generic webhook
   * - ``remediate``
     - AI-assisted, safety-first fix of reversible findings
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

   # Ship to a SIEM
   flareinspect ship -i report.json --target elastic \
     --es-url https://es.example.com --es-api-key $ES_KEY

   # Notify Slack / Teams / webhook
   flareinspect notify -i report.json --target all

   # Plan + apply reversible fixes
   flareinspect remediate plan -i report.json --token $TOKEN
   flareinspect remediate apply -i report.json --token $TOKEN --apply
