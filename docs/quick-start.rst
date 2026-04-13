===========
Quick Start
===========
===========

Run an Assessment
------------------

.. code-block:: bash

   flareinspect assess --token YOUR_CLOUDFLARE_TOKEN

This runs all check categories across every zone in your account. Results are saved to a timestamped JSON file and a summary is printed to the terminal.

To scope the assessment to specific zones:

.. code-block:: bash

   flareinspect assess --token YOUR_CLOUDFLARE_TOKEN --zones example.com,docs.example.com

Export a Report
----------------

Convert a saved assessment into the format you need.

HTML Report
^^^^^^^^^^^

.. code-block:: bash

   flareinspect export -i flareinspect-20260412-143000.json -f html -o report.html

SARIF (for GitHub Advanced Security)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   flareinspect export -i flareinspect-20260412-143000.json -f sarif -o results.sarif

CSV (for spreadsheet analysis)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   flareinspect export -i flareinspect-20260412-143000.json -f csv -o findings.csv

Other supported formats: ``json``, ``markdown``, ``ocsf``, ``asff``. See :doc:`cli/export` for details.

Compare Two Runs
-----------------

Detect security posture drift between a baseline and a current assessment:

.. code-block:: bash

   flareinspect diff --baseline baseline.json --current latest.json

The command prints a drift report showing new, resolved, regressed, and improved findings. It exits with code ``1`` when regressions are detected — useful for CI pipelines.

Export the diff as Markdown:

.. code-block:: bash

   flareinspect diff --baseline baseline.json --current latest.json -f markdown -o drift.md

Start the Web Dashboard
-------------------------

.. code-block:: bash

   node web/server.js

Or with a custom host and port:

.. code-block:: bash

   HOST=0.0.0.0 PORT=8080 node web/server.js

Open the displayed URL in your browser. The dashboard shows assessment history, findings, compliance scores, and report downloads.

If ``FLAREINSPECT_API_KEY`` is set, the dashboard requires the ``X-API-Key`` header on all API requests.

CI/CD Mode
-----------

Run FlareInspect in a pipeline with strict pass/fail gating:

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN \
     --ci \
     --threshold 80 \
     --fail-on high

==================  ============================================================================
Flag                Behavior                                                                    
==================  ============================================================================
``--ci``            Outputs JSON to stdout, disables spinners and banners                       
``--threshold 80``  Exits with code ``1`` if the overall score is below 80                      
``--fail-on high``  Exits with code ``1`` if any finding with severity **high** or above is FAIL
==================  ============================================================================

Combine with SARIF export to upload results to GitHub Advanced Security:

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --ci --threshold 80
   flareinspect export -i flareinspect-*.json -f sarif -o results.sarif
