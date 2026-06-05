===========
Quick Start
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

Open the displayed URL in your browser. The dashboard shows assessment
history, findings, compliance scores, and report downloads.  v2.0 adds
the **Posture map** page (under the *Workspace* nav) which visualises
the resource graph and attack paths as an interactive entity graph.

If ``FLAREINSPECT_API_KEY`` is set, the dashboard requires the
``X-API-Key`` header on all API requests.

Visualise the Posture Map *(v2.0)*
-----------------------------------

After an assessment has run, open the dashboard and click
**Posture map** in the sidebar to see the typed resource graph for
your account.  Nodes are coloured by worst-finding severity; attack
paths (chains that lead to a high/critical exposure) are drawn as
animated dashed edges.  Pan / zoom with the wheel, trackpad pinch, or
the toolbar buttons; click a node to open a side-drawer with its
findings and a *Remediate* link.  See :doc:`/posture-map/index`.

Ship to a SIEM *(v2.0)*
-----------------------

Push the assessment to Elasticsearch or Splunk HEC (or both, or write
NDJSON to disk for air-gapped replay):

.. code-block:: bash

   # Elasticsearch (ECS, with attack-path enrichment)
   flareinspect ship -i flareinspect-20260412-143000.json --target elastic \
     --es-url https://es.example.com --es-api-key $ES_KEY

   # Splunk HEC
   flareinspect ship -i flareinspect-20260412-143000.json --target splunk \
     --hec-url https://splunk.example.com:8088 --hec-token $HEC_TOKEN

   # Pull / air-gapped
   flareinspect ship -i flareinspect-20260412-143000.json --target file \
     --out-dir ./out

The shipped payloads are tuned for the bundled Kibana saved-objects
bundle and Splunk TA under ``integrations/``.  See :doc:`/siem/index`.

Notify a channel *(v2.0)*
-------------------------

Dispatch a summary to Slack, Teams, or a generic webhook:

.. code-block:: bash

   flareinspect notify -i flareinspect-20260412-143000.json --target all

Use ``--threshold high`` to suppress dispatch when no finding is at
or above the threshold — useful in CI to only ping on real findings.
See :doc:`/cli/notify`.

Let an MCP-aware agent drive the loop *(v2.0)*
-----------------------------------------------

The ``flareinspect-mcp`` server (stdio) exposes the engine to any
MCP-aware agent.  Register it in your client's MCP config and let the
agent run the full assess → find → path → plan → apply loop:

.. code-block:: json

   {
     "mcpServers": {
       "flareinspect": {
         "command": "node",
         "args": ["/absolute/path/to/flareinspect/mcp/server.mjs"]
       }
     }
   }

See :doc:`/mcp/index`.

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
