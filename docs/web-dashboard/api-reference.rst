=============
API Reference
=============

The FlareInspect web dashboard exposes a REST API for programmatic
access to assessments, posture graphs, compliance reports, exports,
and (since v2.0) SIEM shipping and notification dispatch.

Base URL
--------

By default the dashboard runs at ``http://127.0.0.1:<PORT>``. The
port is displayed on startup (or set via the ``PORT`` environment
variable).

Authentication
--------------

If ``FLAREINSPECT_API_KEY`` is set, all API requests must include:

.. code-block:: text

   X-API-Key: <your-api-key>

The remediation endpoints (``/api/remediate/apply`` and
``/api/remediate/rollback``) additionally require ``FLAREINSPECT_ALLOW_REMEDIATION=true``
and a body-level ``token`` that passes ``verifyEditScope``. See
:doc:`authentication` and :doc:`/mcp/edit-scope` for the full policy.

Endpoints
---------

.. list-table::
   :header-rows: 1
   :widths: 40 12 48

   * - Endpoint
     - Method
     - Description
   * - ``/api/assessments``
     - GET
     - List all saved assessments
   * - ``/api/assessments/:id``
     - GET
     - Get a specific assessment by UUID
   * - ``/api/assess``
     - POST
     - Run a new assessment
   * - ``/api/compliance/:id/:framework``
     - GET
     - Get compliance report for an assessment
   * - ``/api/diff``
     - POST
     - Compare two assessments for drift
   * - ``/api/export/:id/:format``
     - GET
     - Download an assessment in a specific format
   * - ``/api/posture/graph``
     - GET
     - Resource graph + attack paths for an assessment (v2.0)
   * - ``/api/notify``
     - POST
     - Dispatch a summary to Slack / Teams / webhook (v2.0)
   * - ``/api/integrations/ship``
     - POST
     - Ship an assessment to Elasticsearch / Splunk HEC, or write NDJSON to disk (v2.0)
   * - ``/api/integrations/template/elastic``
     - GET
     - Return the recommended Elasticsearch index template (v2.0)
   * - ``/api/remediate/plan``
     - POST
     - Build a remediation plan (dry-run, no mutation)
   * - ``/api/remediate/apply``
     - POST
     - Apply a remediation plan (gated, mutates Cloudflare)
   * - ``/api/remediate/rollback``
     - POST
     - Roll back from a backup bundle (gated, mutates Cloudflare)
   * - ``/api/remediate/backups``
     - GET
     - List available rollback bundles
   * - ``/api/health``
     - GET
     - Health check
   * - ``/api/download/json``
     - GET
     - Download latest assessment as JSON
   * - ``/api/download/html``
     - GET
     - Download latest HTML report
   * - ``/api/download/sarif``
     - GET
     - Download SARIF
   * - ``/api/download/markdown``
     - GET
     - Download Markdown
   * - ``/api/download/csv``
     - GET
     - Download CSV
   * - ``/api/download/asff``
     - GET
     - Download ASFF
   * - ``/report``
     - GET
     - Render the embedded HTML report

Content Type
------------

All POST endpoints accept and return ``application/json``. GET
endpoints for downloads return the appropriate content type for the
requested format.

Environment variables
---------------------

The server reads the following env vars at boot.

.. list-table::
   :header-rows: 1
   :widths: 36 18 46

   * - Variable
     - Default
     - Purpose
   * - ``HOST``
     - ``127.0.0.1``
     - Bind address for the HTTP server
   * - ``PORT``
     - auto
     - Bind port (auto-selects a free port when unset)
   * - ``FLAREINSPECT_API_KEY``
     - unset
     - When set, require ``X-API-Key`` on every ``/api/*`` request
   * - ``FLAREINSPECT_ALLOW_REMEDIATION``
     - ``false``
     - Global kill-switch for ``/api/remediate/apply`` and ``/api/remediate/rollback``
   * - ``FLAREINSPECT_EDIT_SCOPE``
     - unset
     - Opaque-secret value that ``verifyEditScope`` accepts (see :doc:`/mcp/edit-scope`)
   * - ``FLAREINSPECT_ES_URL``
     - unset
     - Default ``--es-url`` for the ``ship`` CLI; the web ``/api/integrations/ship`` reads from body first
   * - ``FLAREINSPECT_ES_APIKEY``
     - unset
     - Default Elasticsearch API key (Basic-auth ``FLAREINSPECT_ES_USERNAME``/``FLAREINSPECT_ES_PASSWORD`` are also supported)
   * - ``FLAREINSPECT_SPLUNK_HEC_URL``
     - unset
     - Default ``--hec-url`` for the ``ship`` CLI
   * - ``FLAREINSPECT_SPLUNK_HEC_TOKEN``
     - unset
     - Default Splunk HEC token
   * - ``FLAREINSPECT_SLACK_WEBHOOK``
     - unset
     - Default Slack incoming-webhook URL for ``notify``
   * - ``FLAREINSPECT_TEAMS_WEBHOOK``
     - unset
     - Default Teams Power Automate webhook URL for ``notify``
   * - ``FLAREINSPECT_WEBHOOK_URL``
     - unset
     - Default generic webhook URL for ``notify``
   * - ``FLAREINSPECT_WEBHOOK_SECRET``
     - unset
     - HMAC-SHA256 secret used to sign the generic webhook payload
   * - ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY``
     - unset
     - Optional AI keys for the remediation planner (Claude / OpenAI SDKs are optional deps)
