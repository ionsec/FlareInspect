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

Interactive docs (Swagger / OpenAPI)
------------------------------------

A bundled, interactive **Swagger UI** is served by the dashboard:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - URL
     - Description
   * - ``/api-docs``
     - Swagger UI — browse every endpoint and *Try it out* against the running server
   * - ``/api-docs/openapi.json``
     - The raw OpenAPI 3 specification (machine-readable; import into Postman/Insomnia)

The same link is available from the dashboard sidebar (**API docs**) and the
**API health** page. When ``FLAREINSPECT_API_KEY`` is set, use the *Authorize*
button in Swagger UI to supply your key for *Try it out* requests.

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
   * - ``/api/assessment``
     - GET
     - Get the latest assessment
   * - ``/api/assessments``
     - GET
     - List all saved assessments
   * - ``/api/assessments/:id``
     - GET
     - Get a specific assessment by UUID
   * - ``/api/assess``
     - POST
     - Run a new assessment
   * - ``/api/compliance/:framework``
     - GET
     - Map the latest assessment's findings to a compliance framework
   * - ``/api/diff``
     - POST
     - Compare two assessments for drift
   * - ``/api/settings``
     - GET / PUT
     - Read (masked) or update the runtime settings overlay — notifications, AI, SIEM (v2.0)
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
   * - ``FLAREINSPECT_NOTIFY_THRESHOLD``
     - unset
     - Default minimum severity for notifications (``critical|high|medium|low|informational``)
   * - ``FLAREINSPECT_AI_PROVIDER`` / ``FLAREINSPECT_AI_MODEL``
     - unset
     - Default AI planner provider (``none|anthropic|openai|ollama``) and model
   * - ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY``
     - unset
     - Optional AI keys for the remediation planner (Claude / OpenAI SDKs are optional deps)
   * - ``OLLAMA_HOST``
     - ``http://localhost:11434``
     - Base URL for a local Ollama server (offline AI planner)

Runtime settings overlay
------------------------

Notifications, the AI planner, and SIEM credentials can be configured from the
dashboard's **Settings** page instead of (or in addition to) the environment.
Values are persisted to a local, git-ignored ``web/data/settings.json`` (mode
``0600``) and **override** the matching environment variable at request time.

Resolution precedence for every key is: **saved settings value → environment
variable → unset**. Reading the overlay (``GET /api/settings``) never returns
secrets in the clear — only whether each key is ``configured``, its ``source``
(``settings`` / ``env`` / ``none``), and a short masked ``hint``.

The remediation gate (``FLAREINSPECT_ALLOW_REMEDIATION``) and edit-scope token
(``FLAREINSPECT_EDIT_SCOPE``) are intentionally **not** part of this overlay —
they remain env-only so live Cloudflare writes can never be enabled from the
browser.
