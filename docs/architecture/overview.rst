=====================
Architecture Overview
=====================

FlareInspect follows a layered architecture with clear separation
between the CLI, core services, graph engine, integrations, the web
dashboard, and (since v2.0) the MCP server.  The resource graph is
the **single source of truth** shared by the posture map UI, the
SIEM exporters, the MCP server, and the notification dispatcher.

High-Level Architecture
------------------------

.. code-block:: text

   ┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
   │   CLI Entry  │────▶│ AssessmentService│────▶│ CloudflareClient│
   │  (index.js)  │     │                  │     │   (SDK + REST)  │
   └──────┬───────┘     └────────┬─────────┘     └────────┬────────┘
          │                      │                         │
          │                      ▼                         │
          │             ┌──────────────────┐               │
          │             │ SecurityBaseline │◀──────────────┘
          │             │  (check defs +   │
          │             │   scoring)       │
          │             └────────┬─────────┘
          │                      │
          │                      ▼
          │             ┌──────────────────┐
          │             │  ReportService   │
          │             │  (report model)  │
          │             └────────┬─────────┘
          │                      │
          ▼                      ▼
   ┌─────────────┐     ┌──────────────────┐
   │   Exporters  │     │  ComplianceEngine │
   │ html/json/  │     │  contextualScoring│
   │ sarif/csv/  │     │  diffService      │
   │ md/asff/ocsf│     │  graph + paths    │ ◀── shared by posture map,
   │ ecs/hec     │     └──────────────────┘     SIEM, MCP, notify
   └──────┬──────┘
          │
          ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                Integrations layer (v2.0)                      │
   │  src/core/integrations/siem/   → Elasticsearch / Splunk HEC  │
   │  src/core/integrations/notify/ → Slack / Teams / webhooks    │
   └──────┬──────────────────────────────────────────┬────────────┘
          │                                          │
          ▼                                          ▼
   ┌─────────────────────┐                ┌────────────────────┐
   │  Web Dashboard (SPA) │ ◀── shared ──▶ │   MCP server       │
   │  Express + static   │     graph      │   (stdio, ESM)     │
   │  posture map page   │                │   6 tools          │
   │  /api/posture/graph │                │   gated apply /    │
   │  /api/notify        │                │   rollback         │
   │  /api/integrations/*│                └────────────────────┘
   └─────────────────────┘

Key Design Decisions
----------------------

- **CloudflareClient** uses the official ``cloudflare`` v5 SDK with a ``rawRequest`` fallback for endpoints not covered by the SDK
- **SecurityBaseline** is a pure data class — check definitions and scoring logic without API calls
- **AssessmentService** orchestrates the full assessment flow with configurable concurrency via ``p-limit``
- **Exporters** are standalone classes that take an assessment object and produce format-specific output
- **Web server** validates all inputs (UUID format, framework allowlist, concurrency cap, zone list size) before processing
- **Resource graph** (``src/core/graph/resourceGraph.js``) is the single source of truth for the typed node/edge view of the account.  Built once per assessment; consumed by attack-path detection, the posture map, the SIEM shippers (for ``flareinspect.node`` and ``threat.enrichments`` enrichment), and the MCP ``get_attack_paths`` tool
- **Edit-scope policy** (``src/core/auth/editScope.js``) is shared verbatim by the MCP gated tools and the web ``/api/remediate/{apply,rollback}`` endpoints.  One policy, two surfaces — the only way to add a new mutating entry point
- **SIEM shippers** are pure functions over an assessment.  The CLI, web API, and file exporters all call the same ``shipFindings`` and ``buildIndexTemplate`` functions — there is no second implementation
- **Notification channels** are independent transport modules under ``src/core/integrations/notify/`` (``slack.js``, ``teams.js``, ``webhook.js``) selected by the ``target`` flag in the CLI / the body of ``POST /api/notify``
- **MCP server** is a thin transport layer: it parses tool calls, calls the same engine modules the CLI uses, and returns the result.  No business logic lives in ``mcp/server.mjs``
