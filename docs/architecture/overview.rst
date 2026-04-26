=====================
Architecture Overview
=====================

FlareInspect follows a layered architecture with clear separation between the CLI, core services, exporters, and web dashboard.

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
   │ html/json/   │     │  contextualScoring│
   │ sarif/csv/   │     │  diffService      │
   │ md/asff/ocsf │     └──────────────────┘
   └─────────────┘

   ┌─────────────────────────────────────────────────────┐
   │                  Web Dashboard                        │
   │  Express server → AssessmentService → File Storage   │
   │  Static frontend (app.js + styles.css)               │
   └─────────────────────────────────────────────────────┘

Key Design Decisions
----------------------

- **CloudflareClient** uses the official ``cloudflare`` v5 SDK with a ``rawRequest`` fallback for endpoints not covered by the SDK
- **SecurityBaseline** is a pure data class — check definitions and scoring logic without API calls
- **AssessmentService** orchestrates the full assessment flow with configurable concurrency via ``p-limit``
- **Exporters** are standalone classes that take an assessment object and produce format-specific output
- **Web server** validates all inputs (UUID format, framework allowlist, concurrency cap, zone list size) before processing
