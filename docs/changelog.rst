=========
Changelog
=========

2.0.0 — 2026-06-05
--------------------

.. rubric:: Resource graph + attack-path engine

- **Resource graph** (``src/core/graph/resourceGraph.js``) — typed node
  view of the account: 14 node types (``internet``, ``account``,
  ``zone``, ``dns_record``, ``origin``, ``worker``, ``tunnel``,
  ``access_app``, ``r2_bucket``, ``kv_namespace``, ``d1_database``,
  ``queue``, ``service``, ``finding``) and 8 edge types
  (``belongs_to``, ``resolves_to``, ``proxies``, ``exposes``,
  ``protects``, ``executes``, ``reads``, ``internet_to``).  The
  graph is the **single source of truth** shared by the posture
  map UI, the SIEM shippers, the MCP server, and the notification
  dispatcher.
- **Attack-path engine** (``src/core/graph/attackPaths.js``) — five
  deterministic, ordered rule-based detectors:
  ``exposed-origin``, ``weak-transport``, ``open-access-app``,
  ``tunnel-without-access``, ``worker-plaintext-secret``.  Same
  input → same path IDs, so the UI can deep-link a path.
- See :doc:`/architecture/resource-graph` for the full data model.

.. rubric:: Posture map

- **Dashboard page** — Wiz-style entity graph that visualises the
  account's Cloudflare entities (Internet → Account → Zones →
  services) as connected nodes, colours them by finding severity,
  and highlights attack paths (chains that lead to a high/critical
  exposure) as animated dashed edges.  Pan / zoom / hover / click
  with full keyboard and trackpad support.  ``prefers-reduced-motion``
  disables the dash animation.
- New endpoint: ``GET /api/posture/graph?assessmentId=<id>``.
- Source: ``web/public/postureMap.{js,css}``.
- See :doc:`/posture-map/index`.

.. rubric:: SIEM shipping

- **Elasticsearch shipper** (``src/core/integrations/siem/elastic.js``) —
  ECS 8.11.0-aligned documents, ``POST {esUrl}/_bulk``, ApiKey or
  Basic auth, nested ``threat.enrichments`` mapping.
- **Splunk HEC shipper** (``src/core/integrations/siem/splunk.js``) —
  CIM-aligned envelopes, ``POST {hecUrl}/services/collector/event``,
  ``Authorization: Splunk <token>``, per-event error aggregation.
- **Enrichment** (``src/core/integrations/siem/enrichment.js``) —
  joins each finding to its graph node and every attack path it
  participates in.  The only place this join happens; both shippers
  consume it.
- **File exporters** (``src/exporters/ecs.js``,
  ``src/exporters/splunkHec.js``) — write the same NDJSON the live
  shipper would have posted (pull / air-gapped mode).
- **``flareinspect ship`` CLI** with ``--target elastic|splunk|all|file``,
  ``--dry-run``, env-var fallbacks.
- **``POST /api/integrations/ship``** web endpoint mirroring the CLI
  surface.
- **``GET /api/integrations/template/elastic``** for scripted ES
  template bootstrap.
- **Packaged Kibana app** —
  ``integrations/elastic/flareinspect-dashboard.ndjson`` (data view
  + saved search + 2 visualizations + dashboard) importable via
  Kibana → Saved Objects → Import.
- **Packaged Splunk TA** —
  ``integrations/splunk/TA-flareinspect/`` with field extractions,
  transforms, 2 saved searches, and a SimpleXML dashboard.
- See :doc:`/siem/index`, :doc:`/siem/elastic`, :doc:`/siem/splunk`.

.. rubric:: MCP server

- **stdio MCP server** (``mcp/server.mjs``) exposing the engine as
  six tools: ``flareinspect_assess``, ``flareinspect_list_findings``,
  ``flareinspect_get_attack_paths``, ``flareinspect_plan_remediation``,
  ``flareinspect_apply_remediation`` *(gated)*, ``flareinspect_rollback``
  *(gated)*.  Re-uses existing engine seams; no logic duplication.
  ``@modelcontextprotocol/sdk`` is an *optional* dependency.
- **Edit-scope policy** (``src/core/auth/editScope.js``) — shared
  between the MCP gated tools and the web ``/api/remediate/{apply,rollback}``
  endpoints.  Two conditions: ``FLAREINSPECT_ALLOW_REMEDIATION=true``
  *and* a token that satisfies ``verifyEditScope`` (opaque env-bound
  secret, or a JWT with ``permission: 'edit'`` / ``aud`` containing
  ``tag:edit`` / ``scope`` containing ``edit``).
- See :doc:`/mcp/index`, :doc:`/mcp/edit-scope`.

.. rubric:: Notifications

- **``flareinspect notify`` CLI** with ``--target slack|teams|webhook|all``.
- **Three channels**: Slack (Block Kit), Microsoft Teams (Adaptive
  Card 1.5), generic webhook (HMAC-SHA256-signed, ``X-FlareInspect-Signature``
  header).  Per-channel URL + secret via flag or env var.
- **``POST /api/notify``** web endpoint mirroring the CLI surface.
- **Severity threshold** (``--threshold critical|high|medium|low``)
  suppresses dispatch when nothing is at or above the threshold —
  useful in CI to only ping on real findings.
- See :doc:`/cli/notify`.

.. rubric:: New check categories

The assessable surface grew from 21 to 34 categories.  New in v2.0:

- ``credentials`` — Leaked Credentials Detection
- ``notifications`` — 4 security notification types (account-scoped)
- ``ddos`` — L7 DDoS posture (advisory)
- ``account-waf`` — account-level WAF coverage (advisory)
- ``workers`` — Workers inventory + plaintext-secret bindings
- ``storage`` — KV / D1 / Queues inventory
- ``zaraz`` — Zaraz third-party tools + consent
- ``posture`` — device posture rules
- ``access`` — Access application depth (allow-everyone, MFA, session duration)
- ``casb`` — open critical/high CASB findings
- ``email-security`` — Cloud Email Security policies
- ``rbi`` — Browser Isolation policies
- ``magic`` — Magic Firewall / Magic Transit rulesets
- ``performance`` — Brotli / HTTP/2-3 / Cache Deception Armor / Email Obfuscation
- ``rules`` — rules / rate-limit rules
- ``spectrum`` — Spectrum (TCP/UDP) configuration
- ``turnstile`` — Turnstile configuration
- ``loadbalancing`` — Load Balancing posture

Plus the ``leaked-credentials``, ``magic-firewall``, ``device-posture``,
``browser-isolation``, and ``cloud-email-security`` aliases.

.. rubric:: Test coverage

- 262 tests pass (was 140 in 1.3.0).  New test files:
  ``tests/resourceGraph.test.js``, ``tests/attackPaths.test.js``,
  ``tests/foundationStability.test.js``, ``tests/siemEnrichment.test.js``,
  ``tests/elastic.test.js``, ``tests/splunk.test.js``,
  ``tests/siemExporters.test.js``, ``tests/shipCli.test.js``,
  ``tests/integrationsShip.test.js``, ``tests/packagedApps.test.js``,
  ``tests/mcpServer.test.js``, ``tests/editScope.test.js``,
  ``tests/phase2Remediation.test.js`` (Phase 2/3/4 advisory coverage).

1.3.0 — 2026-04-26
--------------------

.. rubric:: SDK Migration

- **Cloudflare SDK v5** — Migrated from ``cloudflare`` v4.5.0 to v5.2.0
- Updated all zone-scoped resource paths (``client.zones.dnsRecords`` → ``client.dns.records``, etc.)
- Updated account-scoped resource paths (``client.accounts.auditLogs`` → ``client.auditLogs``, etc.)
- Adapted response unwrapping for v5's direct-return pattern on ``.get()`` calls
- Added ``_unwrapList()`` helper to normalize v5 Page object responses
- Updated error handling to use typed ``APIError`` subclasses (``error.status``, ``error.errors``)
- Converted ``getZoneAnalytics()`` and ``getSecurityAnalytics()`` to ``rawRequest()`` (no v5 SDK equivalent)
- Fixed ``rulesets.get()`` call signature for v5 positional ``rulesetId`` argument
- Removed optional chaining guards (``?.``) on SDK resources (v5 has stable resource structure)

1.2.2 — 2026-04-26
--------------------

.. rubric:: New checks

- **CFL-TOK-001 — API token pre-flight** (critical). Before the assessment runs, the token is
  verified against ``/user/tokens/verify``; emits FAIL if disabled or expiring within 14 days,
  WARNING if verify itself fails. Token info is persisted on ``assessment.tokenInfo`` for the
  dashboard and report.
- **CFL-R2-001/002/003 — R2 bucket posture**. Enumerates R2 buckets per account and emits findings
  for: public access via custom domain or wildcard CORS (high), missing lifecycle rules (low),
  missing event notifications (low). Skipped silently when the token lacks R2 read scope.
- **CFL-WAF-006/007/008 — WAF managed rulesets**. Detects whether the Cloudflare Managed Ruleset
  and OWASP Core Ruleset are deployed at zone scope, and flags any managed ruleset overridden to
  log-only mode (production drift).

.. rubric:: Tests

- 16 new unit tests covering the new check definitions and assessment methods.
  Suite size: 124 → **140 tests**, all green.

1.2.1 — 2026-04-25
--------------------

.. rubric:: Brand & UI

- **New brand identity** — flare-in-reticle mark with FlareInspect wordmark (Manrope/Fraunces/Geist Mono).
  Replaces the previous Cloudflare-style shield.
- **Redesigned web dashboard** — V1 "Command" layout with sidebar nav, sticky topbar, score-ring hero,
  severity strip, compliance rail, findings table, and zone matrix. Dark-only.
- **Redesigned HTML report** — masthead with KPI strip, score hero, summary cards, charts, top risks,
  per-zone domains table, security insights, severity sections, recommendations, and category posture.
- **CLI banner** — recolored to flare orange with mono-feel rule lines and the new tagline
  ``by ionsec.io · cloudflare posture``.

.. rubric:: Dependencies & security

- Replaced ``uuid`` (vulnerable) with Node's built-in ``crypto.randomUUID()`` — drops one dependency
  and removes the moderate-severity ``uuid`` advisory.
- Bumped ``jest`` to ^30 and added overrides for ``test-exclude``, ``formdata-node``, and ``glob``
  to clear ``inflight@1.0.6`` and ``glob@7`` deprecation/security warnings.
- ``npm audit`` now reports **0 vulnerabilities**.

.. rubric:: Tests

- All 62 existing tests still pass against the updated template and dependencies.

----

1.2.0 — 2026-04-13
--------------------

.. rubric:: Cloud Deployment

- **1-Click Deployment** — Deploy to Render, Heroku, Railway, or Fly.io with single-click buttons
- **Heroku Button** — Added ``app.json`` for one-click Heroku deployment with pre-configured environment variables
- **Render Configuration** — Enhanced ``render.yaml`` with 1 GB persistent storage for assessment history
- **Railway Template** — Added ``railway.json`` for Railway deployment with auto-restart policies
- **Fly.io Configuration** — Added ``fly.toml`` for edge deployment with health checks and auto-scaling
- **Deployment Guide** — New ``DEPLOYMENT.md`` with step-by-step instructions for all platforms

.. rubric:: Documentation

- Updated README with version badge, deployment buttons, and cloud hosting options
- Added deployment overview page and dedicated guides for Heroku, Railway, and Fly.io
- Updated index page to include deployment feature row and quick-deploy buttons
- Refreshed ``render.md`` to reflect 1 GB persistent storage

----

1.1.0 — 2026-04-12
--------------------

- Added ``diff`` command for baseline drift detection
- Added compliance mapping for ``cis``, ``soc2``, ``pci``, and ``nist``
- Added contextual scoring and CI/CD gating options for ``assess``
- Added exporters for ``sarif``, ``markdown``, ``csv``, and ``asff``
- Added config file loading via ``.flareinspect.yml``, ``.flareinspect.yaml``, and ``flareinspect.config.json``
- Expanded web API with assessment history, compliance, drift comparison, API key auth, and extra download endpoints
- Added plugin loader scaffolding and automated tests for new modules
- Updated Docker, Render, linting, and repository metadata for a coherent 1.1.0 release
