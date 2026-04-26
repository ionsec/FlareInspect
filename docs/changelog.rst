=========
Changelog
=========

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
