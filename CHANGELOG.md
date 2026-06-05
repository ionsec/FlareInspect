# Changelog

## 2.0.0 — 2026-06-05

### Resource graph + attack-path engine

- **Resource graph** (`src/core/graph/resourceGraph.js`) — typed node/edge view of the account: 14 node types (`internet`, `account`, `zone`, `dns_record`, `origin`, `worker`, `tunnel`, `access_app`, `r2_bucket`, `kv_namespace`, `d1_database`, `queue`, `service`, `finding`) and 8 edge types (`belongs_to`, `resolves_to`, `proxies`, `exposes`, `protects`, `executes`, `reads`, `internet_to`). The graph is the **single source of truth** shared by the posture map UI, the SIEM shippers, the MCP server, and the notification dispatcher.
- **Attack-path engine** (`src/core/graph/attackPaths.js`) — five deterministic, ordered rule-based detectors: `exposed-origin`, `weak-transport`, `open-access-app`, `tunnel-without-access`, `worker-plaintext-secret`. Same input → same path IDs, so the UI can deep-link a path.

### Posture map

- **Dashboard page** — Wiz-style entity graph that visualises the account's Cloudflare entities (Internet → Account → Zones → services) as connected nodes, colours them by finding severity, and highlights attack paths (chains that lead to a high/critical exposure) as animated dashed edges. Pan/zoom/hover/click with full keyboard and trackpad support. `prefers-reduced-motion` disables the dash animation.
- New endpoint: `GET /api/posture/graph?assessmentId=<id>`.
- Source: `web/public/postureMap.{js,css}`.

### SIEM shipping

- **Elasticsearch shipper** (`src/core/integrations/siem/elastic.js`) — ECS 8.11.0-aligned documents, `POST {esUrl}/_bulk`, ApiKey or Basic auth, nested `threat.enrichments` mapping.
- **Splunk HEC shipper** (`src/core/integrations/siem/splunk.js`) — CIM-aligned envelopes, `POST {hecUrl}/services/collector/event`, `Authorization: Splunk <token>`, per-event error aggregation.
- **Enrichment** (`src/core/integrations/siem/enrichment.js`) — joins each finding to its graph node and every attack path it participates in.
- **File exporters** (`src/exporters/ecs.js`, `src/exporters/splunkHec.js`) — write the same NDJSON the live shipper would have posted (pull / air-gapped mode).
- **`flareinspect ship` CLI** with `--target elastic|splunk|all|file`, `--dry-run`, env-var fallbacks.
- **`POST /api/integrations/ship`** web endpoint mirroring the CLI surface.
- **`GET /api/integrations/template/elastic`** for scripted ES template bootstrap.
- **Packaged Kibana app** — `integrations/elastic/flareinspect-dashboard.ndjson` (data view + saved search + 2 visualizations + dashboard) importable via Kibana → Saved Objects → Import.
- **Packaged Splunk TA** — `integrations/splunk/TA-flareinspect/` with field extractions, transforms, 2 saved searches, and a SimpleXML dashboard.

### MCP server

- **stdio MCP server** (`mcp/server.mjs`) exposing the engine as six tools: `flareinspect_assess`, `flareinspect_list_findings`, `flareinspect_get_attack_paths`, `flareinspect_plan_remediation`, `flareinspect_apply_remediation` *(gated)*, `flareinspect_rollback` *(gated)*. Re-uses existing engine seams; no logic duplication. `@modelcontextprotocol/sdk` is an *optional* dependency.
- **Edit-scope policy** (`src/core/auth/editScope.js`) — shared between the MCP gated tools and the web `/api/remediate/{apply,rollback}` endpoints. Two conditions: `FLAREINSPECT_ALLOW_REMEDIATION=true` *and* a token that satisfies `verifyEditScope` (opaque env-bound secret, or a JWT with `permission: 'edit'` / `aud` containing `tag:edit` / `scope` containing `edit`).

### Notifications

- **`flareinspect notify` CLI** with `--target slack|teams|webhook|all`.
- **Three channels**: Slack (Block Kit), Microsoft Teams (Adaptive Card 1.5), generic webhook (HMAC-SHA256-signed, `X-FlareInspect-Signature` header). Per-channel URL + secret via flag or env var.
- **`POST /api/notify`** web endpoint mirroring the CLI surface.
- **Severity threshold** (`--threshold critical|high|medium|low`) suppresses dispatch when nothing is at or above the threshold — useful in CI to only ping on real findings.

### New check categories

The assessable surface grew from 21 to 34 categories. New in v2.0:

- `credentials` — Leaked Credentials Detection
- `notifications` — 4 security notification types (account-scoped)
- `ddos` — L7 DDoS posture (advisory)
- `account-waf` — account-level WAF coverage (advisory)
- `workers` — Workers inventory + plaintext-secret bindings
- `storage` — KV / D1 / Queues inventory
- `zaraz` — Zaraz third-party tools + consent
- `posture` — device posture rules
- `access` — Access application depth (allow-everyone, MFA, session duration)
- `casb` — open critical/high CASB findings
- `email-security` — Cloud Email Security policies
- `rbi` — Browser Isolation policies
- `magic` — Magic Firewall / Magic Transit rulesets
- `performance` — Brotli / HTTP/2-3 / Cache Deception Armor / Email Obfuscation
- `rules` — rules / rate-limit rules
- `spectrum` — Spectrum (TCP/UDP) configuration
- `turnstile` — Turnstile configuration
- `loadbalancing` — Load Balancing posture

Plus the `leaked-credentials`, `magic-firewall`, `device-posture`,
`browser-isolation`, and `cloud-email-security` aliases.

### Test coverage

- 262 tests pass (was 140 in 1.3.0). New test files include `resourceGraph`, `attackPaths`, `foundationStability`, `siemEnrichment`, `elastic`, `splunk`, `siemExporters`, `shipCli`, `integrationsShip`, `packagedApps`, `mcpServer`, `editScope`, and the expanded `phase2Remediation` (Phase 2/3/4 advisory coverage).

---

## 1.3.0 — 2026-04-26

### SDK Migration

- **Cloudflare SDK v5** — Migrated from `cloudflare` v4.5.0 to v5.2.0
  - Updated all zone-scoped resource paths (`client.zones.dnsRecords` → `client.dns.records`, etc.)
  - Updated account-scoped resource paths (`client.accounts.auditLogs` → `client.auditLogs`, etc.)
  - Adapted response unwrapping for v5's direct-return pattern on `.get()` calls
  - Added `_unwrapList()` helper to normalize v5 Page object responses
  - Updated error handling to use typed `APIError` subclasses (`error.status`, `error.errors`)
  - Converted `getZoneAnalytics()` and `getSecurityAnalytics()` to `rawRequest()` (no v5 SDK equivalent)
  - Fixed `rulesets.get()` call signature for v5 positional `rulesetId` argument
  - Removed optional chaining guards (`?.`) on SDK resources (v5 has stable resource structure)

---

## 1.2.0 — 2026-04-13

### Cloud Deployment

- **1-Click Deployment** — Deploy to Render, Heroku, Railway, or Fly.io with single-click buttons
- **Heroku Button** — Added `app.json` for one-click Heroku deployment with pre-configured environment variables
- **Render Configuration** — Enhanced `render.yaml` with 1 GB persistent storage for assessment history
- **Railway Template** — Added `railway.json` for Railway deployment with auto-restart policies
- **Fly.io Configuration** — Added `fly.toml` for edge deployment with health checks and auto-scaling
- **Deployment Guide** — New `DEPLOYMENT.md` with step-by-step instructions for all platforms

### Documentation

- Updated README with version badge, deployment buttons, and cloud hosting options
- Added deployment overview page and dedicated guides for Heroku, Railway, and Fly.io
- Updated index page to include deployment feature row and quick-deploy buttons
- Refreshed `render.md` to reflect 1 GB persistent storage

---

## 1.1.0 — 2026-04-12

- Added `diff` command for baseline drift detection
- Added compliance mapping for `cis`, `soc2`, `pci`, and `nist`
- Added contextual scoring and CI/CD gating options for `assess`
- Added exporters for `sarif`, `markdown`, `csv`, and `asff`
- Added config file loading via `.flareinspect.yml`, `.flareinspect.yaml`, and `flareinspect.config.json`
- Expanded web API with assessment history, compliance, drift comparison, API key auth, and extra download endpoints
- Added plugin loader scaffolding and automated tests for new modules
- Updated Docker, Render, linting, and repository metadata for a coherent 1.1.0 release
