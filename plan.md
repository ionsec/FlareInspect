# Roadmap: Attack-Path Graph · SIEM (ELK/Splunk) · Notifications · Agent/MCP Interop

## Self-review of the original plan (kept verbatim below, plus these deltas)

The original sequencing, foundation-first design, and reuse of existing engine seams are all correct.
Six concrete deltas before code lands:

1. **Guard against checksum regression up front.** The foundation step #1 changes the captured
   `configuration` shape — a `dnsTxtRecordRecipe`-style regression is likely. Add a
   `tests/foundationStability.test.js` that snapshots the `configuration` round-trip
   (write → read → checksum-stable) for every Phase 2/3/4 recipe. The existing
   `phase2Remediation.test.js` covers `dnsTxtRecordRecipe`; widen it before the foundation lands.
2. **Phase 1 should *augment* the posture map, not rewrite it as a layered DAG.** A DAG rewrite
   of `buildGraph`/`layout`/`paintGraph` is 1 PR on its own. Default to "tree + highlight this
   attack path" (reuses 100% of the existing layout); gate the layered-DAG mode behind a flag.
3. **Split Phase 2.** Shippers + file exporters first (small). Kibana NDJSON + Splunk TA + the
   `ship` CLI + the `POST /api/integrations/ship` endpoint second (packaging polish). Don't
   label "ship apps + CLI + endpoint" as a single phase — it's 3–4 PRs.
4. **Mark `@modelcontextprotocol/sdk` as `optionalDependencies`** (matches the existing
   `optionalDependencies` pattern for `@anthropic-ai/sdk` and `openai`). The MCP server should
   not force a 3 MB SDK on users who only want the CLI.
5. **Enforce the "edit-scoped token" claim.** Add an actual JWT-claim check in the MCP
   `flareinspect_apply_remediation` tool (and a parallel `FLAREINSPECT_REQUIRE_EDIT_SCOPE`
   env gate in `web/server.js`); a one-line tool description is marketing, not a control.
6. **CSP smoke must run in CI before Phase 1 ships.** The posture map already emits inline
   `style=` from runtime; the new `/api/posture/graph` endpoint must be sized to fit under
   the existing `script-src 'self' 'unsafe-inline'` and a sane `connect-src`. Add a smoke
   test that loads `index.html` and asserts the four wiring markers + a successful
   `fetch('/api/posture/graph?assessmentId=…')` (stub `currentAssessment` if needed).

## Context

FlareInspect has matured: an assessment engine (71+ checks), an AI-assisted remediation subsystem
(27 reversible recipes, clean `buildPlan/apply/rollback` seams, web + CLI surfaces), a hierarchical
**Posture Map** (`web/public/postureMap.js`, ~828 lines), and SIEM-shaped exporters (OCSF, ASFF,
SARIF). This roadmap takes it from "assess + fix one resource at a time" to a **graph-based security
platform**: see *attack paths* across connected entities, stream findings into the customer's SIEM,
alert humans in chat, and let autonomous agents drive the whole loop.

Four initiatives, delivered as **one phased roadmap**:
1. **Attack-Path Engine** — a true resource-topology graph (typed nodes + edges) with
   privilege-escalation / misconfiguration-exploitation chain detection (Wiz-style).
2. **SIEM integrations** — push findings to **Elasticsearch (ECS)** and **Splunk (HEC/CIM)** *and*
   ship installable dashboards/apps.
3. **Notification system** — Slack, Microsoft Teams, and generic signed webhooks.
4. **Agent interop** — an **MCP server** exposing assess→findings→paths→plan→apply→rollback as
   tools (universal across Claude Agent SDK / "Cowork", Hermes, OpenClaw, Claude Code), plus a thin
   Claude Code skill/plugin.

## Current-state grounding (from code audit)

- **Posture map** is hierarchical (Internet→Account→Zone→service buckets), groups findings by
  `(resourceType, resourceId, category)`; **no cross-resource edges** today. Functions: `buildGraph()`,
  `layout()`, `paintGraph()`, `openDrawer()` in `web/public/postureMap.js`.
- **Assessment `configuration`** mostly stores **counts**, not full records
  (`assessmentService.js`). The raw entities needed for topology (DNS record content/proxied, cert
  SANs, Access app→policy→IdP, tunnel routes, worker routes/bindings, LB origins, R2 access) are
  fetched but not all retained — **the foundation phase must capture them**.
- **Findings** carry `resourceId`/`resourceType` + `evidence.affectedEntities[]` (named entities) —
  the hook for attaching findings to graph nodes.
- **Exporters** live in `src/exporters/*`; OCSF in `src/core/utils/ocsf.js`; CLI `export` + web
  `/api/download/*` follow a simple per-format switch — new shippers slot in cleanly.
- **Remediation seams** are programmatic-ready: `remediationEngine.buildPlan/apply/rollback`,
  `recipeRegistry.{has,get,all,checkIds}`, web `/api/remediate/*` gated by
  `FLAREINSPECT_ALLOW_REMEDIATION`. **An MCP server should call these directly — no logic duplication.**
- **Config**: `src/core/config.js` (YAML/JSON + env). New `integrations` section + env vars slot in.
- **No** existing webhook/Slack/Teams/Elastic/Splunk/MCP code — all greenfield.

---

## Foundation (keystone — unblocks Phase 1, reused by 2 & 4)

**A shared resource-graph model is the spine of the whole roadmap.** Build it once, server-side, and
reuse it for the map UI, the SIEM exports (richer observables + path context), and the MCP tools.

1. **Capture richer entities** — extend the relevant `assess*` methods in
   `src/core/services/assessmentService.js` to retain full records (not counts) in
   `configuration`: DNS records `{name,type,content,proxied}`, derived **exposed origin IPs**
   (un-proxied A/AAAA/CNAME), cert SAN domains, Access apps + policies + IdPs, tunnels + routes,
   workers + routes + bindings (KV/D1/Queues), LB pools/origins, R2 buckets + public-access flag.
   Reuse existing `cloudflareClient` getters (they already fetch most of this).
2. **`src/core/graph/resourceGraph.js`** — `buildResourceGraph(assessment) → { nodes, edges }`:
   - **Node types:** `internet`, `identity`, `account`, `zone`, `dns_record`, `origin`, `certificate`,
     `access_app`, `access_policy`, `idp`, `tunnel`, `worker`, `binding(kv/d1/queue)`, `r2_bucket`,
     `load_balancer`. Each node: `{id, type, label, props, severity, findingIds}`.
   - **Edge types:** `contains`, `resolves_to`, `exposes`, `protected_by`, `routes_to`,
     `authenticates_with`, `binds`, `serves`. Derive edges by matching values (DNS `content` → origin
     IP; cert SAN → DNS name; tunnel route → origin; worker route → zone; LB origin → origin IP).
   - Attach findings to nodes via `(resourceType,resourceId)` + `evidence.affectedEntities[]`.
   - Node severity = worst FAIL finding on it (reuse `SEVERITY_ORDER`; green if all pass).
3. **`src/core/graph/attackPaths.js`** — `findAttackPaths(graph) → paths[]`, rule-based chains from an
   entry (Internet/identity) through misconfigured nodes to a sensitive asset:
   - exposed-origin (un-proxied A record → WAF/DDoS bypass, ties CFL-INSIGHT-005),
   - weak-transport (SSL flexible/off + min-TLS<1.2 + exposed origin → interception),
   - open-access-app ("allow everyone"/no policy → internal app reachable),
   - tunnel-without-access (tunnel route → origin, no Access policy),
   - worker-plaintext-secret (route → worker → plaintext binding),
   - leaked-creds-off (login endpoint + detection disabled → credential stuffing).
   - Each path: `{id, title, severity, nodes:[…], edges:[…], explanation, relatedCheckIds, remediableCheckIds}`.
     Score with existing `contextualScoring`.
4. **`GET /api/posture/graph?assessmentId=`** (`web/server.js`) → `{ nodes, edges, paths }`. Keeps one
   source of truth; the browser map fetches it (no graph logic duplicated in the front-end).

---

## Phase 1 — Attack-Path Map (UI upgrade)

Upgrade `web/public/postureMap.js` to consume `/api/posture/graph` and render the real topology +
ranked attack paths. Reuse the existing severity palette, pan/zoom, drawer, and animations.

- **Two modes:** *Topology* (full resource DAG) and *Attack paths* (ranked list + on-graph highlight).
- **Layout:** move from strict tree to a **layered DAG** (entry/identity on the left → assets/"crown
  jewels" on the right) so shared resources (e.g., an origin used by two zones) render correctly.
- **Attack Paths panel:** ranked cards (severity, title, hop count); click highlights the chain, dims
  the rest, shows a step-by-step explanation, and a **"Remediate this path"** button that deep-links
  to the Remediate page with the path's `remediableCheckIds` preselected.
- **Node drawer:** resource props + attached findings + remediable badge (extends current drawer).
- Files: `web/public/postureMap.js`, `web/public/postureMap.css` (already linked in `index.html`).

---

## Phase 2 — SIEM integrations (push + packaged apps)

New `src/core/integrations/siem/`. Each finding is enriched with its **node + attack-path context**
from the foundation graph, so SIEM rules can alert on *paths*, not just findings.

- **`elastic.js`** — map finding→**ECS** (`vulnerability.*`, `threat.*`, `event.kind/category`,
  `cloud.provider=cloudflare`, `url/host`, attack-path as `threat.enrichments`); ship via
  Elasticsearch **`_bulk`** (`POST {esUrl}/_bulk`, API-key/basic auth). Provide an **index template**.
- **`splunk.js`** — ship via **HEC** (`POST {hecUrl}/services/collector/event`,
  `Authorization: Splunk <token>`, body `{event, sourcetype:'cloudflare:flareinspect:finding', source,
  fields:{…CIM…}}`). Align fields to CIM (Vulnerabilities/Alerts).
- **Packaged apps** (`integrations/elastic/`, `integrations/splunk/`):
  - Kibana: index template + **saved-objects NDJSON** dashboard (score-over-time, severity breakdown,
    findings table, attack-paths) importable via Saved Objects API/UI.
  - Splunk **app/TA**: `props.conf`/`transforms.conf` field extractions + dashboards + savedsearches.
- **Wiring:** add `ecs` + `splunk-hec` file exporters (for pull/air-gapped) AND an active shipper via
  a new `flareinspect ship --target elastic|splunk` CLI command + `POST /api/integrations/ship`.
  Config under `integrations.elastic` / `integrations.splunk`; secrets via env
  (`FLAREINSPECT_ES_URL`/`_ES_APIKEY`, `FLAREINSPECT_SPLUNK_HEC_URL`/`_HEC_TOKEN`). Reuse OCSF where a
  SIEM prefers it; ECS/HEC are additive.

> Note: Microsoft is retiring O365 connectors (migration window into 2026) — see Phase 3 for the
> current Teams path.

---

## Phase 3 — Notification system

New `src/core/integrations/notify/` + a `notificationService.js` that builds a summary payload
(score, grade, severity counts, top findings, **attack-path count**, and new/regressed via existing
`diffService`) and dispatches to enabled channels with a severity threshold filter.

- **`slack.js`** — Incoming Webhook, Block Kit message (header + severity fields + top findings + link).
- **`teams.js`** — **Power Automate Workflows** webhook posting an **Adaptive Card** (O365 connectors
  are deprecated; Workflows is the supported path; messageCard also accepted).
- **`webhook.js`** — generic JSON `POST` with an **HMAC signature** header for verification.
- **Triggers:** on assess complete, on remediation apply (what changed), on drift detected.
- **Surfaces:** `flareinspect notify --target slack|teams|webhook` + `POST /api/notify`; config
  `integrations.notifications.*`; env `FLAREINSPECT_SLACK_WEBHOOK`, `FLAREINSPECT_TEAMS_WEBHOOK`, etc.

---

## Phase 4 — Agent interop (MCP server first)

New **`mcp/server.js`** using `@modelcontextprotocol/sdk` (`McpServer` + `StdioServerTransport` for
local agents; **Streamable HTTP** transport for remote). It **calls the existing engine seams** —
zero logic duplication. One MCP server makes FlareInspect usable by **any MCP client** (Claude Agent
SDK/"Cowork", Hermes, OpenClaw, Claude Code, etc.).

- **Tools (Zod-validated):**
  - `flareinspect_assess({ token, zones? })` → runs `AssessmentService`, persists, returns summary + `assessmentId`.
  - `flareinspect_list_findings({ assessmentId?, severity?, status? })`.
  - `flareinspect_get_attack_paths({ assessmentId? })` → `resourceGraph` + `attackPaths`.
  - `flareinspect_plan_remediation({ assessmentId?, token, checks? })` → `buildPlan` (dry-run).
  - `flareinspect_apply_remediation({ assessmentId?, token, checkIds, force? })` → `apply`, **gated by
    `FLAREINSPECT_ALLOW_REMEDIATION`**; tool description states the edit-scoped token requirement.
  - `flareinspect_rollback({ bundleFile, token })` → `rollback`.
  - **Resources:** latest assessment + backup bundles exposed as MCP resources.
- **Safety carries over:** read-only by default; apply requires the env gate + explicit `checkIds`;
  recipe registry remains the trust boundary; backups/rollback unchanged.
- **Claude Code skill/plugin:** `.claude/skills/flareinspect/` (SKILL.md) + a plugin that registers
  the MCP server and slash commands (`/flareinspect-assess`, `/flareinspect-remediate`). Document
  connection snippets for Cowork/Hermes/OpenClaw (all just point an MCP client at the server).
- **Packaging:** `bin: { "flareinspect-mcp": "mcp/server.js" }` in `package.json`;
  `@modelcontextprotocol/sdk` as a dependency (optional/peer if you want the core install lean).

---

## Sequencing & dependencies

```
Foundation (resource graph + richer capture)
   ├─► Phase 1  Attack-Path Map UI        (needs foundation)
   ├─► Phase 2  SIEM push + apps          (uses graph for path-enriched docs)
   └─► Phase 4  MCP server                (exposes get_attack_paths; engine already ready)
Phase 3  Notifications                    (mostly independent — quick win, can land first)
```

Recommended order: **Foundation → Phase 3 (quick win) → Phase 1 (augment, not rewrite) → Phase 4 → Phase 2a → Phase 2b.**
Phases 2/3/4 are largely independent once the foundation exists and can be parallelized.

## New / touched files

- **Foundation:** `src/core/graph/resourceGraph.js`, `src/core/graph/attackPaths.js` (new);
  `src/core/services/assessmentService.js` (retain full entities); `web/server.js` (`/api/posture/graph`).
- **Phase 1:** `web/public/postureMap.js`, `web/public/postureMap.css`.
- **Phase 2:** `src/core/integrations/siem/{elastic,splunk}.js`, `src/exporters/{ecs,splunkHec}.js`,
  `integrations/elastic/*` + `integrations/splunk/*` (packaged apps), `web/server.js`, a `ship` CLI command.
- **Phase 3:** `src/core/integrations/notify/{slack,teams,webhook}.js`,
  `src/core/services/notificationService.js`, a `notify` CLI command, `web/server.js`.
- **Phase 4:** `mcp/server.js`, `.claude/skills/flareinspect/SKILL.md` (+ plugin), `package.json` (bin + dep).
- **Cross-cutting:** `src/core/config.js` + `.flareinspect.yml.example` (new `integrations` + `mcp`
  sections); `README.md`; tests under `tests/` (graph, attack-paths, each integration with mocked HTTP, MCP tools).

## Verification

1. **Foundation (unit):** `buildResourceGraph` produces expected nodes/edges from a fixture
   assessment; `findAttackPaths` detects a seeded exposed-origin + weak-transport chain; node↔finding
   attachment correct.
2. **Phase 1 (E2E):** `npm run web`, load an assessment, open Posture map → topology renders, attack
   paths rank correctly, "Remediate this path" deep-links with the right checkIds; pan/zoom/drawer work; no CSP errors.
3. **Phase 2:** unit-test ECS/HEC field mappings against fixtures; integration-test shippers against a
   local Elasticsearch + a Splunk HEC mock (or `--dry-run` printing the bulk/HEC body); import the
   Kibana NDJSON + Splunk app and confirm dashboards populate.
4. **Phase 3:** post to a Slack test webhook, a Teams Workflows webhook, and a local webhook receiver;
   verify Block Kit / Adaptive Card render and HMAC signature validates; threshold filter respected.
5. **Phase 4:** run `flareinspect-mcp` over stdio with MCP Inspector; exercise each tool; confirm
   apply is refused without `FLAREINSPECT_ALLOW_REMEDIATION`; connect from Claude Code via the skill
   and run `/flareinspect-assess` → `/flareinspect-remediate`.
6. **Regression:** existing `npm test` (93 tests) stays green; `npm run lint` clean.

## Sources

- Splunk HEC ingest / examples: https://dev.splunk.com/enterprise/docs/devtools/httpeventcollector/ and https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.2.2510/get-data-with-http-event-collector/http-event-collector-examples
- Elastic ECS vulnerability/threat fields: https://www.elastic.co/docs/reference/ecs/ecs-vulnerability and https://www.elastic.co/guide/en/ecs/current/index.html
- Teams connectors retirement → Power Automate Workflows + Adaptive Cards: https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/ and https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
- MCP TypeScript SDK (McpServer, stdio/HTTP transports, tools): https://github.com/modelcontextprotocol/typescript-sdk and https://www.npmjs.com/package/@modelcontextprotocol/sdk
