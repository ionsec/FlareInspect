# Roadmap: New Cloudflare Services for FlareInspect (Assessment + Remediation)

## Context

FlareInspect today ships **71 assessment checks across ~28 categories** and **10 remediation
recipes** (all single-setting, reversible zone-setting flips + DNSSEC). An audit of the codebase
(`securityBaseline.js`, `assessmentService.js`, `cloudflareClient.js`, `recipeRegistry.js`) shows
the tool touches ~59 Cloudflare API methods — roughly **half** of Cloudflare's security-relevant
API surface — and remediation only covers a thin slice of what it *detects* (most failing findings
are advisory-only).

This roadmap is a **prioritized, phased research survey** of new Cloudflare services to add, for
**both assessment and remediation**, balanced across self-serve (Free/Pro/Biz) and Enterprise/SASE
tiers. Each candidate is scored on: **security value × read availability × safe-reversible-write
feasibility**. The guiding constraint is unchanged — remediation must stay deterministic, reversible,
backed-up, and AI-off-the-critical-path (per the existing `recipeRegistry` trust-boundary model).

Goal: a build order, not a build-now spec. Each phase is independently shippable.

## Scoring legend

- **Assess** = new detection check(s). **Remediate** = safe auto-fix recipe.
- Reversibility: 🟢 setting flip · 🟡 create/delete resource (capture id to reverse) · 🔴 not auto-remediable (advisory only).
- Tier: **SS** = self-serve (Free/Pro/Biz) · **ENT** = Enterprise/SASE.

## Architectural enablers (prerequisite for Phases 2+)

The current `recipeRegistry` only models `PATCH /zones/{id}/settings/{x}` + DNSSEC. To remediate
the higher-value services below, generalize three things (small, well-scoped changes):

1. **`cloudflareClient.js` — audited write wrappers** (all via `logger.mutation`, mirroring the
   existing `patchZoneSetting`/`setDnssec` at `cloudflareClient.js:1855+`): `createRulesetRule` /
   `deleteRulesetRule`, `createDNSRecord` / `deleteDNSRecord`, `putSecurityTxt`, `setLeakedCredentialChecks`,
   `createNotificationPolicy` / `deleteNotificationPolicy`, `setZoneHold` / `removeZoneHold`.
2. **Recipe interface** already supports arbitrary `apply`/`restore`/`verify` (see
   `recipeRegistry.js`). Extend backup entries (`backupManager.js` `buildBundle`) with an optional
   `createdResourceId` / `restoreOp` so **create-then-delete** recipes are reversible and stay
   checksum-protected. No schema break — additive fields.
3. **`remediationEngine.contextFor`** (`remediationEngine.js`) currently maps `zoneId = resourceId`.
   Add `accountId` + honor `resourceType` so **account-scoped** recipes (notifications, account
   rulesets, leaked-creds at account level) work. Add a `scope`-aware token-scope preflight note.

These unlock 🟡 create/delete recipes without weakening any safety guarantee.

---

## Phase 1 — Quick-win reversible recipes (SS, low risk)

Pure zone-setting flips: **no new client wrappers needed** (reuse `patchZoneSetting`). Each gets a
recipe in `recipeRegistry.js` and, where missing, a check in `securityBaseline.js`. This roughly
doubles the recipe catalog at near-zero risk and is the fastest win.

| Service / setting | Tier | Assess | Remediate | checkId | Notes |
|---|---|---|---|---|---|
| TLS 1.3 (`tls_1_3`) | SS | ✅ new | 🟢 `on` | CFL-SSL-006 | pairs with existing min-TLS recipe |
| Automatic HTTPS Rewrites (`automatic_https_rewrites`) | SS | ✅ new | 🟢 `on` | CFL-SSL-007 | fixes mixed content |
| Opportunistic Encryption (`opportunistic_encryption`) | SS | ✅ new | 🟢 `on` | CFL-SSL-008 | |
| Browser Integrity Check (`browser_check`) | SS | ✅ new | 🟢 `on` | CFL-WAF-009 | low-risk bot/abuse filter |
| Email Obfuscation (`email_obfuscation`) | SS | ✅ new | 🟢 `on` | CFL-PERF-006 | anti-scraping |
| Bot Fight Mode (`bot_fight_mode`) | SS | ✔ exists (CFL-BOT-001) | 🟢 `on` | — | promote existing manual finding to a recipe (medium risk: may challenge bots) |

---

## Phase 2 — High-value security detections + remediations (SS + account, medium effort)

Requires the architectural enablers. These are the highest **security ROI** items.

| Service | Tier | Assess | Remediate | API | checkId / category |
|---|---|---|---|---|---|
| **Leaked Credentials Detection** | SS | ✅ is detection on? | 🟡 enable (non-blocking, detection-only) | `POST /zones/{id}/leaked-credential-checks` | `CFL-LEAK-001`, new `credentials` category |
| **WAF managed ruleset enablement** | SS | ✔ CFL-WAF-006/007 (manual today) | 🟡 deploy Cloudflare Managed + OWASP Core via execute rule; **high risk** (can block traffic) → default to a confirmation gate, deployable in log-only first | `PUT /zones/{id}/rulesets/phases/http_request_firewall_managed/entrypoint` | promote CFL-WAF-006/007 to recipes |
| **security.txt** | SS | ✔ CFL-SEC-001 (manual today) | 🟡 publish with operator-supplied contact/expires | `PUT /zones/{id}/security-center/securitytxt` | promote CFL-SEC-001 to recipe (low risk) |
| **Notifications / Alerting** | SS+ENT | ✅ are security alerts configured? (cert expiry, WAF/DDoS spike, origin error, audit-log) | 🟡 create recommended policies (needs email/webhook destination input) | `GET/POST/DELETE /accounts/{id}/alerting/v3/policies` | new `notifications` category: `CFL-ALERT-001..004` |
| **Email DNS hardening (SPF/DMARC)** | SS | ✔ CFL-EMAIL-001/003 | 🟡 create TXT records — **conservative defaults** (DMARC `p=none` reporting-only); medium risk → confirmation | `POST /zones/{id}/dns_records` | promote to recipes |
| **DDoS managed ruleset posture** | SS+ENT | ✅ L7 ruleset not disabled/log-only/over-overridden | 🔴 advisory (override semantics too risky to auto-flip) | `GET /zones/{id}/rulesets/phases/ddos_l7/entrypoint` | `CFL-DDOS-001` |
| **Account-level rulesets / WAF exceptions** | ENT | ✅ reusable account rulesets, skip/exception rules, account managed-ruleset coverage | 🔴 advisory | `GET /accounts/{id}/rulesets` | `CFL-ACCTWAF-001` |

---

## Phase 3 — Workers / storage ecosystem (SS, assessment-led)

Closes the biggest detection gap (Workers coverage is ~20%). Mostly assessment; few safe writes.

| Service | Tier | Assess | Remediate | API | checkId |
|---|---|---|---|---|---|
| **Workers plaintext secrets** | SS | ✅ flag `plain_text` bindings holding secret-looking values (vs `secret_text`) | 🔴 advisory (cannot move values safely) | `workers.scripts.settings` / bindings | `CFL-WORK-003` |
| **Workers routes & cron triggers** | SS | ✅ inventory routes, unauthenticated triggers (attack-surface map) | 🔴 advisory | `workers.scripts` + zone routes | `CFL-WORK-004` |
| **KV / D1 / Queues inventory** | SS | ✅ existence + binding exposure; D1 backup posture | 🔴 advisory | `workers/kv/namespaces`, `d1/database`, `workers/queues` | `CFL-STORE-001..003` |
| **Zaraz third-party scripts** | SS | ✅ supply-chain: inventory third-party tags, consent config | 🔴 advisory | `/zones/{id}/settings/zaraz/*` | `CFL-ZARAZ-001` |
| **R2 deeper posture** | SS | ✅ versioning, object-lock (extends existing public-access CFL-R2-001) | 🟡 enable versioning (reversible) | `r2/buckets/{name}/*` | extend `CFL-R2-*` |

---

## Phase 4 — Enterprise / Cloudflare One SASE (ENT, assessment-led)

High security value for Enterprise/SASE customers; almost entirely assessment (Cloudflare One config
is rarely a safe auto-flip). Tag every finding ENT so self-serve scans don't surface noise.

| Service | Tier | Assess | Remediate | API | checkId |
|---|---|---|---|---|---|
| **Zone Holds** | ENT | ✅ hold enabled? (anti-takeover) | 🟡 enable hold (reversible delete) | `GET/POST/DELETE /zones/{id}/hold` | `CFL-HOLD-001` |
| **Device Posture rules** | ENT | ✅ posture checks defined (OS, disk-encryption, firewall, AV) & bound to policies | 🔴 advisory | `zeroTrust/devices/posture` | `CFL-POSTURE-001` |
| **Access app hardening (depth)** | ENT | ✅ no "allow everyone" policies, session duration, require-MFA/posture, purpose justification | 🔴 advisory | `zeroTrust/access/applications(.policies)` | `CFL-ZT-007..009` |
| **CASB** | ENT | ✅ integrations connected, open critical/high findings | 🔴 advisory | `/accounts/{id}/casb/*` | `CFL-CASB-001` |
| **Cloud Email Security (Area 1)** | ENT | ✅ policies active, detections, directory sync | 🔴 advisory | `/accounts/{id}/email-security/*` | `CFL-EMAILSEC-001` |
| **Browser Isolation** | ENT | ✅ isolate policies for risky categories / uploads | 🔴 advisory | gateway HTTP policies (`isolate` action) | `CFL-RBI-001` |
| **Magic Transit / Magic Firewall** | ENT | ✅ Magic Firewall ruleset presence/coverage | 🔴 advisory | `magic/*` | `CFL-MAGIC-001` |

---

## Files this roadmap will touch (per phase)

- **Checks:** `src/core/services/securityBaseline.js` — add check definitions + `getRemediation()` strings.
- **Assessment flow:** `src/core/services/assessmentService.js` — new `assess*` methods wired into `assessAccount`/`assessZone`.
- **API client:** `src/core/services/cloudflareClient.js` — new read methods (all phases) + audited write wrappers (Phase 2+).
- **Remediation:** `src/core/remediation/recipeRegistry.js` (new recipes), `backupManager.js` (create/delete reversal fields, Phase 2+), `remediationEngine.js` (account-scope ctx).
- **Compliance:** `src/core/services/complianceEngine.js` — map new checkIds to CIS/SOC2/PCI/NIST.
- **Surfaces:** CLI `--checks` accepts new categories automatically; web Remediate page already renders any recipe — only new category labels/badges may need touch-ups.
- **Tests:** extend `tests/remediation.test.js` + add `tests/newChecks*.test.js` following the existing mock-client pattern.

## Recommended sequencing

1. **Phase 1 first** — biggest recipe-catalog gain for the least risk/effort; no new wrappers.
2. **Phase 2** — the security headline items (leaked credentials, alerting, WAF ruleset enablement);
   requires the architectural enablers, which then unlock all future create/delete recipes.
3. **Phase 3** — Workers/storage detection breadth (assessment-led, low remediation surface).
4. **Phase 4** — Enterprise/SASE assessment coverage, gated to ENT zones to keep self-serve scans clean.

## Verification (per increment)

1. **Unit (no network):** for each new recipe, assert `read/proposed/apply/restore/verify` payloads
   against the mock client; assert `isCompliant` short-circuits; for create/delete recipes assert
   restore deletes the captured `createdResourceId` and the bundle stays checksum-valid.
2. **Read-only dry-run E2E** (real token): `flareinspect remediate plan` shows the new candidates and
   writes a before-backup; re-run `assess` to confirm **Cloudflare is unchanged**.
3. **Apply on a disposable zone** for each new recipe → verify in dashboard, `after` backup written,
   `verify=true`; then `rollback` and confirm restoration (re-run `assess` + `diff`).
4. **Token-scope preflight:** confirm each new write surfaces the required edit scope in the
   `printScopeNotice()` guidance when a read-only token is used (extends the existing notice).
5. **Tier gating:** confirm ENT-only checks don't fire/penalize on non-Enterprise zones.

## Sources

- Leaked credentials detection (enable, non-blocking): https://developers.cloudflare.com/waf/detections/leaked-credentials/get-started/ and https://developers.cloudflare.com/waf/managed-rules/check-for-exposed-credentials/configure-api/
- Zone Holds: https://developers.cloudflare.com/fundamentals/account/account-security/zone-holds/ and https://developers.cloudflare.com/api/resources/zones/subresources/holds/methods/delete/
- Notifications / Alerting policies: https://developers.cloudflare.com/api/resources/alerting/subresources/policies/methods/create/ and https://developers.cloudflare.com/notifications/
- WAF security-event alerts: https://developers.cloudflare.com/waf/reference/alerts/
- security.txt: https://developers.cloudflare.com/security-center/infrastructure/security-file/
- CASB + Email Security (2025): https://developers.cloudflare.com/changelog/post/2025-04-01-casb-email-security/ and https://www.cloudflare.com/sase/products/casb/
