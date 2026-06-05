# Handover Plan: Posture Map (Attack-Path Visualization) for FlareInspect Dashboard

> **For the implementing model.** This is a self-contained spec — you do not need prior
> conversation context. Read the "Repo facts" section carefully; the dashboard is **vanilla JS
> classic scripts (no framework, no build step)**, so the integration rules are specific.

## Goal

Add a new **Posture Map** section to the FlareInspect web dashboard: an interactive, Wiz-style
**entity graph** that visualizes the account's Cloudflare entities (account → zones → security
services) as connected nodes, colors them by finding severity, and **highlights attack paths**
(chains that lead to a high/critical exposure). Aesthetic must match modern security platforms
(Wiz, Orca, Cloudflare One): dark, glassy nodes with icons, severity glow, smooth curved edges,
pan/zoom, and a click-to-inspect detail drawer.

Pure front-end feature. **No backend, no new npm deps, no build tooling.** It renders from the
assessment JSON already loaded in the browser.

## Repo facts you must respect

**Stack & conventions** (`web/public/`):
- The SPA is **classic `<script>` tags**, not modules. `web/public/app.js` declares top-level
  `let`/`const`/`function` that live in the **shared global lexical scope** — a second classic
  script loaded *after* `app.js` can reference them directly. You will rely on this.
- Reusable globals from `app.js` you SHOULD use (do not re-declare):
  - `let currentAssessment` — the loaded assessment object (or `null`). Set in `updateWithAssessment()` (app.js:184).
  - `function escHtml(str)` — HTML-escape helper (app.js:24). **Use for all interpolated strings.**
  - `function $(id)` — `document.getElementById` shorthand (app.js:39).
  - `const SEVERITY_ORDER = { critical:0, high:1, medium:2, low:3, informational:4 }` (app.js:9).
  - `function navigateTo(section)` (app.js:43) — section router; shows `#page-<section>`, hides others, sets active navlink + crumb, and calls per-section loaders. **You add a hook here.**
  - `const TOPBAR_TITLES = {…}` (app.js:11) — breadcrumb labels. **Add an entry.**
  - `function showToast(message, type)` — toast helper (optional, for errors).
- Section pages are `<div class="v1-page" id="page-<name>" style="display:none">`; `navigateTo`
  sets `page.style.display = 'flex'`.

**CSP** (`web/server.js`, helmet): `scriptSrc 'self' 'unsafe-inline' https://cdn.jsdelivr.net`,
`styleSrc 'self' 'unsafe-inline'`, `imgSrc 'self' data:`. → Inline SVG and inline styles are fine.
**Prefer zero external deps** (build it in raw SVG). If you really want a lib, jsdelivr is the only
allowed CDN — but the bar is: don't add one unless it materially improves quality.

**Design system** (`web/public/styles.css` `:root`) — REUSE these variables, do not hardcode hex:
- Surfaces: `--bg-0:#08080b … --bg-3:#1a1a20`, `--bg-elev:#17171d`. Lines: `--line`, `--line-2`, `--line-3`.
- Text: `--fg`, `--fg-2`, `--fg-3`, `--fg-4`. Brand: `--flare`, `--flare-2`, `--flare-soft`.
- Severity (OKLCH): `--crit`, `--high`, `--med`, `--low`, `--info` and `*-soft` variants (e.g. `--crit-soft`) for glows/fills.
- Fonts: `--font-ui` (Manrope), `--font-mono` (Geist Mono — use for IDs/labels). Radii: `--r-sm/-r/-r-lg/-r-xl`.
- Existing component classes to match the look: `.v1-page`, `.v1-page-head`, `.v1-card`, `.v1-btn`, `.v1-btn-primary`, `.v1-btn-ghost`, `.v1-badge`.

**Finding object shape** (in `currentAssessment.findings[]`):
```
{ checkId, checkTitle (or title), severity: 'critical|high|medium|low|informational',
  status: 'PASS|FAIL|WARNING', service (category, e.g. 'ssl','waf','dns','account'),
  resourceId, resourceType: 'zone'|'account'|'certificate'|…, description,
  metadata: { evidence, status }, remediation }
```
**Assessment shape:** `currentAssessment = { account:{id,name}, zones:[{id,name,plan,status}], findings:[…] }`.

## Files to create / modify

| Action | File | What |
|---|---|---|
| **Create** | `web/public/postureMap.js` | Graph build + SVG render + interactions (the engine). |
| **Create** | `web/public/postureMap.css` | Wiz-style graph styling using the CSS vars above. |
| **Edit** | `web/public/index.html` | Nav link, `<link>` to css, `#page-posture` container, `<script>` to js. |
| **Edit** | `web/public/app.js` | One line in `navigateTo` + one entry in `TOPBAR_TITLES`. |

### index.html edits (exact anchors)

1. In `<head>`, after `<link rel="stylesheet" href="/styles.css" />`, add
   `<link rel="stylesheet" href="/postureMap.css" />`.
2. In the **Workspace** nav group, after the Findings `<button class="v1-navlink" data-section="findings" …>` block, add a navlink:
   `<button class="v1-navlink" data-section="posture" type="button"> <svg…network/graph icon…/> <span>Posture map</span> </button>`.
3. Add the page container just before `<div id="toast-container" …>` (near the end of `.v1-main`):
   `<div class="v1-page" id="page-posture" style="display:none"> … </div>` (structure below).
4. After `<script src="/app.js"></script>` add `<script src="/postureMap.js"></script>`
   (must load AFTER app.js so shared globals exist).

### app.js edits

- In `TOPBAR_TITLES` add: `posture: 'Posture map',`.
- In `navigateTo`, alongside the other `if (section === …)` loader hooks, add:
  `if (section === 'posture' && typeof initPostureMap === 'function') initPostureMap();`

## `#page-posture` DOM structure

```
#page-posture (.v1-page)
  .v1-page-head  → <h1>Posture map</h1> + sub "Entities, connections, and attack paths from the latest assessment"
  .pm-toolbar
     .pm-stats   → chips: "<n> entities", "<n> attack paths", "<n> exposed assets"
     .pm-legend  → severity swatches (crit/high/med/low/pass) + an "attack path" dashed-red key
     .pm-controls→ toggle "Attack paths" (default ON), buttons: Fit, Zoom +, Zoom −
  .pm-stage      → position:relative; flex:1; holds:
     <svg id="pm-svg">  (full-size; contains <g id="pm-viewport"> that you pan/zoom via transform)
        <defs> arrow markers, edge gradients, soft drop-shadow filters per severity
        <g id="pm-edges">  (render edges first so nodes sit on top)
        <g id="pm-nodes">
     .pm-empty    → shown when no assessment ("Run an assessment to populate the posture map.")
  aside.pm-drawer (off-canvas right; .open class slides in) → node title, type, severity, finding list, "Remediate" link
```

## Data model — build the graph from `currentAssessment`

Build a **tree** (root → account → zones/account-services → zone-services). Nodes:

1. **Internet** (root, single): label "Internet", type `internet`. Entry point.
2. **Account**: one node, type `account`, label = `account.name`. Child of Internet.
3. **Zone**: one per `zones[]`, type `zone`, label = zone name. Child of Account.
4. **Service/category nodes**: group findings into entity nodes keyed by `(scope, parentId, category)`:
   - If `resourceType === 'account'` → child of **Account**.
   - If `resourceType === 'zone'` (or resourceId matches a zone id) → child of that **Zone**.
   - Else → child of Account (fallback).
   - `category = finding.service`. One node per distinct category under each parent.
   - **Node severity** = worst severity among that node's `status==='FAIL'` findings (use `SEVERITY_ORDER`); if it has findings but none FAIL → `pass` (green). Keep the node's full findings array for the drawer.
   - **Node count badge** = number of FAIL findings (hide if 0).

**Category → {label, icon, role}** map (role drives column + attack-path semantics). Provide a lookup; default unknown categories to `{label: titlecased, icon: 'generic', role:'asset'}`:
- exposure/transport (role `transport`): `dns`, `ssl`, `mtls`, `securitytxt`, `ch`(custom hostnames), `insight`/`securityInsights`
- edge protection (role `control`): `waf`, `bot`, `api`, `page-shield`, `cache`, `rules`/`cfrule`/`txrule`, `turnstile`, `performance`
- assets/backends (role `asset`): `workers`, `pages`, `r2`, `tunnels`, `gateway`, `dlp`, `zerotrust`, `spectrum`, `ai-gateway`, `snippets`, `lb`, `email`
- identity (role `identity`): `account`, `token`, `attack-surface`, `device`

Icons: define a small inline-SVG path set per type (`internet`=globe, `account`=building/shield,
`zone`=globe-dot, `ssl`/`mtls`=lock, `waf`=shield, `dns`=server, `bot`=robot/bug, `workers`=code,
`r2`=database, `email`=mail, `zerotrust`=fingerprint, `tunnels`=plug, `dlp`=eye-off,
`gateway`=filter, `generic`=dot). 24×24, `stroke="currentColor"`, `fill="none"`, stroke-width 1.6
to match existing nav icons.

## Layout — tidy left→right tree

Columns by depth: `0 Internet → 1 Account → 2 Zones (+account-services) → 3 zone-services`.
(Account-level service nodes sit in column 2 next to zones; zone-service nodes in column 3.)

Algorithm (deterministic, no physics needed — cleaner than force-directed):
- `x = depth * COL_W` (e.g. COL_W ≈ 240).
- Assign `y` by leaf order: walk the tree depth-first; each **leaf** gets the next slot
  `y = leafIndex++ * ROW_H` (ROW_H ≈ 92). Each **internal node** gets `y = average(children.y)`.
- Compute total bounds → used by Fit.
- Nodes are fixed-size cards (≈ 200×56) or pills; center the icon + label + count badge.

Edges: cubic bézier from parent right-edge to child left-edge
(`M x1,y1 C x1+dx,y1 x2-dx,y2 x2,y2`, dx≈COL_W/2). Edge color = child severity (soft);
on-attack-path edges get the red dashed animated treatment.

## Attack paths

Definition (clear + defensible): an **attack path** is any root→leaf path that **terminates at a
node whose severity is `critical` or `high`** (i.e., reaching a serious exposure). Compute by:
1. Mark "danger" leaves (severity ∈ {critical, high}).
2. Walk up from each danger leaf marking all ancestor nodes and the connecting edges as `onPath`.
3. Count distinct danger leaves → "attack paths" stat.

Render: `onPath` edges = `--crit` stroke, `stroke-dasharray` with an animated `stroke-dashoffset`
(CSS `@keyframes pm-flow`); `onPath` nodes get a subtle crit outline/glow. A toolbar toggle
("Attack paths", default ON) shows/hides this emphasis (toggle a class on `#pm-svg`).

## Interactions

- **Pan/zoom:** maintain `{scale, tx, ty}`; apply `transform="translate(tx,ty) scale(scale)"` to
  `#pm-viewport`. Wheel = zoom toward cursor (clamp scale ~0.3–2.5); drag background = pan; buttons
  Zoom±; **Fit** computes scale/translate from graph bounds vs stage size.
- **Hover node:** add `.pm-dim` to `#pm-svg`; give the hovered node + its edges/neighbors a
  `.pm-focus` class (so unrelated nodes fade). Remove on mouseleave.
- **Click node:** open `.pm-drawer` with: icon + label, type, severity badge, and the node's
  findings (reuse the visual language of `buildFindingMarkup` — id · category · severity · evidence).
  If a finding's `checkId` is remediable, show a small "Remediable" tag and a button that calls
  `navigateTo('remediate')`. Close on backdrop click / Esc / X.
- **Empty state:** if `!currentAssessment || !findings.length`, show `.pm-empty` and skip rendering.

`initPostureMap()` is the entry point (called by `navigateTo`). It should be idempotent: rebuild
from the current `currentAssessment` each time the section is opened (cheap; assessment can change).

## Aesthetic checklist (match Wiz / big-tech)

- Dark stage (`--bg-0`), faint dotted/grid background optional (very subtle, `--line`).
- Nodes: `--bg-elev` fill, `1px solid --line-2`, `--r` radius, slight backdrop feel; left accent bar
  or icon chip tinted with the node's severity-soft color; label in `--fg`, sublabel/id in
  `--font-mono`/`--fg-3`. Severity ring = 2px border in the severity color; danger nodes get a soft
  outer glow via `filter: drop-shadow(... --crit-soft)`.
- Edges: 1.5px, severity-soft colored, rounded; attack-path edges animated dashed `--crit`.
- Smooth transitions (`transition: opacity/transform .18s ease`); focus/dim at ~0.25 opacity.
- Legend + stat chips styled like `.v1-badge`/`.v1-chip`. Controls like `.v1-btn-ghost`.
- Keep it calm and readable at 1 zoom; no clutter. Title IDs in monospace. Respect existing spacing.

## Accessibility

- Nav button is real `<button>`; nodes should be focusable (`tabindex="0"`, `role="button"`,
  `aria-label`) and openable via Enter/Space. Drawer closable via Esc. Sufficient contrast (the
  OKLCH severity colors already pass on the dark bg).

## Acceptance criteria

1. New **Posture map** item appears in the sidebar (Workspace group) and routes correctly.
2. With an assessment loaded, the stage renders Internet → Account → Zones → service nodes,
   colored by severity, with type icons and FAIL-count badges.
3. Attack-path emphasis highlights chains to high/critical nodes; the toolbar toggle hides/shows it;
   the "attack paths" stat matches the number of high/critical leaf exposures.
4. Pan, wheel-zoom, Zoom± and Fit all work; hover dims unrelated nodes; clicking a node opens a
   drawer listing that node's findings (with a Remediate link where applicable).
5. Empty state shows when no assessment is loaded.
6. No console errors; no CSP violations; no new npm dependencies; visual style consistent with the
   rest of the dashboard (uses the documented CSS variables).

## Verification steps

1. `npm install` (if needed) then `npm run web`; open the printed `http://127.0.0.1:<port>`.
2. If no assessment exists, run one from the **Run assessment** page (needs a read-only Cloudflare
   token: Zone:Read, DNS:Read, SSL:Read) — or load an existing one from **History**.
3. Open **Posture map**: confirm the graph renders, severities/icons look right, attack paths
   animate, toggle works, pan/zoom/fit work, node click opens the drawer with that node's findings.
4. Resize the window / collapse the sidebar: layout stays usable (Fit re-centers).
5. Check DevTools console + network for CSP errors (should be none).

## Out of scope (nice-to-haves, only if time allows)

- A minimap; export-graph-as-PNG/SVG; saved layouts; cross-zone shared-origin edges (group DNS
  records pointing at the same origin IP); diff mode (compare two assessments on the map).

## Reference: prior roadmap

A separate phased roadmap of *new Cloudflare services* (assessment + remediation) lives in the
agent plans directory (`~/.claude/plans/plan-a-remidiation-automation-swift-thompson.md`). It is
unrelated to this posture-map task but provides product context if useful.
