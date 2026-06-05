# FlareInspect — Design System (MASTER)

> **Global source of truth.** When building any surface, read this file first. If a
> `design-system/pages/<page>.md` override exists for the surface you're building, its
> rules take precedence over this file; otherwise follow MASTER exclusively.
> Implemented in `web/public/styles.css` (`:root` tokens) — keep this doc and the CSS in sync.

## Product pattern

- **Type:** Cloud-security posture / CSPM operations dashboard (Wiz-class), developer-facing.
- **Pattern:** Real-Time / Operations — dark, data-dense but scannable; status colors carry meaning;
  KPI/score hero + per-category breakdown + findings + posture graph.
- **Mode:** **Dark-only** (OLED). Light mode is intentionally deferred — the audience is security/ops.

## Style

- **Dark Mode (OLED) + Data-Dense Dashboard.** Deep near-black surfaces, hairline borders, minimal
  padding, high information density, calm at rest, color reserved for signal (severity/brand).
- 12-ish column feel, 4/8px spacing rhythm, sticky table headers, sortable/exportable data tables.

## Color tokens (OKLCH — authoritative)

| Token | Value | Use |
|---|---|---|
| `--bg-0…3`, `--bg-elev` | `#08080b → #1a1a20`, `#17171d` | surfaces (page → cards → elevated) |
| `--line / -2 / -3` | white @ 6% / 10% / 18% | hairline borders, dividers |
| `--fg / -2 / -3 / -4` | `#eaeaec / #b4b4bb / #7a7a82 / #4a4a52` | text primary → disabled |
| `--flare` | `oklch(72% 0.17 52)` | **BRAND only** — logo, nav-active, score ring, primary CTA |
| `--flare-2`, `--flare-soft` | hue 52 | brand hover / brand tint |
| `--crit` | `oklch(65% 0.21 25)` | critical severity |
| `--high` | `oklch(70% 0.19 40)` | high severity — **red-orange, deliberately ≠ brand hue 52** |
| `--med` | `oklch(80% 0.14 85)` | medium |
| `--low` | `oklch(72% 0.15 155)` | low / pass-good |
| `--info` | `oklch(70% 0.14 240)` | informational |
| `--*-soft` | same hue @ 0.14 alpha | severity background fills |
| `--danger / --warning / --success` | alias → crit / med / low | **reference intent, not raw severity, in feature code** |

**RULE — brand ≠ severity.** `--flare` (hue 52) is brand/interactive; `--high` is hue 40. Never use
`--flare` to indicate risk, and never use a severity color for a CTA. This was a real collision
(brand and high-severity were identical) — keep them split.

## Typography

- **Fonts (keep):** UI = **Manrope** (`--font-ui`); mono/data = **Geist Mono** (`--font-mono`).
  Do not switch — this pairing is premium and correct for the category.
- **Mono everywhere technical:** IDs, checkIds (CFL-*), IPs, tokens, timestamps, env-var names.
- **Tabular figures:** `.v1-mono` and `.v1-tnum` set `font-variant-numeric: tabular-nums`. Use for all
  scores, counts, hop-counts, timers, and numeric table columns so they don't jitter.
- **Scale:** `12 · 14 · 16 · 20 · 24 · 32`. Body ≥ **14px**; 12px reserved for mono metadata only.
- **Weights:** headings 700; nav/labels 500–600; body 400.

## Effects & motion

- **Motion tokens:** `--dur-fast 150ms / --dur 220ms / --dur-slow 320ms`; `--ease-out` (enter),
  `--ease-in` (exit). Exit ≈ 70% of enter. Animate `transform`/`opacity` only.
- **Reduced motion:** a global `@media (prefers-reduced-motion: reduce)` neutralizes animations &
  transitions — any new animation (e.g. attack-path flow, score ring) is auto-covered; don't fight it.
- Elevation = surface step + hairline border (no heavy shadows). One ambient motion signature: the
  pulsing status dot.

## Iconography

- One stroke icon family (Lucide-compatible), `stroke-width: 1.6`, sizes `16 / 20 / 24`.
- **No emoji as structural icons.** No mixing filled/outline at the same hierarchy level.

## Accessibility (non-negotiable)

- **`color-not-only`:** pair every severity with a glyph/shape + text label (esp. posture map, charts,
  notifications). Never color alone.
- **Contrast:** body text ≥ 4.5:1. `--fg-3` is for ≥14px secondary/metadata only — never primary body.
- **Focus:** visible `:focus-visible` ring (already `2px var(--flare)`); all interactive elements
  (incl. graph nodes) keyboard-focusable with `role`/`aria-label`.

## Anti-patterns

- Brand orange used to mean "danger"; severity color used for a CTA.
- Body text < 14px; gray-on-gray; raw hex in components (use tokens).
- Emoji icons; pie charts with >5 categories; color-only meaning; animations that ignore reduced-motion.

## Per-surface specs

- **Posture map / attack paths** — see `design-system/pages/posture-map.md` (override).
- **SIEM dashboards (Kibana/Splunk):** ship a canonical severity→hex map so host-rendered panels match
  the app exactly; score-over-time = line + anomaly highlights; severity = stacked bar (not pie);
  always legends + empty/loading states; tabular numerals.
- **Notification cards (Slack/Teams/webhook):** stay within each platform idiom but carry a
  severity-colored bar/container + logo; **emoji-free** (severity = colored chip **+** text label);
  payload = score, grade, top findings, attack-path count, one CTA.
- **Agents & MCP:** mono for tokens/IDs; **mask secrets**; show the apply-gate state
  (`FLAREINSPECT_ALLOW_REMEDIATION`) with the same badge component used elsewhere.

## Navigation (information architecture)

Grouped sidebar: **Workspace** (Overview, Run assessment, Findings, Posture map, Compliance, History) ·
**Remediation** (Remediate) · **Integrations** (SIEM, Notifications, Agents & MCP) · **System**
(Exports, Full report, API health). Unbuilt integrations show honest "soon" badges + configure/empty
states — never dead links.
