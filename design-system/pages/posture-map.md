# Page override — Posture Map / Attack Paths

> Overrides `design-system/MASTER.md` for the posture-map surface (`web/public/postureMap.{js,css}`).
> Inherit all MASTER tokens; the rules below take precedence for this page.

## Intent

The marquee surface — must feel Wiz-grade. A resource-topology graph with ranked attack paths.
Layered left→right: entry (Internet / identity) on the left → assets / "crown jewels" on the right.

## Nodes

- Composition: **severity accent ring + type icon + text label** (never color-only — a11y
  `color-not-only`). Crown-jewel assets get a heavier ring/elevation; entry nodes visually lighter.
- Severity = worst FAIL finding on the node; all-pass → `--low` (green). Use `--crit/--high/--med/--low`.
- **Keyboard-focusable** (`tabindex="0"`, `role="button"`, `aria-label`), openable via Enter/Space.
- Risk score in the drawer/tooltip uses tabular numerals (`.v1-tnum`).

## Edges & attack paths

- Normal edges: 1.5px, severity-soft color, rounded bezier.
- **Attack-path edges:** red-orange (`--high`/`--crit`) **dashed + animated flow** when the
  "Attack paths" toggle is on; under `prefers-reduced-motion` the global guard freezes the flow →
  render a **solid** red path (don't rely on motion to convey the path).
- Always-visible **legend**: severity swatches + glyphs + an "attack path" key + node-type icons.

## Interactions

- Pan (drag bg), wheel-zoom toward cursor (clamp ~0.3–2.5), Fit, Zoom±.
- Hover dims unrelated nodes/edges (`.pm-dim` + `.pm-focus`); click opens the drawer.
- Drawer: resource props + attached findings (severity glyph + checkId mono) + remediable badge +
  **"Remediate this path"** deep-link carrying the path's `remediableCheckIds`.

## Motion

- Use MASTER motion tokens (`--dur`, `--ease-out`). Stagger node entrance ~30–50ms. All animations
  interruptible and covered by the global reduced-motion guard.
