============
Posture Map
============

The **Posture map** is a v2.0 dashboard page that visualises the
resource graph and attack paths discovered in the most recent
assessment.  It is a Wiz-style entity graph — Internet at the top,
Account below it, Zones under that, services under the zones — with
edges connecting entities and severity colours for nodes.  Attack
paths (chains that lead to a high/critical exposure) are drawn as
animated dashed edges and a side-drawer surfaces the findings that
participate in them.

What it shows
-------------

- **Nodes** — every entity in the account graph: the *Internet*
  root, the *Account*, every *Zone*, every *DNS record*, every
  *Worker*, every *Origin*, every *Tunnel*, every *Access app*, …
  Nodes are coloured by the worst finding severity attached to them
  (``info``/``low``/``medium``/``high``/``critical``).
- **Edges** — typed relationships (a zone contains a DNS record; a
  DNS record resolves to an origin; a tunnel exposes a service; …).
  Edges are drawn as soft cubic-bezier curves.
- **Attack paths** — chains of nodes/edges where the path severity
  is ``high`` or ``critical``.  These are drawn as **animated dashed**
  lines so they pop visually.  The animation is disabled when the
  user has ``prefers-reduced-motion`` set.

How it is built
---------------

The page is a pure front-end feature — no new npm deps, no build
tooling.  The data comes from a single endpoint:

.. code-block:: text

   GET /api/posture/graph?assessmentId=<id>

…which returns the typed resource graph (``nodes``, ``edges``,
``stats``) and the attack paths (``findAttackPaths`` output).  The
browser builds a tidy tree from the current assessment, lays it out
deterministically (same input → same node positions, so the
animation never wiggles on re-open), and renders it to SVG.

Source files:

- ``web/public/postureMap.css`` — dark glassy graph styling using the
  dashboard's CSS vars (severity-tinted nodes, soft edges, animated
  attack-path treatment, off-canvas drawer, legend, responsive
  collapse).
- ``web/public/postureMap.js`` — the SVG engine: tree build,
  deterministic layout, cubic-bezier edges, attack-path detection,
  pan/zoom, hover-neighbor focus, click-to-open drawer.
- ``web/public/index.html`` — the page container, navlink, and
  ``<script>`` tag.
- ``web/public/app.js`` — ``initPostureMap()`` wired in
  ``navigateTo``.

Interactions
------------

- **Wheel** — scroll to zoom (with ``ctrlKey`` for finer-grained
  trackpad pinch).
- **Trackpad pinch** — two-finger zoom.
- **Toolbar** — explicit ``+`` / ``−`` / *Fit* buttons in the top
  right.
- **Hover** — neighbouring nodes/edges stay sharp; the rest fade
  for a "spotlight" effect.
- **Click** — opens a side-drawer with that node's findings (sorted
  by severity desc) and a *Remediate* link that jumps to the
  Findings page filtered to that node.

Empty state
-----------

If the current assessment has no findings, the page shows a small
empty state ("No findings in this run — nothing to map.") and the
graph panel is hidden.

The implementation is **idempotent** — repeated navigations to
``/posture`` re-render cleanly without stacking event handlers or
leaking the previous SVG.

Attack-path data model
----------------------

Each path returned by ``/api/posture/graph`` has the shape:

.. code-block:: text

   {
     "id": "ap:exposed-origin:dns:z1:r1",
     "kind": "exposed-origin",
     "title": "Exposed origin (un-proxied A/AAAA/CNAME)",
     "severity": "high",
     "hopCount": 2,
     "entryNodeId": "internet",
     "targetNodeId": "origin:203.0.113.1",
     "nodes": ["internet", "dns:z1:r1", "origin:203.0.113.1"],
     "edges": [{ "from": "internet", "to": "dns:z1:r1", "type": "resolves_to" },
               { "from": "dns:z1:r1", "to": "origin:203.0.113.1", "type": "resolves_to" }],
     "explanation": "DNS record a.x.test (A) is not proxied and resolves to 203.0.113.1 — origin is directly reachable from the Internet.",
     "relatedCheckIds": ["CFL-INSIGHT-005"],
     "remediableCheckIds": []
   }

There are five rule kinds, all deterministic and ordered (same input
→ same path IDs, so the UI can deep-link a path):

- ``exposed-origin`` — un-proxied A/AAAA/CNAME record that resolves
  directly to an origin
- ``weak-transport`` — TLS configuration that does not enforce
  HTTPS / min TLS 1.2
- ``open-access-app`` — Cloudflare Access application whose policy
  effectively allows everyone
- ``tunnel-without-access`` — public tunnel routing to a private
  service with no Access app in front
- ``worker-plaintext-secret`` — Workers binding whose value is a
  secret-shaped plain-text string

See :doc:`/architecture/resource-graph` for the full data model.

Next steps
----------

- :doc:`/architecture/resource-graph` — node types, edge types,
  rule shapes
- :doc:`/architecture/overview` — how the graph fits into the engine
- :doc:`/web-dashboard/index` — the rest of the dashboard
