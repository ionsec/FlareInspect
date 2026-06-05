================
Resource Graph
================

The **resource graph** is the typed node/edge view of a Cloudflare
account, built once per assessment and shared by the attack-path
engine, the SIEM shippers, the MCP ``get_attack_paths`` tool, the
notification dispatcher, and the dashboard **Posture map** page.  It
is the only place findings are joined to entities; every downstream
consumer reads from the same shape.

Source: ``src/core/graph/resourceGraph.js``.

Building the graph
------------------

.. code-block:: javascript

   const { buildResourceGraph } = require('flareinspect/src/core/graph/resourceGraph');
   const graph = buildResourceGraph(assessment);
   // graph = { nodes: [...], edges: [...], stats: {...} }

The builder walks ``assessment.zones``, ``assessment.configuration``,
``assessment.findings``, and the per-account sub-resources (Workers,
KV, D1, Queues, Zaraz, access apps, tunnels, …) and emits a
flat array of typed nodes and a flat array of typed edges.  Findings
are attached to their owning node (so the attack-path rules, the
posture map, and the SIEM enrichments all see the same attachment).

Node types
----------

There are **14** node types.  Each node has a stable ``id`` (the
``{type}:{zone|account}:{resource}`` triple), a ``type`` string, a
``label`` (for the UI), and a ``props`` bag of resource-specific
data.

.. list-table::
   :header-rows: 1
   :widths: 22 50 28

   * - Type
     - Meaning
     - Example id
   * - ``internet``
     - Synthetic root node — the entry point for every external request
     - ``internet``
   * - ``account``
     - The Cloudflare account
     - ``account:acct-1``
   * - ``zone``
     - A zone in the account
     - ``zone:z1``
   * - ``dns_record``
     - A DNS record (A / AAAA / CNAME / TXT / …)
     - ``dns:z1:r1``
   * - ``origin``
     - The IP / hostname a record resolves to
     - ``origin:203.0.113.1``
   * - ``worker``
     - A Cloudflare Worker script
     - ``worker:z1:ping``
   * - ``tunnel``
     - A Cloudflare Tunnel
     - ``tunnel:t1``
   * - ``access_app``
     - A Cloudflare Access application
     - ``access_app:a1``
   * - ``r2_bucket``
     - An R2 bucket
     - ``r2:b1``
   * - ``kv_namespace``
     - A Workers KV namespace
     - ``kv:k1``
   * - ``d1_database``
     - A D1 database
     - ``d1:d1``
   * - ``queue``
     - A Workers Queue
     - ``queue:q1``
   * - ``service``
     - A generic downstream service (tunnel target, LB origin, …)
     - ``service:s1``
   * - ``finding``
     - A finding attached to a parent node (informational; rare)
     - ``finding:f1``

Edge types
----------

There are **8** edge types.  Each edge has ``from``, ``to``, and a
``type`` string.  Edges are directional but the UI draws them
undirected.

.. list-table::
   :header-rows: 1
   :widths: 24 36 40

   * - Type
     - Meaning
     - Example
   * - ``belongs_to``
     - Hierarchical ownership (record → zone → account)
     - ``dns:z1:r1`` → ``zone:z1``
   * - ``resolves_to``
     - DNS A/AAAA/CNAME record → origin
     - ``dns:z1:r1`` → ``origin:203.0.113.1``
   * - ``proxies``
     - Proxied DNS record → its service
     - ``dns:z1:www`` → ``service:www``
   * - ``exposes``
     - Tunnel / worker / access-app → service
     - ``tunnel:t1`` → ``service:api``
   * - ``protects``
     - Access app → service (or Access policy → app)
     - ``access_app:a1`` → ``service:api``
   * - ``executes``
     - Worker script → service / route
     - ``worker:z1:ping`` → ``service:ping``
   * - ``reads``
     - Worker → KV / D1 / R2
     - ``worker:z1:svc`` → ``kv:k1``
   * - ``internet_to``
     - Internet → entry node
     - ``internet`` → ``dns:z1:www``

The ``stats`` bag on the graph records counts (nodes by type, edges
by type, findings by severity).

Attack-path rules
-----------------

``src/core/graph/attackPaths.js`` runs five rule-based detectors
against the graph.  Each rule reads nodes + edges + the
``findingsByNode`` index and emits 0+ paths.  Rules are
**deterministic and ordered** — same input → same path IDs (so the
UI can deep-link a path).

.. list-table::
   :header-rows: 1
   :widths: 22 14 64

   * - Kind
     - Severity
     - Trigger
   * - ``exposed-origin``
     - high
     - Un-proxied A/AAAA/CNAME record that resolves to an origin
   * - ``weak-transport``
     - high
     - TLS configuration that does not enforce HTTPS / min TLS 1.2
   * - ``open-access-app``
     - high
     - Access app whose policy effectively allows everyone (no MFA / allow-everyone)
   * - ``tunnel-without-access``
     - medium
     - Public tunnel routing to a private service with no Access app in front
   * - ``worker-plaintext-secret``
     - critical
     - Workers binding whose value is a secret-shaped plain-text string (e.g. ``sk-…``, ``AKIA…``)

Each emitted path has the shape:

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

Adding a new rule
-----------------

1. Append a new ``detect*`` function in ``attackPaths.js``.
2. Add it to the ``RULES`` array with a unique ``kind`` string.
3. Add a fixture + assertion in ``tests/attackPaths.test.js``.

The pipeline is fault-tolerant: a single rule that throws is
captured as a ``rule_error:<kind>`` path so the rest of the rules
still run.

Consumers
---------

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Consumer
     - What it reads
   * - Posture map (``web/public/postureMap.js``)
     - Full graph + paths; draws nodes, edges, attack paths
   * - ``/api/posture/graph``
     - Returns the graph + paths JSON for the dashboard
   * - SIEM shippers (``src/core/integrations/siem/enrichment.js``)
     - Per-finding ``node`` + ``threat.enrichments[]`` join
   * - MCP ``flareinspect_get_attack_paths`` tool
     - Returns the graph + paths to the agent
   * - Notification dispatcher
     - ``attackPathCount`` in the summary payload

Next steps
----------

- :doc:`/posture-map/index` — how the dashboard page uses this graph
- :doc:`/siem/index` — how the shippers enrich findings with the graph
- :doc:`/mcp/index` — the MCP ``get_attack_paths`` tool
