=======
Splunk
=======

Ship FlareInspect findings to Splunk via the **HTTP Event Collector
(HEC)**.  Events use a **CIM-aligned** envelope; the bundled
Technology Add-on (``TA-flareinspect``) extracts them into the
``cloudflare:flareinspect:finding`` sourcetype and aliases the fields
to the standard ``vulnerability.*`` namespace.

Wire protocol
-------------

The live shipper posts to
``POST {hecUrl}/services/collector/event`` with
``Authorization: Splunk <token>``.  The body is one JSON envelope per
line (``application/json``).  Per-event errors are accumulated
rather than thrown — a single 4xx doesn't abort the rest of the
batch.

Event shape
-----------

.. code-block:: text

   {
     "time": 1748604896.789,
     "host": "flareinspect",
     "source": "flareinspect",
     "sourcetype": "cloudflare:flareinspect:finding",
     "index": "main",
     "event": {
       "vulnerability": {
         "id": "CFL-INSIGHT-005::x.test::a.x.test",
         "classification": "EXPOSURE",
         "severity": "high",
         "score": { "base": 7.5 }
       },
       "event": {
         "kind": "alert",
         "category": ["vulnerability"],
         "type": ["finding"],
         "module": "flareinspect",
         "severity_name": "high",
         "dataset": "flareinspect.findings"
       },
       "host": { "name": "x.test" },
       "url":   { "full": "https://x.test/" },
       "cloud": { "account": { "id": "acct-1", "name": "Acme" } },
       "status": "failed",
       "remediable": true,
       "flareinspect": {
         "assessment_id": "ast-2026-05-30-...",
         "node": { "id": "dns:z1:r1", "type": "dns_record" },
         "attack_path_ids": ["ap:exposed-origin:dns:z1:r1"],
         "remediable": true,
         "rule_kind": "exposed-origin"
       },
       "threat": {
         "enrichments": [
           { "indicator": { "type": "attack-path" },
             "attack_path": {
               "id": "ap:exposed-origin:dns:z1:r1",
               "kind": "exposed-origin",
               "severity": "high",
               "hop_count": 2,
               "entry_node_id": "internet",
               "target_node_id": "origin:203.0.113.1",
               "nodes": ["internet", "dns:z1:r1", "origin:203.0.113.1"],
               "explanation": "DNS record a.x.test (A) is not proxied and resolves to 203.0.113.1 — origin is directly reachable from the Internet."
             }
           }
         ]
       }
     }
   }

CLI
---

.. code-block:: bash

   # Dry-run
   flareinspect ship -i assessment.json --target splunk \
     --hec-url https://splunk.example.com:8088 \
     --hec-token $HEC_TOKEN --dry-run

   # Live ship
   flareinspect ship -i assessment.json --target splunk \
     --hec-url https://splunk.example.com:8088 \
     --hec-token $HEC_TOKEN

   # Override the default 'main' index
   flareinspect ship -i assessment.json --target splunk \
     --hec-url ... --hec-token ... --splunk-index flare

See :doc:`/cli/ship` for the full flag table and env-var fallbacks.

Web API
-------

.. code-block:: bash

   curl -X POST http://localhost:3000/api/integrations/ship \
     -H "X-API-Key: $FLAREINSPECT_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "splunk",
       "hecUrl": "https://splunk.example.com:8088",
       "hecToken": "...",
       "assessment": { ... }
     }'

The response body includes ``ok``, ``count``, ``sent`` (number of
events actually accepted by HEC), and the upstream Splunk
``ackId``.

Packaged Technology Add-on (TA)
-------------------------------

``integrations/splunk/TA-flareinspect/`` is a minimal Splunk TA that:

- Declares the ``cloudflare:flareinspect:finding`` sourcetype and
  extracts it via ``KV_MODE = json``.
- Defines field renames (``transforms.conf``) so the JSON envelope
  fields land on the standard ``vulnerability.*`` namespace
  (CIM-aligned).
- Ships 2 saved searches (*FlareInspect — critical open* and
  *FlareInspect — high attack paths*).
- Ships 1 SimpleXML dashboard (*FlareInspect overview*) with a
  severity bar, a top-attack-paths pie, and a recent-findings table.

Install:

.. code-block:: bash

   cp -R integrations/splunk/TA-flareinspect $SPLUNK_HOME/etc/apps/
   # …or package and install via the Splunk UI / deployer

HEC configuration (Splunk UI):

- **Settings → Data → HTTP Event Collector → New Token**
- Index: ``main`` (or the index you'll use)
- Source type override: ``cloudflare:flareinspect:finding``
- Default index: ``main`` (or override per ship with ``--splunk-index``)

Next steps
----------

- :doc:`/siem/elastic` — the Elasticsearch equivalent
- :doc:`/cli/ship` — the ``ship`` CLI reference
- ``integrations/splunk/README.md`` — the integration's own README
