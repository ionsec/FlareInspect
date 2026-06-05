================
Elasticsearch
================

Ship FlareInspect findings to Elasticsearch using the **ECS 8.11.0**
mapping.  Every event is enriched with its resource-graph node and
the attack paths it participates in.

Wire protocol
-------------

The live shipper posts to ``{esUrl}/_bulk`` with the standard
``application/x-ndjson`` body.  Each line is either a ``{"index":
{"_index": "flareinspect-findings"}}`` action or a JSON document.
The index name defaults to ``flareinspect-findings`` (override with
``--index-name``).  Authentication is **ApiKey** (``--es-api-key``)
or **Basic** (``--es-username`` / ``--es-password``).

Document shape
--------------

.. code-block:: text

   {
     "@timestamp": "2026-05-30T12:34:56.789Z",
     "event": {
       "kind": "alert",
       "category": ["vulnerability"],
       "type": ["finding"],
       "module": "flareinspect",
       "severity_name": "high",
       "dataset": "flareinspect.findings"
     },
     "vulnerability": {
       "id": "CFL-INSIGHT-005::x.test::a.x.test",
       "classification": "EXPOSURE",
       "severity": "high",
       "score": { "base": 7.5 }
     },
     "host": { "name": "x.test" },
     "url":   { "full": "https://x.test/" },
     "cloud": { "account": { "id": "acct-1", "name": "Acme" } },
     "labels": {
       "status": "failed",
       "remediable": "true",
       "check_id": "CFL-INSIGHT-005"
     },
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
     },
     "related": { "entity": ["x.test", "203.0.113.1"] }
   }

Index template
--------------

Apply the bundled ``integrations/elastic/flareinspect-index-template.json``
to ensure the ``threat.enrichments`` field is mapped as ``nested``
(the default ``object`` mapping won't allow per-path queries).

.. code-block:: bash

   curl -X PUT "$ES_URL/_index_template/flareinspect" \
     -H "Authorization: ApiKey $ES_API_KEY" \
     -H "Content-Type: application/json" \
     --data-binary @integrations/elastic/flareinspect-index-template.json

The same template is served at runtime by
``GET /api/integrations/template/elastic`` for scripted bootstrap.

CLI
---

.. code-block:: bash

   # Dry-run
   flareinspect ship -i assessment.json --target elastic \
     --es-url https://es.example.com --es-api-key $ES_KEY --dry-run

   # Live ship
   flareinspect ship -i assessment.json --target elastic \
     --es-url https://es.example.com --es-api-key $ES_KEY

   # Write the bulk body to a file (no HTTP)
   flareinspect ship -i assessment.json --target file \
     --out-dir ./out --index-name flareinspect-findings

   # Ship to both elastic and splunk in one call
   flareinspect ship -i assessment.json --target all \
     --es-url ... --es-api-key ... \
     --hec-url ... --hec-token ...

See :doc:`/cli/ship` for the full flag table and env-var fallbacks.

Web API
-------

.. code-block:: bash

   curl -X POST http://localhost:3000/api/integrations/ship \
     -H "X-API-Key: $FLAREINSPECT_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "elastic",
       "esUrl": "https://es.example.com",
       "esApiKey": "...",
       "assessment": { ... },
       "includeTemplate": true
     }'

The response body includes ``ok``, ``count``, and the upstream
Elasticsearch status.  When ``includeTemplate: true`` is set, the
response also carries ``indexTemplate`` (the same shape as
``GET /api/integrations/template/elastic``).

Packaged Kibana app
-------------------

``integrations/elastic/flareinspect-dashboard.ndjson`` is a Kibana
saved-objects bundle with:

- 1 data view (``flareinspect-*``)
- 1 saved search (the *FlareInspect findings* table)
- 2 visualizations (severity histogram + attack-paths pie)
- 1 dashboard (combines the three above)

Import via **Kibana → Stack Management → Saved Objects → Import**, or
via the API:

.. code-block:: bash

   curl -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
     -H "kbn-xsrf: true" \
     --form file=@integrations/elastic/flareinspect-dashboard.ndjson

The bundled visualizations are *visualization* type (histogram + pie)
rather than the more brittle *lens* type so the import always succeeds
against a fresh Kibana instance.

Next steps
----------

- :doc:`/siem/splunk` — the Splunk HEC equivalent
- :doc:`/cli/ship` — the ``ship`` CLI reference
- ``integrations/elastic/README.md`` — the integration's own README
