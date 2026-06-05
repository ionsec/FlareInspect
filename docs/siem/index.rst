========
SIEM
========

FlareInspect v2.0 ships first-class **Elasticsearch** and **Splunk**
shipping for findings.  Every shipped event is enriched with its
**resource-graph node** and every **attack path** it participates in,
so SIEM rules can alert on *paths*, not just findings.

The wire protocol lives in ``src/core/integrations/siem/`` and is
re-used by three surfaces — the ``flareinspect ship`` CLI, the
``/api/integrations/ship`` web endpoint, and the file exporters.  The
packaged Kibana saved-objects bundle and Splunk Technology Add-on
under ``integrations/`` are import-ready dashboards and field
extractions tuned to the same payload.

.. toctree::
   :maxdepth: 1
   :hidden:

   elastic
   splunk

Why ship to a SIEM?
-------------------

A standalone assessment tells you what is wrong *right now*.  A
SIEM tells you what changed *over time* and *across all your
accounts*.  Two operators running the same assessment at 3 a.m.
will see the same critical findings; what they want from a SIEM
is correlation, alerting, and historic context.

To support that, every shipped event carries:

- the **finding** (severity, evidence, check ID, resource);
- the **graph node** the finding is attached to (typed by
  ``node.type`` and keyed by ``node.id``);
- the **attack path IDs** the finding participates in
  (``flareinspect.attack_path_ids[]`` and a nested
  ``threat.enrichments[]`` with the full path node/edge list and
  explanation).

Common shape
------------

For Elasticsearch we use **ECS 8.11.0** field names; for Splunk we
use a **CIM-aligned** envelope.  Both ship *the same logical
information* under slightly different field names so the dashboards
work out of the box on each platform.

.. list-table::
   :header-rows: 1
   :widths: 28 36 36

   * - Concept
     - Elasticsearch (ECS)
     - Splunk (CIM)
   * - Severity
     - ``event.severity_name`` + ``vulnerability.severity``
     - ``event_severity`` + ``vulnerability.severity``
   * - Finding ID
     - ``vulnerability.id``
     - ``vulnerability.id``
   * - Affected resource
     - ``host.name`` / ``url.full``
     - ``host`` / ``url``
   * - Graph node
     - ``flareinspect.node.id`` + ``flareinspect.node.type``
     - ``flareinspect.node.id`` + ``flareinspect.node.type``
   * - Attack paths
     - ``flareinspect.attack_path_ids[]`` + ``threat.enrichments[]``
     - ``flareinspect.attack_path_ids[]`` + ``threat.enrichments[]``
   * - Status / remediable
     - ``labels.status`` / ``labels.remediable``
     - ``status`` / ``remediable``

Targets
-------

``flareinspect ship --target <target>`` accepts one of:

- ``elastic`` — live ship to Elasticsearch via ``POST {esUrl}/_bulk`` (ApiKey or Basic auth)
- ``splunk`` — live ship to Splunk via ``POST {hecUrl}/services/collector/event`` (``Authorization: Splunk <token>``)
- ``all`` — both elastic and splunk in one call (each target reports its own ok / error)
- ``file`` — skip the HTTP path; write the same NDJSON the live shipper would have posted, plus the recommended Elasticsearch index template, into ``--out-dir``.  Use this for air-gapped environments or for piping the file into an offline SIEM.

All four targets support ``--dry-run``: the payload is built and printed, but no HTTP and no file write.

The web API mirrors the same dispatch — see :doc:`/web-dashboard/api-reference`
for ``POST /api/integrations/ship``.

Authentication
--------------

For Elasticsearch, prefer **ApiKey** (``--es-api-key``) but Basic auth
(``--es-username`` / ``--es-password``) is also supported.  For
Splunk, the **HEC token** (``--hec-token``) is the only auth option.

All credentials can come from CLI flags or env vars (see the
*Environment variables* table in
:doc:`/web-dashboard/api-reference`).  Flags take precedence; the
web API reads from the JSON body first.

Pull / air-gapped mode
----------------------

When you can't reach the SIEM directly, use ``--out-dir`` to write
the files the live shipper would have posted:

.. code-block:: bash

   flareinspect ship -i assessment.json --target file --out-dir ./out

This produces:

- ``flareinspect-findings-<timestamp>.ndjson`` — the ECS _bulk body
- ``flareinspect-hec-<timestamp>.ndjson`` — the HEC envelopes
- ``flareinspect-index-template.json`` — the recommended Elasticsearch index template (also available at ``GET /api/integrations/template/elastic``)

The two NDJSON files can be replayed later with
``curl -H "Authorization: ApiKey $KEY" --data-binary @…``
or by piping into the HEC collector.

Deduplication
-------------

Every shipped document carries the finding ID under
``vulnerability.id`` and the assessment ID under
``flareinspect.assessment_id``.  Most SIEMs will index these
automatically; for idempotent re-ship we recommend an ingest
pipeline (Elasticsearch) or a search-time lookup (Splunk) keyed on
the same fields.

Next steps
----------

- :doc:`elastic` — Elasticsearch ECS mapping, index template, packaged Kibana app
- :doc:`splunk` — Splunk HEC envelope, packaged TA, dashboard
