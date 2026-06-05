============
ship Command
============

Push an assessment to **Elasticsearch**, **Splunk**, or **both** —
or write the same payloads to disk in air-gapped / pull mode.

This command (added in v2.0) is the operator-facing surface for the
SIEM shippers; the wire protocol lives in
``src/core/integrations/siem/`` and is re-used by the
``/api/integrations/ship`` web endpoint and the file exporters.

Usage
-----

.. code-block:: bash

   flareinspect ship -i assessment.json [options]

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 32 60 18

   * - Option
     - Description
     - Default
   * - ``-i, --input <file>``
     - Input assessment file (JSON) *(required)*
     - —
   * - ``--target <target>``
     - ``elastic`` · ``splunk`` · ``all`` · ``file``
     - ``all``
   * - ``--es-url <url>``
     - Elasticsearch base URL (overrides ``FLAREINSPECT_ES_URL``)
     - env or required for ``--target elastic``
   * - ``--es-api-key <key>``
     - Elasticsearch API key (overrides ``FLAREINSPECT_ES_APIKEY``)
     - env or required for ``--target elastic`` *(unless basic auth)*
   * - ``--es-username <u>``
     - Elasticsearch basic-auth username (overrides ``FLAREINSPECT_ES_USERNAME``)
     - env or required for ``--target elastic`` *(unless api key)*
   * - ``--es-password <p>``
     - Elasticsearch basic-auth password (overrides ``FLAREINSPECT_ES_PASSWORD``)
     - env or required for ``--target elastic`` *(unless api key)*
   * - ``--index-name <name>``
     - Elasticsearch index name
     - ``flareinspect-findings``
   * - ``--hec-url <url>``
     - Splunk HEC base URL (overrides ``FLAREINSPECT_SPLUNK_HEC_URL``)
     - env or required for ``--target splunk``
   * - ``--hec-token <tok>``
     - Splunk HEC token (overrides ``FLAREINSPECT_SPLUNK_HEC_TOKEN``)
     - env or required for ``--target splunk``
   * - ``--splunk-index <name>``
     - Splunk index
     - ``main``
   * - ``--out-dir <dir>``
     - If set, write NDJSON to this directory and **skip** the live HTTP ship.  Only valid with ``--target file`` (implied).
     - —
   * - ``--dry-run``
     - Build the payloads but do not POST and do not write
     - —

Env-var fallbacks
-----------------

Every flag has a matching env var.  Flags take precedence over env
vars.  Use env vars for secrets in CI.

.. list-table::
   :header-rows: 1
   :widths: 32 36

   * - Flag
     - Env var
   * - ``--es-url``
     - ``FLAREINSPECT_ES_URL``
   * - ``--es-api-key``
     - ``FLAREINSPECT_ES_APIKEY``
   * - ``--es-username``
     - ``FLAREINSPECT_ES_USERNAME``
   * - ``--es-password``
     - ``FLAREINSPECT_ES_PASSWORD``
   * - ``--hec-url``
     - ``FLAREINSPECT_SPLUNK_HEC_URL``
   * - ``--hec-token``
     - ``FLAREINSPECT_SPLUNK_HEC_TOKEN``

Exit codes
----------

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Code
     - Meaning
   * - ``0``
     - All requested targets succeeded (or ``--dry-run`` / ``--out-dir`` ran cleanly)
   * - ``1``
     - Any requested target failed (missing creds, network error, 4xx/5xx, bad input)

Examples
--------

.. rubric:: Live ship to Elasticsearch

.. code-block:: bash

   flareinspect ship -i assessment.json --target elastic \
     --es-url https://es.example.com --es-api-key $ES_KEY

.. rubric:: Live ship to Splunk HEC

.. code-block:: bash

   flareinspect ship -i assessment.json --target splunk \
     --hec-url https://splunk.example.com:8088 --hec-token $HEC_TOKEN

.. rubric:: Ship to both in one call

.. code-block:: bash

   flareinspect ship -i assessment.json --target all \
     --es-url https://es.example.com --es-api-key $ES_KEY \
     --hec-url https://splunk.example.com:8088 --hec-token $HEC_TOKEN

.. rubric:: Dry-run (print the payload, do not POST)

.. code-block:: bash

   flareinspect ship -i assessment.json --target elastic \
     --es-url https://es.example.com --es-api-key $ES_KEY --dry-run

.. rubric:: Pull / air-gapped (write NDJSON to a directory)

.. code-block:: bash

   flareinspect ship -i assessment.json --target file --out-dir ./out

This produces ``flareinspect-findings-<timestamp>.ndjson`` (ECS
shape) and ``flareinspect-hec-<timestamp>.ndjson`` (HEC shape), plus
``flareinspect-index-template.json`` (the recommended ES template).

.. rubric:: CI: env-var-driven

.. code-block:: bash

   export FLAREINSPECT_ES_URL=https://es.example.com
   export FLAREINSPECT_ES_APIKEY=$ES_KEY
   flareinspect ship -i assessment.json --target elastic
   # exit 0 on success, exit 1 on failure — CI-friendly

Packaged apps
-------------

The shipped payloads are tuned for the bundled Kibana and Splunk
apps under ``integrations/``:

- :doc:`/siem/elastic` — the ECS mapping, index template, and packaged Kibana saved-objects bundle
- :doc:`/siem/splunk` — the HEC envelope, packaged TA, and dashboard

Next steps
----------

- :doc:`/siem/index` — SIEM section landing page
- :doc:`/web-dashboard/api-reference` — the ``POST /api/integrations/ship`` web endpoint
- :doc:`notify` — the ``notify`` command (Slack / Teams / webhook)
