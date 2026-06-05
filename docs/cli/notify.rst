==============
notify Command
==============

Dispatch a summary of an assessment to one or more notification
channels: **Slack** (Block Kit), **Microsoft Teams** (Adaptive Card
1.5), or a **generic webhook** (HMAC-SHA256-signed JSON).  Added in
v2.0.

The wire protocol lives in ``src/core/integrations/notify/`` and is
re-used by the ``POST /api/notify`` web endpoint.  Each transport is
an independent module — adding a new channel is additive, no
existing code changes.

Usage
-----

.. code-block:: bash

   flareinspect notify -i assessment.json [options]

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
     - ``slack`` · ``teams`` · ``webhook`` · ``all``
     - ``all``
   * - ``--slack <url>``
     - Slack incoming-webhook URL (overrides ``FLAREINSPECT_SLACK_WEBHOOK``)
     - env
   * - ``--teams <url>``
     - Teams Power Automate webhook URL (overrides ``FLAREINSPECT_TEAMS_WEBHOOK``)
     - env
   * - ``--webhook <url>``
     - Generic webhook URL (overrides ``FLAREINSPECT_WEBHOOK_URL``)
     - env
   * - ``--secret <secret>``
     - HMAC-SHA256 secret for the generic webhook (overrides ``FLAREINSPECT_WEBHOOK_SECRET``)
     - env
   * - ``--threshold <severity>``
     - Only notify when there is at least one finding at or above this severity (``critical`` / ``high`` / ``medium`` / ``low``)
     - unset (always send)
   * - ``--link <url>``
     - Dashboard link to include in the message
     - unset
   * - ``--dry-run``
     - Build the payloads but do not POST
     - —

Env-var fallbacks
-----------------

.. list-table::
   :header-rows: 1
   :widths: 24 36

   * - Flag
     - Env var
   * - ``--slack``
     - ``FLAREINSPECT_SLACK_WEBHOOK``
   * - ``--teams``
     - ``FLAREINSPECT_TEAMS_WEBHOOK``
   * - ``--webhook``
     - ``FLAREINSPECT_WEBHOOK_URL``
   * - ``--secret``
     - ``FLAREINSPECT_WEBHOOK_SECRET``

Channels
--------

Slack
^^^^^

Renders a Block Kit message with the score, grade, severity counts,
top 5 findings (severity-sorted, with check ID and zone), and the
attack-path count.  A *View in dashboard* button is included when
``--link`` is set.

.. code-block:: bash

   flareinspect notify -i assessment.json --target slack \
     --slack https://hooks.slack.com/services/T0/B0/XXX \
     --link https://flareinspect.example.com

Microsoft Teams
^^^^^^^^^^^^^^^

Renders an Adaptive Card 1.5 with the same payload, optimised for
the Teams Power Automate "Post to channel when a webhook request is
received" trigger.

.. code-block:: bash

   flareinspect notify -i assessment.json --target teams \
     --teams https://prod-XX.logic.azure.com:443/workflows/.../triggers/manual/paths/invoke

Generic webhook (HMAC-signed)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Posts a flat JSON document with a ``X-FlareInspect-Signature``
header (``sha256=<hex>``) computed over the body using
``FLAREINSPECT_WEBHOOK_SECRET``.  Receivers should verify the
signature before trusting the payload.

.. code-block:: bash

   flareinspect notify -i assessment.json --target webhook \
     --webhook https://ops.example.com/hooks/flareinspect \
     --secret "$(openssl rand -hex 32)"

All channels
^^^^^^^^^^^^

.. code-block:: bash

   flareinspect notify -i assessment.json --target all
   # dispatches to every channel that has a URL configured

Severity threshold
------------------

``--threshold`` filters the dispatch: if the assessment has no
finding at or above the threshold, **no** notification is sent.  This
is useful in CI: you only want a ping when something is wrong.

.. code-block:: bash

   # Only ping on critical or high findings
   flareinspect notify -i assessment.json --target all --threshold high

Payload shape (generic webhook)
-------------------------------

.. code-block:: text

   {
     "assessment_id": "ast-2026-05-30-...",
     "score": 78,
     "grade": "B",
     "totals": { "critical": 1, "high": 3, "medium": 5, "low": 2, "informational": 0 },
     "attack_path_count": 2,
     "top_findings": [
       { "check_id": "CFL-INSIGHT-005", "severity": "high",
         "title": "Exposed origin", "resource": "a.x.test" }
     ],
     "link": "https://flareinspect.example.com"
   }

The HMAC-SHA256 signature is sent as
``X-FlareInspect-Signature: sha256=<hex>``.

Next steps
----------

- :doc:`ship` — the ``ship`` command (SIEM shipping)
- :doc:`/web-dashboard/api-reference` — the ``POST /api/notify`` web endpoint
