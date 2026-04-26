===========
HTML Export
===========

The HTML export format produces a shareable interactive report for browsers. Reports include score summaries, severity breakdowns, detailed findings review, and remediation guidance.

Since v1.2.1 the report ships the **V1 dark design** — same brand language as the web dashboard — and embeds canvas-based charts inline so the file remains self-contained (no external scripts, no internet required to view).

Usage
-----

.. code-block:: bash

   flareinspect export -i assessment.json -f html -o output.html

Layout
------

The report is a single self-contained HTML document with the following sections:

- **Masthead** — flare-in-reticle mark, *FlareInspect* wordmark (Fraunces + italic flare-orange *Inspect*), account name, completion timestamp, and run duration.
- **KPI strip** — overall score, grade, total findings, zones assessed, checks run, passed checks.
- **Score & severity** — score-ring SVG and a severity bar (critical/high/medium/low).
- **Charts** — two canvas bar charts: one for risk distribution by severity, one for findings by category. Rendered with vanilla ``<canvas>`` (no Chart.js or other CDN dependencies).
- **Detailed Findings Review** — every finding with severity pill, ``id · category · zone``, evidence, observed/expected, remediation guidance, and OCSF-aligned metadata.
- **Affected Entities** — table of zones/resources implicated by failing checks.
- **Compliance summary** — per-framework score rows (CIS, SOC 2, PCI-DSS, NIST CSF).

The report inherits the dashboard's OKLCH color tokens and is safe to email, archive, or attach to a ticket — open it offline and every chart, font fallback, and interaction still works.

