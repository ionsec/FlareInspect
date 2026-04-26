=============
Web Dashboard
=============

FlareInspect includes a local web dashboard for viewing assessment history, compliance reports, and downloading results through a browser-based interface. Since v1.2.1 the dashboard ships the **V1 "Command"** design — a dark, sidebar-driven SPA built around a score-ring hero and a zone matrix.

Starting the Dashboard
-----------------------

.. code-block:: bash

   node web/server.js

Or with custom host and port:

.. code-block:: bash

   HOST=0.0.0.0 PORT=8080 node web/server.js

Layout
------

The interface is a single-page app with two persistent regions and eight pages.

**Sidebar** (240 px, sticky, ``var(--bg-1)``)
  Brand mark + wordmark, account picker, two nav groups (*Workspace*: Overview, Run assessment, Findings, Compliance, History — *System*: Exports, Full report, API health), and a footer with system status and Docs/GitHub links.

**Topbar** (56 px, sticky, blurred)
  Breadcrumbs (``account / page``), global search input (``⌘K``), ghost **Export** button, primary **New run** button. The topbar bottom border is baseline-aligned with the sidebar brand bottom border at 56 px.

**Pages**

- **Overview** — hi-fi hero. Animated 170 px score ring with gradient stroke (green → amber → flare orange), grade letter, three score-key rows (previous, sparkline, passed), and a *By category* breakdown with weighted bars. To the right: a severity strip (proportional segments for critical/high/medium/low) and a compliance rail (CIS, SOC 2, PCI, NIST). Below the grid: top findings list and a zone matrix card per Cloudflare zone with plan pill, posture score, and severity chips.
- **Run assessment** — token + zone-filter form with progress bar.
- **Findings** — full filterable list with severity pills, evidence (observed → expected), and status badges.
- **Compliance** — per-framework cards.
- **History** — list of runs with score, grade, trigger, and duration.
- **Exports** — download tiles for JSON · HTML · OCSF · SARIF · Markdown · CSV · ASFF.
- **Full report** — embedded HTML report iframe.
- **API health** — server health key/value rows.

Design tokens
-------------

The dashboard uses OKLCH-based color tokens (``--flare``, ``--crit``, ``--high``, ``--med``, ``--low``, ``--info``) and the *Manrope* + *Geist Mono* + *Fraunces* font stack. The brand mark — a flare burst held in an inspection reticle — is the same SVG used in the README, CLI banner, and HTML report.

Features
--------

- Assessment history with score trends and 12-run sparkline
- Compliance report viewing (CIS, SOC 2, PCI-DSS, NIST CSF)
- Drift comparison between assessment runs
- Report download in HTML, Markdown, CSV, SARIF, OCSF, and ASFF
- API key authentication for non-localhost deployments
- Responsive: at viewport ≤ 768 px the sidebar collapses to an off-canvas drawer with a hamburger toggle

.. toctree::
   :maxdepth: 1
   :hidden:

   api-reference
   authentication
