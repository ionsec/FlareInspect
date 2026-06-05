FlareInspect
============

.. image:: _static/logo.svg
   :align: center
   :width: 300
   :alt: FlareInspect logo

.. image:: https://img.shields.io/badge/node-%3E%3D20.0.0-green?style=flat-square
   :target: https://github.com/ionsec/flareinspect/actions

.. image:: https://img.shields.io/badge/version-2.0.0-orange?style=flat-square

.. image:: https://img.shields.io/badge/license-MIT-blue?style=flat-square

.. image:: https://img.shields.io/badge/docs-Sphinx-8B5CF6?style=flat-square

|

**FlareInspect** is an open-source Cloudflare security assessment CLI
and local web dashboard built by `IONSEC.IO <https://ionsec.io>`__.
Scan your infrastructure, detect posture drift, ship findings to a
SIEM, and let an MCP-aware agent drive the full
*assess → find → path → plan → apply* loop.

Highlights
----------

.. list-table::
   :widths: 30 70
   :class: a11-y

   * - 🔍 **50+ Security Checks**
     - 34 categories spanning DNS, SSL/TLS, WAF, Zero Trust, Workers, Access, CASB, Magic, and more.
   * - 🕸️ **Resource Graph** *(v2.0)*
     - Typed node/edge view of the account — the single source of truth for the posture map, attack paths, and SIEM enrichment.
   * - ⚔️ **Attack-Path Engine** *(v2.0)*
     - Five rule-based detectors chain findings into paths that lead to high/critical exposure.
   * - 🗺️ **Posture Map** *(v2.0)*
     - Interactive entity graph in the dashboard — Internet → Account → Zones → services, with severity colours and attack-path highlight.
   * - 🚢 **SIEM Shipping** *(v2.0)*
     - ``flareinspect ship`` to Elasticsearch (ECS) or Splunk HEC, with attack-path enrichment.  Packaged Kibana and Splunk apps included.
   * - 🤖 **MCP Server** *(v2.0)*
     - ``flareinspect-mcp`` exposes the engine to any MCP-aware agent (Claude Code, Cowork, Hermes, OpenClaw) over stdio.
   * - 🔔 **Notifications** *(v2.0)*
     - ``flareinspect notify`` to Slack (Block Kit), Microsoft Teams (Adaptive Card 1.5), or an HMAC-signed generic webhook.
   * - 📊 **Drift Detection**
     - Track posture regressions over time with ``flareinspect diff``.
   * - 📋 **Compliance Mapping**
     - CIS, SOC 2, PCI-DSS, and NIST CSF controls.
   * - 📄 **Multi-Format Export**
     - JSON, HTML, OCSF, SARIF, Markdown, CSV, ASFF, ECS, and Splunk HEC.
   * - 🌐 **Web Dashboard**
     - Local UI with assessment history, posture map, score visualization, and downloads.
   * - ☁️ **1-Click Deploy**
     - Deploy to Render, Heroku, Railway, or Fly.io in minutes.
   * - 🚀 **CI/CD Ready**
     - Exit codes, threshold gates, and SARIF output for any pipeline.
   * - 🔌 **Plugin Support**
     - Scaffold trusted local extensions for custom checks.

.. toctree::
   :maxdepth: 2
   :caption: Contents
   :numbered:

   getting-started
   quick-start
   installation
   cli/index
   configuration/index
   checks/index
   export-formats/index
   compliance/index
   scoring/index
   drift-detection/index
   web-dashboard/index
   posture-map/index
   siem/index
   mcp/index
   ci-cd/index
   deployment/index
   plugins/index
   architecture/index
   contributing/index
   permissions-guide
   troubleshooting
   faq
   changelog

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
