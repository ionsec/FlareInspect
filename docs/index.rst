FlareInspect
============

.. image:: _static/logo.svg
   :align: center
   :width: 300
   :alt: FlareInspect logo

.. image:: https://img.shields.io/badge/node-%3E%3D20.0.0-green?style=flat-square
   :target: https://github.com/ionsec/flareinspect/actions

.. image:: https://img.shields.io/badge/version-1.3.0-orange?style=flat-square

.. image:: https://img.shields.io/badge/license-MIT-blue?style=flat-square

.. image:: https://img.shields.io/badge/docs-Sphinx-8B5CF6?style=flat-square

|

**FlareInspect** is an open-source Cloudflare security assessment CLI and local web dashboard
built by `IONSEC.IO <https://ionsec.io>`__. Scan your infrastructure, detect posture drift,
and generate compliance reports for auditors and CI/CD pipelines.

Highlights
----------

.. list-table::
   :widths: 30 70
   :class: a11-y

   * - 🔍 **40+ Security Checks**
     - DNS, SSL/TLS, WAF, Zero Trust, Workers, API Gateway, and more.
   * - 📊 **Drift Detection**
     - Track posture regressions over time with ``flareinspect diff``.
   * - 📋 **Compliance Mapping**
     - CIS, SOC 2, PCI-DSS, and NIST CSF controls.
   * - 📄 **Multi-Format Export**
     - JSON, HTML, OCSF, SARIF, Markdown, CSV, and ASFF.
   * - 🌐 **Web Dashboard**
     - Local UI with assessment history, score visualization, and downloads.
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
