FlareInspect
===========

.. image:: _static/logo.svg
   :align: center
   :width: 300
   :alt: FlareInspect logo

.. image:: https://img.shields.io/badge/node-%3E%3D20.0.0-green?style=flat-square
   :target: https://github.com/ionsec/flareinspect/actions
.. image:: https://img.shields.io/badge/version-1.2.0-orange?style=flat-square
.. image:: https://img.shields.io/badge/license-MIT-blue?style=flat-square
.. image:: https://img.shields.io/badge/docs-Sphinx-8B5CF6?style=flat-square

|

**FlareInspect** is an open-source Cloudflare security assessment CLI tool and web dashboard
built by `IONSEC.IO <https://ionsec.io>`__. Scan your infrastructure, detect posture drift,
and generate compliance reports for auditors and CI/CD pipelines.

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
   contributing
   permissions-guide
   troubleshooting
   faq
   changelog

.. grid::
   :gutter: 3

   .. grid-item-card:: 🔍 Security Checks
      :text-align: center

      40+ checks across DNS, SSL/TLS, WAF, Zero Trust, Workers, API Gateway, and more.

   .. grid-item-card:: 📊 Drift Detection
      :text-align: center

      Track posture regressions over time with ``flareinspect diff``.

   .. grid-item-card:: 📋 Compliance
      :text-align: center

      Mapped to CIS, SOC 2, PCI-DSS, and NIST CSF controls.

   .. grid-item-card:: 📄 Multi-Format Export
      :text-align: center

      JSON, HTML, OCSF, SARIF, Markdown, CSV, and ASFF.

   .. grid-item-card:: 🌐 Web Dashboard
      :text-align: center

      Local UI with assessment history, score visualization, and downloads.

   .. grid-item-card:: ☁️ 1-Click Deploy
      :text-align: center

      Deploy to Render, Heroku, Railway, or Fly.io in minutes.

   .. grid-item-card:: 🚀 CI/CD Ready
      :text-align: center

      Exit codes, threshold gates, and SARIF output for any pipeline.

   .. grid-item-card:: 🔌 Plugin Support
      :text-align: center

      Scaffold trusted local extensions for custom checks.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
