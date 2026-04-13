=============
Web Dashboard
=============

FlareInspect includes a local web dashboard for viewing assessment history, compliance reports, and downloading results through a browser-based interface.

Starting the Dashboard
-----------------------

.. code-block:: bash

   node web/server.js

Or with custom host and port:

.. code-block:: bash

   HOST=0.0.0.0 PORT=8080 node web/server.js

Features
--------

- Assessment history with score trends
- Compliance report viewing (CIS, SOC 2, PCI-DSS, NIST CSF)
- Drift comparison between assessment runs
- Report download in HTML, Markdown, CSV, SARIF, OCSF, and ASFF
- API key authentication for non-localhost deployments

.. toctree::
   :maxdepth: 1
   :hidden:

   api-reference
   authentication
