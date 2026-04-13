=================
CI/CD Integration
=================
=================

.. toctree::
   :maxdepth: 1
   :hidden:

   github-actions
   gitlab-ci
   exit-codes

FlareInspect integrates with CI/CD pipelines to gate deployments on security posture. The ``--ci`` flag produces machine-readable output and sets exit codes based on configurable thresholds.

Quick Start
-----------

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --ci --threshold 80 --fail-on high

- ``--ci`` — outputs JSON to stdout, disables spinners and banners
- ``--threshold 80`` — exits with code ``1`` if overall score is below 80
- ``--fail-on high`` — exits with code ``1`` if any finding at severity high or above is FAIL
