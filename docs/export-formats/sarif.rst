============
SARIF Export
============
============

The SARIF (Static Analysis Results Interchange Format) export produces a file compatible with GitHub Advanced Security code scanning alerts. Upload SARIF files to GitHub to display findings alongside code.

Usage
-----

.. code-block:: bash

   flareinspect export -i assessment.json -f sarif -o output.sarif

