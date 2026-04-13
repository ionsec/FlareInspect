Drift Detection
===============

.. toctree::
   :maxdepth: 1
   :hidden:

   interpreting-drift

Security posture is not static. Use the ``diff`` command to compare assessment runs
and detect regressions or improvements over time.

.. code-block:: bash

   flareinspect diff --baseline baseline.json --current latest.json

See :doc:`interpreting-drift` for guidance on reading the diff output.
