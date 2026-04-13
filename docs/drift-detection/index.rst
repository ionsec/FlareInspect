===============
Drift Detection
===============

.. toctree::
   :maxdepth: 1
   :hidden:

   interpreting-drift

FlareInspect's drift detection compares two assessment runs to identify security posture changes over time. Use it to catch regressions before they become incidents.

Quick Start
-----------

.. code-block:: bash

   flareinspect diff --baseline old.json --current new.json

The ``diff`` command classifies every finding into one of five delta types:

===============  ===============================================================================
Delta            Meaning                                                                        
===============  ===============================================================================
``NEW``          Finding exists in the current assessment but not in the baseline               
``RESOLVED``     Finding existed in the baseline but no longer appears in the current assessment
``REGRESSION``   Finding was PASS in baseline but is FAIL in current                            
``IMPROVEMENT``  Finding was FAIL in baseline but is PASS in current                            
``UNCHANGED``    Finding has the same status in both assessments                                
===============  ===============================================================================

CI Integration
--------------

The ``diff`` command exits with code ``1`` when regressions are detected, making it suitable for CI pipelines:

.. code-block:: bash

   flareinspect diff --baseline baseline.json --current latest.json
   # Exit code 1 → regressions detected, pipeline should fail

Export drift reports as Markdown or JSON for archival:

.. code-block:: bash

   flareinspect diff --baseline baseline.json --current latest.json -f markdown -o drift.md
