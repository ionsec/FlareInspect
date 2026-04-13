==================
Interpreting Drift
==================
==================

The drift score summarizes the net change in security posture between two assessment runs.

Drift Score
-----------

The drift score ranges from **-100** to **+100**:

========  ===================================
Range     Interpretation                     
========  ===================================
Positive  Net improvement in security posture
Zero      No net change                      
Negative  Net regression in security posture 
========  ===================================

The score accounts for both the count and severity weight of regressions and improvements.

Score Calculation
------------------

.. code-block:: text

   driftScore = ((improvementScore - regressionScore) / total) × 100

Where:

- ``improvementScore`` is the sum of severity weights for findings that changed from FAIL to PASS
- ``regressionScore`` is the sum of severity weights for findings that changed from PASS to FAIL
- ``total`` is the sum of all possible severity weights

Grade Changes
--------------

The diff output also shows grade changes between assessments:

.. code-block:: text

   Grade: C → B (+1)

Grade values: A=5, B=4, C=3, D=2, F=1. The delta is the difference between the two grade values.

Common Drift Scenarios
-----------------------

.. rubric:: New Deployment Introduces Regression

A new deployment disables WAF on a zone:

.. code-block:: text

   REGRESSION: CFL-WAF-001 (WAF Security Level) — PASS → FAIL
   Drift score: -7 (high severity weight)

.. rubric:: Security Hardening

A security team enables DNSSEC on previously unprotected zones:

.. code-block:: text

   IMPROVEMENT: CFL-DNS-001 (DNSSEC Enablement) — FAIL → PASS
   Drift score: +7 (high severity weight)

.. rubric:: New Check Coverage

A new check category is added between runs:

.. code-block:: text

   NEW: CFL-AIGW-001 (AI Gateway Configuration) — FAIL
   (This is not a regression — the check did not exist in the baseline)
