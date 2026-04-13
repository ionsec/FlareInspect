==================

Contextual Scoring

==================




FlareInspect uses a CVSS-inspired contextual scoring model that adjusts finding

severity based on zone plan, exposure, and data sensitivity.



Formula


----


.. code-block::


    Final Score = Base Score × Exploitability × Plan Multiplier × Exposure Multiplier × Sensitivity Multiplier



Scores are capped at **10.0**.



Base Scores


----


  ===============  ============

   Severity         Base Score

  ===============  ============

   Critical         9.0

   High             7.5

   Medium           5.0

   Low              3.0

   Informational    1.0

  ===============  ============


Plan Multipliers


----


  =================  ============  ============================================

   Plan               Multiplier    Rationale

  =================  ============  ============================================

   Free               1.3           Missing features are riskier on free plans

   Pro                1.1           —

   Business           1.0           Baseline

   Enterprise         0.9           More built-in protections

   Enterprise Plus    0.85          Most comprehensive protection

  =================  ============  ============================================


Exposure Multipliers


----


  =============  ============

   Exposure       Multiplier

  =============  ============

   Public         1.3

   Internal       0.8

   Staging        0.6

   Development    0.5

  =============  ============

Exposure is inferred from the zone name and finding service:

- Account/Zero Trust findings → ``internal``

- Zones containing ``staging``, ``dev``, ``test`` → ``staging``

- DNS/SSL/WAF findings → ``public``

- Everything else → ``public``



Sensitivity Multipliers


----


  =============  ============  =================================

   Sensitivity    Multiplier    Use Case

  =============  ============  =================================

   Critical       1.5           PII, financial data, healthcare

   High           1.3           Business-sensitive data

   Medium         1.0           Standard business data

   Low            0.8           Public information

  =============  ============  =================================

Set with ``--sensitivity``:



.. code-block:: bash


    flareinspect assess --token $TOKEN --sensitivity critical




Exploitability Factors


----


  =====================  ============

   Factor                 Multiplier

  =====================  ============

   Exposed credentials    1.5

   Origin IP exposed      1.4

   Missing WAF            1.3

   Weak SSL               1.3

   No MFA                 1.2

   Missing headers        1.1

   No DNSSEC              1.1

   Default                1.0

  =====================  ============


Usage


----


.. code-block:: bash


    flareinspect assess --token $TOKEN --sensitivity high



The contextual scores are added to each finding under ``contextualScore`` and

summarized in ``contextualSummary``.

