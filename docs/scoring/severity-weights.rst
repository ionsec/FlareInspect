================

Severity Weights

================




FlareInspect assigns weighted values to each severity level for score

calculation and drift detection.



Weight Table


----


  ===============  ========  ==================================

   Severity         Weight    Used For

  ===============  ========  ==================================

   Critical         10        Score calculation, drift scoring

   High             7         Score calculation, drift scoring

   Medium           4         Score calculation, drift scoring

   Low              2         Score calculation, drift scoring

   Informational    1         Score calculation, drift scoring

  ===============  ========  ==================================


How Weights Are Used


----


.. rubric:: Overall Score



For each finding:

- If ``status === PASS``, the weight contributes to the passed total

- If ``status === FAIL``, the weight contributes only to the possible total



.. code-block::


    overallScore = (passedWeight / totalWeight) × 100




.. rubric:: Drift Score



In the diff engine:

- Each **improvement** (FAIL → PASS) adds its weight to the improvement score

- Each **regression** (PASS → FAIL) adds its weight to the regression score



.. code-block::


    driftScore = ((improvementScore - regressionScore) / total) × 100



Range: -100 (all regressions) to +100 (all improvements).

