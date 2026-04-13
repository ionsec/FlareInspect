=============

Grading Scale

=============




FlareInspect assigns a letter grade based on the weighted overall score.


  =======  =============

   Grade    Score Range

  =======  =============

   A        ≥ 90

   B        ≥ 80

   C        ≥ 70

   D        ≥ 60

   F        < 60

  =======  =============


Category Breakdown


----


In addition to the overall grade, scores are broken down by service category

(e.g., account, dns, ssl, waf, zerotrust). Each category receives its own

score:



.. code-block::


    categoryScore = (passedWeight / totalWeight) × 100




Grade in CI Mode


----


Use ``--threshold`` to enforce a minimum score:



.. code-block:: bash


    flareinspect assess --token $TOKEN --ci --threshold 80

    # Exits with code 1 if score < 80 (grade < B)




Grade in Diff


----


The diff command shows grade changes between assessments:



.. code-block::


    Grade: C → B (+1)



Grade values: A=5, B=4, C=3, D=2, F=1. The delta is the difference.

