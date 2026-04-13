============

diff Command

============




Compare two assessments to detect security posture drift. This is useful for tracking whether your Cloudflare configuration has improved, regressed, or stayed the same between runs.



Usage


----


.. code-block:: bash


    flareinspect diff --baseline <file> --current <file> [options]




Options


----


=========================  ==============================================  =========

   Option                     Description                                     Default

=========================  ==============================================  =========

   ``--baseline <file>``        Baseline assessment file (JSON) *(required)*    —

   ``--current <file>``         Current assessment file (JSON) *(required)*     —

   ``-o, --output <file>``      Output file path for diff results               Stdout

   ``-f, --format <format>``    Output format: ``json``, ``markdown``               ``json``

=========================  ==============================================  =========


Delta Types


----


Each finding in the diff is classified by one of the following delta types:


===============  =================================================================================

   Delta            Meaning

===============  =================================================================================

   ``NEW``            Finding exists in the current assessment but not in the baseline

   ``RESOLVED``       Finding existed in the baseline but no longer appears in the current assessment

   ``REGRESSION``     Finding was PASS in baseline but is FAIL in current

   ``IMPROVEMENT``    Finding was FAIL in baseline but is PASS in current

   ``UNCHANGED``      Finding has the same status in both assessments

===============  =================================================================================


Drift Score


----


The drift score is a number from **-100** to **+100**:


==========  =====================================

   Range       Interpretation

==========  =====================================

   Positive    Net improvement in security posture

   Zero        No net change

   Negative    Net regression in security posture

==========  =====================================

The score accounts for both the count and severity weight of regressions and improvements.



Exit Codes


----


=======================================  ===========

   Condition                                Exit Code

=======================================  ===========

   No regressions detected                  ``0``

   One or more regressions detected         ``1``

   Error (invalid input, file not found)    ``1``

=======================================  ===========

This makes ``diff`` suitable for CI pipelines where you want to block merges that introduce security regressions.



Examples


----


.. rubric:: Basic Diff




.. code-block:: bash


    flareinspect diff --baseline baseline.json --current latest.json




.. rubric:: Export Diff as Markdown




.. code-block:: bash


    flareinspect diff --baseline baseline.json --current latest.json \

      -f markdown -o drift-report.md




.. rubric:: Use in CI Pipeline




.. code-block:: bash


    # Previous assessment stored as baseline

    # Latest assessment generated in this pipeline run

    flareinspect diff --baseline baseline.json --current latest.json


    # Exit code 1 if regressions are found

    if [ $? -ne 0 ]; then

      echo "Security regressions detected!"

      exit 1

    fi


