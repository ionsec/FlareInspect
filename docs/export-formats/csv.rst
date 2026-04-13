=================

CSV Export Format

=================




Flattens all findings into a CSV file with evidence columns for spreadsheet

analysis.



Usage


----


.. code-block:: bash


    flareinspect export -i assessment.json -f csv -o findings.csv




Columns


----


  ===================  ========================================

   Column               Description

  ===================  ========================================

   Check ID             FlareInspect check identifier

   Title                Check title

   Category             Assessment category

   Severity             critical/high/medium/low/informational

   Status               PASS/FAIL/WARNING

   Resource             Affected resource identifier

   Observed             Current observed value

   Expected             Expected compliant value

   Affected Entities    Named items affected

   Remediation          Remediation guidance

  ===================  ========================================


Use Cases


----


- Open in Excel or Google Sheets for filtering and sorting

- Import into data visualization tools

- Create custom dashboards and pivot tables

- Filter by severity, category, or status for targeted remediation

