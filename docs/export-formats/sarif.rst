===================

SARIF Export Format

===================




Produces a Static Analysis Results Interchange Format (SARIF) document

compatible with GitHub Code Scanning and other security tooling.



Usage


----


.. code-block:: bash


    flareinspect export -i assessment.json -f sarif -o findings.sarif




GitHub Code Scanning


----


Upload SARIF results to GitHub:



.. code-block:: bash


    gh code-scanning upload-sarif findings.sarif



Or use the ``github/codeql-action/upload-sarif`` action in CI pipelines.



Structure


----


The SARIF document follows the SARIF v2.1.0 specification:


- **``$schema``** — SARIF schema URI

- **version** — ``2.1.0```

- **runs[0].tool** — FlareInspect tool metadata

- **runs[0].results** — Array of findings mapped to SARIF results

  -`` ruleId`` — FlareInspect check ID (e.g., ``CFL-SSL-001``)

  - ``level`` — ``error`` for FAIL, ``none`` for PASS

  - ``message.text`` — Finding description

  -`` locations[0]``` — Zone or account resource

