==================

Interpreting Drift

==================




A practical guide to reading and acting on FlareInspect diff results.



Sample Output


----


.. code-block::


    ═══════════════════════════════════════════════════

             FlareInspect Drift Detection Report

    ═══════════════════════════════════════════════════


    Score: 75 → 82 (+7)

    Grade: C → B (+1)

    Drift Score: +40


    Changes Summary:

      🆕 New findings:      2

      ✅ Resolved:          3

      🔴 Regressions:       1

      🟢 Improvements:      4

      →  Unchanged:         35




Key Metrics


----


.. rubric:: Score Delta



The difference between the current and baseline overall scores. A positive

delta means the security posture improved; negative means it regressed.



.. rubric:: Grade Delta



Grade values are numeric (A=5, B=4, C=3, D=2, F=1). A grade delta of +1 means

the grade improved by one level.



.. rubric:: Drift Score



The weighted net direction of change. Use this as a quick signal:

- **> 0** — posture is improving

- **< 0** — posture is regressing

- **0** — no meaningful change



Reading Regressions


----


Regressions (PASS → FAIL) are the most critical finding type. They indicate

that a security control that was previously compliant is now misconfigured.



.. code-block::


    🔴 REGRESSIONS (PASS → FAIL):

      • [HIGH] Minimum TLS Version (zone-abc123)



**Action:** Investigate immediately. Regressions cause the diff command to

exit with code 1.



Reading Improvements


----


Improvements (FAIL → PASS) confirm that remediation efforts were effective.



.. code-block::


    🟢 IMPROVEMENTS (FAIL → PASS):

      • [CRITICAL] MFA Enforcement (account-xyz789)




New and Resolved Findings


----


- **New findings** may appear when new zones are added to the account or when

  FlareInspect introduces new check categories

- **Resolved findings** disappear when the matching check+resource key is no

  longer present in the current assessment



Service-Level Deltas


----


The diff also includes score changes by service category:



.. code-block:: json


    {

      "dns": { "baseline": 2, "current": 1, "delta": -1 },

      "ssl": { "baseline": 3, "current": 1, "delta": -2 }

    }



This helps identify which areas improved or degraded.



Using in CI/CD


----


.. code-block:: bash


    # Fail the pipeline if any regression is detected

    flareinspect diff --baseline baseline.json --current latest.json


    # The exit code tells you:

    # 0 — safe to deploy

    # 1 — security regressed, block deployment


