# Drift Detection

FlareInspect compares two assessments to identify changes in security posture
between runs. This is useful for:

- **Security regression monitoring** — detect when a previously passing check
  now fails
- **Compliance tracking** — verify that remediation efforts are effective
- **CI/CD gates** — fail pipelines when security degrades

## Quick Start

```bash
# Run two assessments at different times
flareinspect assess --token $TOKEN --output baseline.json
# ... make changes ...
flareinspect assess --token $TOKEN --output current.json

# Compare
flareinspect diff --baseline baseline.json --current current.json
```

## How It Works

The diff engine matches findings between assessments using a composite key of
`checkId::resourceId`. Each matched finding is classified as one of five delta
types:

| Delta | Condition |
|-------|-----------|
| **NEW** | Exists in current but not in baseline |
| **RESOLVED** | Existed in baseline but not in current |
| **REGRESSION** | PASS → FAIL |
| **IMPROVEMENT** | FAIL → PASS |
| **UNCHANGED** | Same status in both |

## Drift Score

The drift score summarizes the overall direction of change:

```
driftScore = ((improvement - regression) / total) × 100
```

| Range | Meaning |
|-------|---------|
| +100 | All changes are improvements |
| +1 to +99 | Net improvement |
| 0 | No net change |
| -1 to -99 | Net regression |
| -100 | All changes are regressions |

## Score and Grade Deltas

The diff also reports changes in the overall security score and letter grade:

```
Score: 75 → 82 (+7)
Grade: C → B (+1)
```

## Exit Codes

| Code | Condition |
|------|-----------|
| 0 | No regressions |
| 1 | At least one regression or negative score delta |

## Output Formats

```bash
# JSON (default)
flareinspect diff --baseline old.json --current new.json -o drift.json

# Markdown
flareinspect diff --baseline old.json --current new.json -f markdown -o drift.md
```

## See Also

- [Interpreting Drift](interpreting-drift.md) — detailed walkthrough
- [CI/CD Integration](../ci-cd/exit-codes.md) — using diff in pipelines
