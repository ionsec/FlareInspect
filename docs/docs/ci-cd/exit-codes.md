# Exit Codes

FlareInspect uses exit codes to signal assessment and diff results in CI/CD
pipelines.

## Assess Command

| Code | Condition |
|------|-----------|
| 0 | Assessment completed and passed all CI gates |
| 1 | Assessment failed, threshold not met, or severity gate triggered |

### Threshold Gate

```bash
flareinspect assess --token $TOKEN --ci --threshold 80
```

Exits with code 1 if `overallScore < threshold`.

### Severity Gate

```bash
flareinspect assess --token $TOKEN --ci --fail-on high
```

Exits with code 1 if any finding with status `FAIL` has severity at or above
the specified level. Severity ordering:

| Level | Value |
|-------|-------|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |

`--fail-on high` catches critical (4) and high (3) findings.

### Combined Gates

```bash
flareinspect assess --token $TOKEN --ci --threshold 80 --fail-on high
```

Both conditions are checked. Either failing causes exit code 1.

## Diff Command

| Code | Condition |
|------|-----------|
| 0 | No regressions detected |
| 1 | At least one regression (PASS → FAIL) or score decreased |

## Error Exit Codes

| Code | Condition |
|------|-----------|
| 1 | General error (invalid token, API failure, file not found) |

## Using in Shell Scripts

```bash
if flareinspect assess --token $TOKEN --ci --threshold 80; then
  echo "Security assessment passed"
else
  echo "Security assessment failed"
  exit 1
fi
```
