# ASFF Export Format

Produces an AWS Security Finding Format (ASFF) document for ingestion into
AWS Security Hub or compatible SIEM systems.

## Usage

```bash
flareinspect export -i assessment.json -f asff -o findings.asff.json
```

## Structure

Each finding is mapped to the ASFF schema:

| ASFF Field | Source |
|------------|--------|
| `ProductArn` | FlareInspect product ARN |
| `Types` | `["Software and Configuration Checks/Cloudflare"]` |
| `Severity.Label` | FlareInspect severity |
| `Title` | Check title |
| `Description` | Finding description |
| `Resources` | Zone or account resource |
| `Remediation.Recommendation` | Remediation text |
| `Compliance.Status` | PASSED/FAILED/WARNING |

## Security Hub Integration

Import findings into Security Hub via the `BatchImportFindings` API or use
the ASFF output with event bridges for automated workflows.

## Note

FlareInspect is not an AWS product. The ASFF format is provided for
compatibility with Security Hub ingestion pipelines. The `ProductArn` uses
a custom vendor identifier.
