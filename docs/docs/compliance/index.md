# Compliance Mapping

FlareInspect maps security check results to four compliance frameworks,
enabling you to produce evidence-rich compliance reports from Cloudflare
assessments.

## Supported Frameworks

| Framework | Flag | Full Name |
|-----------|------|-----------|
| CIS | `--compliance cis` | Center for Internet Security |
| SOC 2 | `--compliance soc2` | System and Organization Controls 2 |
| PCI-DSS | `--compliance pci` | Payment Card Industry Data Security Standard |
| NIST CSF | `--compliance nist` | NIST Cybersecurity Framework |

## Usage

```bash
flareinspect assess --token $TOKEN --compliance cis
```

The compliance report is included in the assessment output under
`complianceReport`.

## How Scoring Works

Each compliance control is evaluated based on the mapped findings:

| Pass Rate | Status |
|-----------|--------|
| ≥ 80% | **Pass** |
| 50–79% | **Partial** |
| < 50% | **Fail** |

The **overall compliance score** is the percentage of controls that pass.

## Report Structure

The compliance report for each framework includes:

- `framework` — framework name
- `controls` — array of control objects with pass rates
- `overallScore` — percentage of passing controls
- `totalControls` — number of mapped controls
- `passedControls` — controls with ≥ 80% pass rate
- `partialControls` — controls with 50–79% pass rate
- `failedControls` — controls with < 50% pass rate

## Framework Pages

- [CIS Benchmark](cis.md)
- [SOC 2](soc2.md)
- [PCI-DSS](pci-dss.md)
- [NIST CSF](nist-csf.md)
