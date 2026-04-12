# export Command

Export a saved assessment to a different file format. This is useful for generating human-readable reports, integrating with security tools, or uploading to compliance platforms.

## Usage

```bash
flareinspect export [options]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --input <file>` | Input assessment file (JSON) *(required)* | — |
| `-o, --output <file>` | Output file path *(required)* | — |
| `-f, --format <format>` | Export format: `json`, `html`, `ocsf`, `sarif`, `markdown`, `csv`, `asff` | `json` |

## Formats

| Format | Use Case |
|--------|----------|
| `json` | Machine-readable, re-importable full results |
| `html` | Shareable interactive report for browsers |
| `ocsf` | OCSF (Open Cybersecurity Schema Framework) normalized JSON |
| `sarif` | Static Analysis Results Interchange Format for GitHub Advanced Security |
| `markdown` | Text-based report for wikis and documentation |
| `csv` | Tabular findings for spreadsheet analysis |
| `asff` | AWS Security Finding Format for Security Hub integration |

## Examples

### Export to HTML

```bash
flareinspect export -i assessment.json -f html -o report.html
```

### Export to SARIF for GitHub Advanced Security

```bash
flareinspect export -i assessment.json -f sarif -o results.sarif
```

### Export to CSV for Spreadsheet Analysis

```bash
flareinspect export -i assessment.json -f csv -o findings.csv
```

### Export to OCSF

```bash
flareinspect export -i assessment.json -f ocsf -o assessment-ocsf.json
```

### Export to ASFF (AWS Security Finding Format)

```bash
flareinspect export -i assessment.json -f asff -o findings-asff.json
```

### Export to Markdown

```bash
flareinspect export -i assessment.json -f markdown -o report.md
```
