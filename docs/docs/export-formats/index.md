# Export Formats

FlareInspect supports seven export formats for different use cases.

| Format | Flag | Best For |
|--------|------|----------|
| JSON | `json` | Programmatic access, re-import, full fidelity |
| HTML | `html` | Human review, management reporting, interactive charts |
| OCSF | `ocsf` | SIEM ingestion, OCSF-compliant pipelines |
| SARIF | `sarif` | GitHub Code Scanning, static analysis tools |
| Markdown | `markdown` | Tickets, PRs, audit notes, wikis |
| CSV | `csv` | Spreadsheet analysis, filtered evidence review |
| ASFF | `asff` | AWS Security Hub, Security Finding Format pipelines |

## Quick Reference

```bash
# Export to any format
flareinspect export -i assessment.json -f <format> -o <output>

# Examples
flareinspect export -i assessment.json -f html -o report.html
flareinspect export -i assessment.json -f sarif -o findings.sarif
flareinspect export -i assessment.json -f csv -o findings.csv
```

## Format Details

- **JSON** preserves the complete assessment including findings, report model,
  and configuration snapshot
- **HTML** generates a standalone interactive report with score visualization,
  findings tables, and analysis sections
- **OCSF** maps findings to the Open Cybersecurity Schema Framework class 2001
- **SARIF** produces a Static Analysis Results Interchange Format compatible
  with GitHub code scanning
- **Markdown** creates a lightweight report suitable for pasting into issues,
  PRs, or wikis
- **CSV** flattens all findings into rows with evidence columns for spreadsheet
  filtering
- **ASFF** produces AWS Security Finding Format documents for Security Hub
