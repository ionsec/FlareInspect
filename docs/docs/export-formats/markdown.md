# Markdown Export Format

Generates a lightweight Markdown report suitable for tickets, pull requests,
and audit notes.

## Usage

```bash
flareinspect export -i assessment.json -f markdown -o report.md
```

## Contents

The Markdown report includes:

- Executive summary with score and grade
- Risk distribution table
- Findings by category
- Evidence for each failed check (observed vs expected)
- Remediation guidance
- Compliance status summary

## Use Cases

- Paste into GitHub issues or PR descriptions
- Add to wiki or Confluence pages
- Include in audit evidence packages
- Email to stakeholders as plain text

## Diff as Markdown

The `diff` command also supports Markdown output:

```bash
flareinspect diff --baseline old.json --current new.json -f markdown -o drift.md
```
