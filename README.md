# FlareInspect

<div align="center">
  <img src="flareinspect-logo.png" alt="FlareInspect Logo" width="200">
  <p>Cloudflare security assessment CLI and local web dashboard</p>
</div>

## Overview

FlareInspect assesses Cloudflare accounts and zones, highlights security gaps, compares posture drift between runs, and exports reports for engineers, security teams, and CI pipelines.

Version `1.1.0` adds:

- drift detection with `flareinspect diff`
- compliance reports for `cis`, `soc2`, `pci`, and `nist`
- contextual scoring and CI gate options
- new exporters: `sarif`, `markdown`, `csv`, `asff`
- shared config file support
- expanded web APIs and optional API key protection

## Key Features

- Cloudflare account and zone security assessments
- Drift detection between assessment runs with `flareinspect diff`
- Compliance mapping for `cis`, `soc2`, `pci`, and `nist`
- Contextual scoring and CI/CD gate support
- Export formats for `json`, `html`, `ocsf`, `sarif`, `markdown`, `csv`, and `asff`
- Local web dashboard with assessment history and downloads
- Shared config file support for team workflows
- Docker and Render deployment support

## Installation

### From source

```bash
git clone https://github.com/ionsec/flareinspect.git
cd flareinspect
npm install
```

### Docker

```bash
docker build -t flareinspect .
```

## Quick Start

```bash
# Run an assessment directly
flareinspect assess --token YOUR_TOKEN

# Export a saved assessment
flareinspect export -i flareinspect-20260412-120000.json -f html -o report.html

# Compare two runs
flareinspect diff --baseline old.json --current new.json -f markdown -o drift.md

# Start the web dashboard
npm run web
```

## Configuration

FlareInspect can load settings from:

- `.flareinspect.yml`
- `.flareinspect.yaml`
- `flareinspect.config.json`

Example:

```yaml
token: ${CLOUDFLARE_TOKEN}

output:
  format: json
  directory: ./output

assessment:
  concurrency: 4
  checks:
    - dns
    - ssl
    - waf
  excludeZones:
    - dev.example.com

compliance:
  framework: cis

scoring:
  sensitivity: high

ci:
  threshold: 80
  failOn: high
```

CLI flags override config file values.

## CLI Usage

### Assess

```bash
flareinspect assess --token YOUR_TOKEN
flareinspect assess --token YOUR_TOKEN --zones example.com,api.example.com
flareinspect assess --checks dns,ssl,waf --output report.json
flareinspect assess --compliance cis --sensitivity high
flareinspect assess --ci --threshold 80 --fail-on high
```

Supported `--checks` categories include:

- `account`
- `dns`
- `ssl`
- `waf`
- `zerotrust`
- `workers`
- `pages`
- `api`
- `bot`
- `logpush`
- `mtls`
- `securitytxt`
- `attack-surface`
- `dlp`
- `tunnels`
- `gateway`
- `page-shield`
- `cache`
- `snippets`
- `custom-hostnames`
- `ai-gateway`

### Export

```bash
flareinspect export -i assessment.json -f html -o report.html
flareinspect export -i assessment.json -f ocsf -o findings.ocsf.json
flareinspect export -i assessment.json -f sarif -o findings.sarif
flareinspect export -i assessment.json -f markdown -o report.md
flareinspect export -i assessment.json -f csv -o findings.csv
flareinspect export -i assessment.json -f asff -o findings.asff.json
```

### Diff

```bash
flareinspect diff --baseline previous.json --current current.json
flareinspect diff --baseline previous.json --current current.json -f markdown -o drift.md
```

## Web App

Start the dashboard:

```bash
npm run web
```

Optional environment variables:

- `HOST` default `127.0.0.1`
- `PORT` default auto-selected free port
- `FLAREINSPECT_API_KEY` to require `X-API-Key` on `/api/*`

Assessment data is stored in `web/data/assessments`.

API endpoints:

- `POST /api/assess`
- `GET /api/assessment`
- `GET /api/assessments`
- `GET /api/assessments/:id`
- `GET /api/compliance/:framework`
- `POST /api/diff`
- `GET /api/download/json`
- `GET /api/download/html`
- `GET /api/download/sarif`
- `GET /api/download/markdown`
- `GET /api/download/csv`
- `GET /api/download/asff`
- `GET /api/health`

## Output Formats

- `json`: native FlareInspect assessment output
- `html`: human-readable report
- `ocsf`: OCSF-oriented JSON document
- `sarif`: static analysis style findings for code scanning tools
- `markdown`: lightweight report for tickets and PRs
- `csv`: findings spreadsheet export
- `asff`: AWS Security Finding Format for Security Hub style ingestion

## Docker

Build and run the CLI:

```bash
docker build -t flareinspect .
docker run --rm -it flareinspect
docker run --rm -v $(pwd)/output:/app/output flareinspect \
  assess --token YOUR_TOKEN --output /app/output/assessment.json
```

Run the web app with Compose:

```bash
docker compose up flareinspect-web
```

The compose file exposes:

- `flareinspect` for CLI execution
- `flareinspect-web` for the dashboard
- `flareinspect-dev` for interactive development

## Cloudflare API Permissions

Minimum useful coverage:

- `Zone:Read`
- `DNS:Read`
- `SSL and Certificates:Read`
- `Firewall Services:Read`
- `Account Settings:Read`

Recommended for broader coverage:

- `Access/Zero Trust:Read`
- `Workers Scripts:Read`
- `Audit Logs:Read`
- `Security Center:Read`
- `Logpush:Read`
- `API Gateway:Read`

![Cloudflare API Token Permissions](permissions.png)

## Development

```bash
npm install
npm test
npm run lint
npm run dev
```

## Troubleshooting

- `403` usually means the token is missing product-specific scopes.
- `No matching zones found` means zone filters excluded everything.
- `Unknown check categories` means `--checks` included unsupported category names.
- `Unknown compliance framework` means the web or CLI request used a framework outside `cis`, `soc2`, `pci`, or `nist`.

## License

MIT. See `LICENSE`.
