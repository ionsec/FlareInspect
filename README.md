# FlareInspect

<div align="center">
  <img src="flareinspect-logo.png" alt="FlareInspect Logo" width="200">
  <p>Cloudflare security assessment CLI + web dashboard</p>
</div>

## Overview

FlareInspect assesses Cloudflare accounts and zones, highlights security gaps, and exports reports in JSON, HTML, or OCSF. It includes a local web dashboard that runs assessments and manages report downloads.

## Key features

- Account and zone security checks
- DNS, SSL/TLS, WAF, bot management, rate limiting
- Zero Trust, Access, mTLS, Turnstile
- API Gateway (API Shield) discovery and schema validation checks
- Security Center insights, security.txt checks, and Attack Surface checks
- Logpush coverage checks for security datasets
- HTML, JSON, and OCSF exports
- Local web dashboard with history and downloads
- Docker and one-click deploy support

## Installation

### NPM

```bash
npm install -g flareinspect
```

### Docker

```bash
docker pull ionsec/flareinspect:latest
```

### From source

```bash
git clone https://github.com/ionsec/flareinspect.git
cd flareinspect
npm install
```

## Quick start

```bash
# Run assessment
flareinspect assess --token YOUR_TOKEN

# Export HTML report
flareinspect export -i assessment.json -o report.html -f html

# Run web app
npm run web
```

## Web app

```bash
npm run web
```

Notes:
- Auto-selects a free port if `PORT` is not set
- Stores results locally in `web/data/assessments`

Endpoints:
- `GET /api/assessment` (latest)
- `GET /api/assessments` (history)
- `GET /api/assessments/:id`
- `GET /api/health`
- `GET /api/download/json`
- `GET /api/download/html`

## One-click deploy

- Heroku: https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect
- Render: https://render.com/deploy?repo=https://github.com/ionsec/flareinspect

## Docker usage

```bash
# Build locally
docker build -t flareinspect .

# Interactive CLI
docker run -it --rm flareinspect

# Run assessment and save output
docker run --rm -v $(pwd):/app/output flareinspect \
  assess --token YOUR_TOKEN --output /app/output/assessment.json

# Web app via docker-compose
docker-compose up flareinspect-web
```

## Cloudflare API token permissions

Minimum:
- Zone:Read
- DNS:Read
- SSL and Certificates:Read
- Firewall Services:Read
- Account Settings:Read

Recommended for full coverage:
- Access/Zero Trust:Read
- Workers Scripts:Read
- Audit Logs:Read
- Security Center:Read
- Logpush:Read
- API Gateway:Read

![Cloudflare API Token Permissions](permissions.png)

## Usage

### CLI

```bash
flareinspect assess --token YOUR_TOKEN
flareinspect assess --token YOUR_TOKEN --output assessment.json
flareinspect assess --token YOUR_TOKEN --output report.html --format html
```

### Export

```bash
flareinspect export -i assessment.json -o report.html -f html
flareinspect export -i assessment.json -o ocsf.json -f ocsf
```

## Output formats

- JSON: full assessment data
- HTML: executive report + charts
- OCSF: SIEM-ready findings

## Assessment coverage

Account:
- MFA enforcement and admin access
- Audit log visibility
- Zero Trust configuration (IdP, policies, device rules, DLP, gateway)
- Workers and Pages inventory checks
- Turnstile widgets
- DNS Firewall policies
- Logpush jobs (security datasets)
- Access and mTLS certificates
- Security Center insights
- Attack Surface issues

Zone:
- DNSSEC, CAA, wildcard records, proxy status
- SSL mode, minimum TLS, HSTS, Always Use HTTPS
- WAF security level, firewall rules, rate limiting rulesets
- Bot management
- API Shield and API Gateway checks
- Security Center insights and security.txt
- Load balancer checks
- Email routing checks

## Troubleshooting

- 403 errors: token lacks required permissions
- No zones: token scope too narrow or no zones available
- Security Insights missing: requires Security Center and permission
- Web report styling: ensure CSP allows inline styles and chart CDN

## Development

```bash
npm install
npm test
npm run dev
```

## License

MIT. See `LICENSE`.
