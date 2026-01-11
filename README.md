# FlareInspect

<div align="center">
  <img src="flareinspect-logo.png" alt="FlareInspect Logo" width="200">
  <p>Cloudflare security assessment CLI + web dashboard</p>
</div>

## What it does

FlareInspect audits Cloudflare accounts and zones, highlights risks, and exports reports (JSON, HTML, OCSF). It also ships with a local web dashboard for running assessments and downloading reports.

## Quick start

```bash
# Install deps
npm install

# Run CLI assessment
node src/cli/index.js assess --token YOUR_TOKEN

# Run web app
npm run web
```

## Web app

- Local dashboard: `npm run web`
- Auto-picks a free port if `PORT` is not set
- Stores results in `web/data/assessments`

Endpoints:
- `GET /api/assessment` (latest)
- `GET /api/assessments` (history)
- `GET /api/assessments/:id`
- `GET /api/health`
- `GET /api/download/json`
- `GET /api/download/html`

## Docker

```bash
# Build
docker build -t flareinspect .

# Interactive CLI
docker run -it --rm flareinspect

# Run assessment and save output
docker run --rm -v $(pwd):/app/output flareinspect \
  assess --token YOUR_TOKEN --output /app/output/assessment.json

# Web app
docker-compose up flareinspect-web
```

## One-click deploy

- Heroku: https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect
- Render: https://render.com/deploy?repo=https://github.com/ionsec/flareinspect

## Features

- Account + zone security checks
- DNS, SSL/TLS, WAF, bot management, rate limits
- Zero Trust, Access, mTLS, Turnstile
- API Gateway (API Shield) discovery + schemas
- Security Center insights and security.txt checks
- Logpush and Attack Surface checks
- HTML + JSON + OCSF exports
- Local storage + history in the web app

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

## Output formats

- JSON: full assessment data
- HTML: executive report + charts
- OCSF: SIEM-ready findings

## Troubleshooting

- 403 errors: check token scope and account access
- No zones: token may be scoped too narrowly
- Security Insights missing: requires Security Center + permission

## Development

```bash
npm install
npm test
npm run dev
```

## License

MIT. See `LICENSE`.
