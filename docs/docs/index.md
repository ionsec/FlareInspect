# FlareInspect

> Cloudflare security assessment CLI and web dashboard

FlareInspect assesses Cloudflare accounts and zones, highlights security gaps, compares posture drift between runs, and exports evidence-rich reports for engineers, security teams, auditors, and CI pipelines.

## Features

| Feature | Description |
|---------|-------------|
| 🔍 Security Assessments | Comprehensive Cloudflare account and zone security checks — 40+ checks across 21 categories |
| 📊 Drift Detection | Compare assessments to find security posture regressions |
| 📋 Compliance Mapping | CIS, SOC 2, PCI-DSS, NIST CSF control mapping |
| 📄 Multi-Format Export | JSON, HTML, OCSF, SARIF, Markdown, CSV, ASFF |
| 🌐 Web Dashboard | Local web UI with assessment history and report downloads |
| 🚀 CI/CD Ready | Exit codes, threshold gates, and SARIF for pipeline integration |
| ☁️ Cloud Deployment | 1-click deployment to Render, Heroku, Railway, and Fly.io |
| 🔌 Plugin Support | Scaffold trusted local extensions for custom checks |

## Quick Install

```bash
git clone https://github.com/ionsec/flareinspect.git
cd flareinspect
npm install
```

## Quick Deploy

| Platform | Deploy |
|----------|--------|
| Render (recommended) | [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ionsec/flareinspect) |
| Heroku | [![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect) |
| Railway | [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/flareinspect) |

## Next Steps

- [Getting Started](getting-started.md) — Run your first assessment
- [CLI Reference](cli/assess.md) — All commands and options
- [Security Checks](checks/index.md) — Full check catalog
- [Deployment](deployment/docker.md) — Cloud and local deployment options
