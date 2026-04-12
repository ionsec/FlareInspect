# FlareInspect

> Cloudflare security assessment CLI and local web dashboard

FlareInspect assesses Cloudflare accounts and zones, highlights security gaps, compares posture drift between runs, and exports evidence-rich reports for engineers, security teams, auditors, and CI pipelines.

## Features

| Feature | Description |
|---------|-------------|
| 🔍 Security Assessments | Comprehensive Cloudflare account and zone security checks |
| 📊 Drift Detection | Compare assessments to find security posture regressions |
| 📋 Compliance Mapping | CIS, SOC 2, PCI-DSS, NIST CSF control mapping |
| 📄 Multi-Format Export | JSON, HTML, OCSF, SARIF, Markdown, CSV, ASFF |
| 🌐 Web Dashboard | Local web UI with assessment history and report downloads |
| 🚀 CI/CD Ready | Exit codes, threshold gates, and SARIF for pipeline integration |

## Quick Install

```bash
git clone https://github.com/ionsec/flareinspect.git
cd flareinspect
npm install
```

## Next Steps

- [Getting Started](getting-started.md) — Run your first assessment
- [CLI Reference](cli/assess.md) — All commands and options
- [Security Checks](checks/index.md) — Full check catalog
