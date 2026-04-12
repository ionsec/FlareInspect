# Contributing

FlareInspect accepts contributions for the CLI, report generation, exporters,
web dashboard, documentation, tests, and deployment assets.

## Before You Start

- Open or review an issue before making large behavior changes
- Keep PRs focused on one concern when possible
- Do not commit Cloudflare tokens, customer data, assessment outputs, or
  private logs
- Treat plugins as trusted local code, not a sandbox boundary

## Local Setup

```bash
git clone https://github.com/ionsec/flareinspect.git
cd flareinspect
npm install
```

## Development Commands

```bash
# Run tests
npm test -- --runInBand

# Lint
npm run lint

# Start web dashboard (with auto-reload)
npm run dev

# Run CLI
node src/cli/index.js assess --token $TOKEN
```

## Development Expectations

- Preserve current CLI behavior unless the change intentionally updates it
- Update documentation when user-facing behavior changes
- Add or adjust tests for report/export/security changes
- Prefer deterministic behavior in Docker and local installs
- Keep security-sensitive handling conservative: no secret logging, no token
  leakage, no path traversal shortcuts

## Pull Requests

Please include:

- A concise summary of the change
- Why the change is needed
- Any user-facing behavior differences
- Verification performed locally

## Coding Notes

- Assessment logic lives under `src/core/services/`
- Exporters live under `src/exporters/`
- The HTML report template is `templates/report.html`
- The local dashboard lives under `web/`
- Tests live under `tests/`

## Reporting Security Issues

Do not open a public issue for a live secret exposure or a sensitive
vulnerability involving customer data. Report those privately to the project
maintainers.
