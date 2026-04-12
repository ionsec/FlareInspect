# Contributing

## Scope

FlareInspect accepts contributions for the CLI, report generation, exporters, web dashboard, documentation, tests, and deployment assets.

## Before You Start

- open or review an issue before making large behavior changes
- keep PRs focused on one concern when possible
- do not commit Cloudflare tokens, customer data, assessment outputs, or private logs
- treat plugins as trusted local code, not a sandbox boundary

## Local Setup

```bash
git clone https://github.com/ionsec/flareinspect.git
cd flareinspect
npm install
```

Useful commands:

```bash
npm test -- --runInBand
npm run lint
npm run web
```

## Development Expectations

- preserve current CLI behavior unless the change intentionally updates it
- update documentation when user-facing behavior changes
- add or adjust tests for report/export/security changes
- prefer deterministic behavior in Docker and local installs
- keep security-sensitive handling conservative: no secret logging, no token leakage, no path traversal shortcuts

## Pull Requests

Please include:

- a concise summary of the change
- why the change is needed
- any user-facing behavior differences
- verification performed locally

Good PR examples:

- add evidence fields to a finding type and update exporters plus tests
- tighten API validation and add route coverage
- add a new assessment category with docs and fixtures

Less useful PRs:

- large mixed refactors with no behavior summary
- documentation changes that describe features the code does not support
- dependency churn without a security, compatibility, or maintenance reason

## Coding Notes

- assessment logic lives under `src/core/services/`
- exporters live under `src/exporters/`
- the HTML report template is `templates/report.html`
- the local dashboard lives under `web/`
- tests live under `tests/`

## Reporting Security Issues

Do not open a public issue for a live secret exposure or a sensitive vulnerability involving customer data. Report those privately to the project maintainers through the contact path used by the repository owners.
