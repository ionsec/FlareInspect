# Web Dashboard

FlareInspect includes a local web dashboard for running assessments, viewing
history, and downloading reports through a browser interface.

## Starting the Dashboard

```bash
npm run web
```

The server prints the URL on startup:

```
FlareInspect web app running on http://127.0.0.1:54321
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Bind address | `127.0.0.1` |
| `PORT` | Port number (`0` = auto-select) | `0` |
| `FLAREINSPECT_API_KEY` | Require API key on `/api/*` routes | — |

### Bind to All Interfaces

```bash
HOST=0.0.0.0 PORT=3000 npm run web
```

### Enable API Key Authentication

```bash
FLAREINSPECT_API_KEY=my-secret-key npm run web
```

See [Authentication](authentication.md) for details.

## Features

- **Assessment History** — view past assessment results
- **Inline Report Viewer** — render HTML reports in the browser at `/report`
- **Download Endpoints** — export in JSON, HTML, SARIF, Markdown, CSV, ASFF
- **Drift Comparison** — compare two assessments via the API
- **Compliance Reports** — view CIS, SOC 2, PCI, NIST compliance status

## Data Storage

Assessment data is stored in `web/data/assessments/`. Each assessment is saved
as a JSON file named by its UUID. The most recent assessment is also saved as
`latest.json`.

## Frontend

The frontend is a static HTML/CSS/JS application served from `web/public/`.
It communicates with the API endpoints to display assessment history, scores,
and report links.

## See Also

- [API Reference](api-reference.md) — full endpoint documentation
- [Authentication](authentication.md) — API key setup
