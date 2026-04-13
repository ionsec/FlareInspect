# Deployment Overview

FlareInspect can be deployed in several ways depending on your needs.

## Cloud (1-Click)

The quickest way to run the web dashboard on the internet is via a 1-click cloud platform:

| Platform | Button | Notes |
|----------|--------|-------|
| **Render** (recommended) | [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ionsec/flareinspect) | Free tier · 1 GB persistent storage |
| **Heroku** | [![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect) | ~$5/month Hobby dyno |
| **Railway** | [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/flareinspect) | $5 trial credit · pay-as-you-go |
| **Fly.io** | See [Fly.io guide](flyio.md) | Free allowance · edge regions |

## Local / Self-Hosted

| Option | Guide |
|--------|-------|
| Docker / Compose | [Docker](docker.md) |
| PM2 / systemd | [Standalone](standalone.md) |

## Environment Variables

All deployment options share the same environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `CLOUDFLARE_TOKEN` | ❌ | Cloudflare API token (can be provided via the dashboard UI) |
| `FLAREINSPECT_API_KEY` | ❌ | Protects the web dashboard with `X-API-Key` header auth |
| `NODE_ENV` | ❌ | `production` (recommended for cloud deploys) |
| `LOG_LEVEL` | ❌ | `info` (default), `debug`, or `error` |
| `HOST` | ❌ | Bind address — default `0.0.0.0` for cloud, `127.0.0.1` for local |
| `PORT` | ❌ | Port number — default `3000` |

## Choosing a Platform

- **Render** — easiest setup with a free tier and 1 GB persistent disk for assessment history.
- **Heroku** — familiar PaaS with one-click deploy but ephemeral storage (data lost on restart).
- **Railway** — simple pay-as-you-go with good persistent volume support.
- **Fly.io** — best for global edge deployment; requires the Fly CLI.
- **Docker** — best for on-premise or containerized environments.
- **Standalone** — best for long-running VMs where you manage the process yourself.
