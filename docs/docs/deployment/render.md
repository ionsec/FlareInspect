# Render Deployment

FlareInspect includes a `render.yaml` blueprint for one-click deployment to
[Render](https://render.com).

## One-Click Deploy

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ionsec/flareinspect)

1. Click the button above and connect your GitHub account.
2. Render detects `render.yaml` and pre-configures the service.
3. Click **Apply** — deployment takes ~3 minutes.

## Blueprint

The `render.yaml` blueprint deploys the web dashboard as a web service:

| Setting | Value |
|---------|-------|
| Type | Web service |
| Environment | Node.js |
| Plan | Free |
| Build command | `npm ci` |
| Start command | `node web/server.js` |
| Port | 3000 |
| Persistent disk | 1 GB mounted at `/app/web/data` |

## Environment Variables

Set in the Render dashboard under **Environment**:

| Variable | Value |
|----------|-------|
| `NODE_ENV` | `production` |
| `HOST` | `0.0.0.0` |
| `PORT` | `3000` |
| `CLOUDFLARE_TOKEN` | Your Cloudflare API token (optional — can be provided via UI) |
| `FLAREINSPECT_API_KEY` | A random secret to protect the dashboard |

Generate an API key:

```bash
openssl rand -hex 32
```

## Persistent Storage

The blueprint mounts a **1 GB persistent disk** at `/app/web/data`, so assessment history survives deploys and restarts. You can increase the disk size in the Render dashboard if needed.

## Troubleshooting

- Service fails to start — check the Render logs; common causes are a missing `package-lock.json` or Node version mismatch.
- `403` on Cloudflare API — verify the token has the required scopes.
- Dashboard is slow — the free tier spins down after inactivity; the first request after idle may take 30–60 seconds.
