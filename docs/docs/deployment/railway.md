# Railway Deployment

FlareInspect ships with a `railway.json` configuration for one-click Railway deployment.

## One-Click Deploy

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/flareinspect)

1. Click the button above and sign in with GitHub.
2. Railway auto-detects Node.js and applies `railway.json` settings.
3. Add optional environment variables in the Railway dashboard.
4. Railway builds and starts the web dashboard automatically.

## Pricing

Includes a **$5 trial credit**. Ongoing usage is pay-as-you-go — typically $2–5/month for light use. See [railway.app/pricing](https://railway.app/pricing) for details.

## Configuration (`railway.json`)

```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "npm run web",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 3
  }
}
```

## Environment Variables

Set in the Railway dashboard under **Variables**:

| Variable | Description |
|----------|-------------|
| `CLOUDFLARE_TOKEN` | Cloudflare API token (optional — can be provided via UI) |
| `FLAREINSPECT_API_KEY` | API key to protect the dashboard |
| `NODE_ENV` | Set to `production` |
| `LOG_LEVEL` | `info` (default) |

## Persistent Storage

Railway supports persistent volumes. To mount one:

1. Go to your service in the Railway dashboard.
2. Open the **Volumes** tab and create a volume.
3. Mount it at `/app/web/data` to persist assessment history across deploys.

## Useful Commands

```bash
# Using the Railway CLI
railway login
railway up           # deploy from local source
railway logs         # stream logs
railway open         # open dashboard in browser
```

## Troubleshooting

- Build fails — ensure `package.json` is in the root and `npm run web` is the correct start command.
- Assessment data lost — add a persistent volume mounted at `/app/web/data`.
- `403` on Cloudflare API — verify token scopes.
