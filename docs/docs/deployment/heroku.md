# Heroku Deployment

FlareInspect ships with an `app.json` manifest for one-click Heroku deployment.

## One-Click Deploy

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect)

1. Click the button above and log in to Heroku.
2. Configure optional environment variables (see below).
3. Click **Deploy app** — Heroku installs dependencies and starts the web dashboard automatically.

## Pricing

~$5/month on the Hobby dyno. The free tier was discontinued by Heroku in 2022.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CLOUDFLARE_TOKEN` | ❌ | Cloudflare API token (can be provided via the dashboard UI) |
| `FLAREINSPECT_API_KEY` | ❌ | Protects the dashboard with `X-API-Key` header (auto-generated on deploy) |
| `NODE_ENV` | ✅ | Set to `production` by `app.json` |
| `LOG_LEVEL` | ❌ | `info` (default), `debug`, or `error` |

After deployment you can update secrets with the Heroku CLI:

```bash
heroku config:set CLOUDFLARE_TOKEN=your_token --app your-app-name
heroku config:set FLAREINSPECT_API_KEY=$(openssl rand -hex 32) --app your-app-name
```

## Storage

Heroku dynos use **ephemeral storage** — assessment data in `web/data/assessments` is lost on every deploy or restart. Use a Heroku add-on (e.g., Heroku Postgres or an object-storage add-on) or external storage for persistent history.

## Useful Commands

```bash
# View live logs
heroku logs --tail --app your-app-name

# Restart the dyno
heroku restart --app your-app-name

# Open the dashboard in a browser
heroku open --app your-app-name
```

## Troubleshooting

- `H10 App crashed` — check logs; the most common cause is a missing or invalid `NODE_ENV`.
- Assessment data disappears — expected on ephemeral storage; see Storage section above.
- `403` on API calls — verify `CLOUDFLARE_TOKEN` has the required scopes.
