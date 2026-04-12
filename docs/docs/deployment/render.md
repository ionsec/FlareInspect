# Render Deployment

FlareInspect includes a `render.yaml` blueprint for one-click deployment to
[Render](https://render.com).

## Blueprint

The Render blueprint deploys the web dashboard as a web service:

- **Type:** Web service
- **Environment:** Node.js
- **Plan:** Free
- **Build command:** `npm ci`
- **Start command:** `node web/server.js`
- **Port:** 3000

## Setup

1. Connect your GitHub repository to Render
2. Select the FlareInspect repo
3. Render detects `render.yaml` and configures the service

## Environment Variables

Set in the Render dashboard:

| Variable | Value |
|----------|-------|
| `NODE_ENV` | `production` |
| `HOST` | `0.0.0.0` |
| `PORT` | `3000` |
| `FLAREINSPECT_API_KEY` | Your chosen API key |

## Persistent Storage

Render's free tier uses ephemeral filesystem. Assessment data stored in
`web/data/assessments` will not persist across deploys. For production use,
consider using a persistent disk or external storage.
