# FlareInspect Deployment Guide

Deploy FlareInspect to cloud platforms with 1-click buttons or minimal configuration.

## Quick Deploy Options

### Render (Recommended - Free Tier)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ionsec/flareinspect)

**Free tier includes:**
- 512MB RAM
- Shared CPU
- 1GB persistent storage for assessment history
- Automatic HTTPS

**Steps:**
1. Click the Deploy button above
2. Connect your GitHub account
3. Environment variables are pre-configured
4. Click "Apply" - deployment takes ~3 minutes

### Heroku

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/ionsec/flareinspect)

**Pricing:** ~$5/month (Hobby dyno)

**Steps:**
1. Click the Deploy button above
2. Log in to Heroku
3. Configure environment variables (optional)
4. Click "Deploy app"

**After deployment:**
```bash
# Set your Cloudflare token (optional)
heroku config:set CLOUDFLARE_TOKEN=your_token

# Set API key for protection
heroku config:set FLAREINSPECT_API_KEY=$(openssl rand -hex 32)

# View logs
heroku logs --tail
```

### Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/flareinspect?referralCode=flareinspect)

**Free tier includes:**
- $5 trial credit
- Pay-as-you-go pricing (~$2-5/month for light usage)

**Steps:**
1. Click the Deploy button
2. Sign in with GitHub
3. Railway auto-detects Node.js
4. Add environment variables in Railway dashboard

### Fly.io

**Prerequisites:** Install [Fly CLI](https://fly.io/docs/hands-on/install-flyctl/)

**Deploy commands:**
```bash
# Clone and deploy
git clone https://github.com/ionsec/flareinspect.git
cd flareinspect
fly launch --no-deploy
fly deploy

# Set environment variables
fly secrets set CLOUDFLARE_TOKEN=your_token
fly secrets set FLAREINSPECT_API_KEY=$(openssl rand -hex 32)

# Open the app
fly open
```

**Free allowance:** 3 shared-cpu-1x VMs (256MB each)

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CLOUDFLARE_TOKEN` | ❌ | Cloudflare API token (can provide via UI) |
| `FLAREINSPECT_API_KEY` | ❌ | Protect dashboard with X-API-Key header |
| `NODE_ENV` | ❌ | Set to `production` (default) |
| `LOG_LEVEL` | ❌ | Logging level: `info`, `debug`, `error` (default: `info`) |
| `HOST` | ❌ | Bind address (default: `0.0.0.0`) |
| `PORT` | ❌ | Port number (default: `3000`) |

---

## Post-Deployment

### Access the Dashboard
```
http://localhost:3000 (local)
https://your-app.onrender.com (Render)
https://your-app.herokuapp.com (Heroku)
https://your-app.railway.app (Railway)
https://your-app.fly.dev (Fly.io)
```

### Generate API Key
```bash
# Using OpenSSL
openssl rand -hex 32

# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Using the Dashboard

1. **Run Assessment:**
   - Enter Cloudflare API token (or use pre-configured)
   - Select zones to assess (optional)
   - Click "Run Assessment"

2. **View Results:**
   - Security score and findings
   - Compliance mapping (CIS, SOC2, PCI, NIST)
   - Affected identities and resources

3. **Export Reports:**
   - HTML, Markdown, CSV, SARIF, OCSF, ASFF
   - Download or share with team

---

## Troubleshooting

### App won't start
```bash
# Check logs (Render)
render logs -f

# Check logs (Heroku)
heroku logs --tail

# Check logs (Fly.io)
fly logs
```

### Assessment fails
- Verify Cloudflare API token has correct permissions
- Check token hasn't expired
- Ensure zones exist and are accessible

### Storage issues
- Render: Data persists in 1GB disk
- Heroku: Ephemeral storage (use add-on for persistence)
- Railway: Persistent volume included
- Fly.io: Use `fly volumes create` for persistence

---

## Security Considerations

### Multi-tenant SaaS
For production SaaS deployments:
- Enable `FLAREINSPECT_API_KEY` for access control
- Consider adding user authentication
- Use HTTPS (enabled by default on all platforms)
- Rotate API keys regularly

### Rate Limiting
- Cloudflare API has rate limits (1200 requests/5 minutes)
- Assessments may take 2-5 minutes for large accounts
- Consider caching results for repeated requests

### Data Privacy
- Assessment data stored on platform filesystem
- Consider encryption at rest for sensitive deployments
- Implement data retention policies

---

## Custom Deployment

### Docker
```bash
docker build -t flareinspect .
docker run -p 3000:3000 -e CLOUDFLARE_TOKEN=your_token flareinspect
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: flareinspect
spec:
  replicas: 1
  selector:
    matchLabels:
      app: flareinspect
  template:
    metadata:
      labels:
        app: flareinspect
    spec:
      containers:
      - name: flareinspect
        image: flareinspect:latest
        ports:
        - containerPort: 3000
        env:
        - name: CLOUDFLARE_TOKEN
          valueFrom:
            secretKeyRef:
              name: flareinspect-secrets
              key: cloudflare-token
```

---

## Support

- Documentation: https://flareinspect.readthedocs.io
- GitHub Issues: https://github.com/ionsec/flareinspect/issues
- License: MIT
