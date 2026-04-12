# Web Dashboard Authentication

The FlareInspect web dashboard supports optional header-based API key
authentication for protecting API endpoints when exposed beyond localhost.

## Enabling API Key Auth

Set the `FLAREINSPECT_API_KEY` environment variable:

```bash
FLAREINSPECT_API_KEY=my-secret-key npm run web
```

When set, all `POST /api/assess`, `POST /api/diff`, and download endpoints
require the `X-API-Key` header.

## Making Authenticated Requests

```bash
curl -H "X-API-Key: my-secret-key" http://localhost:3000/api/assessment
```

## Security Details

- Key comparison uses **timing-safe equality** (`crypto.timingSafeEqual`) to
  prevent timing attacks
- Unauthorized requests receive HTTP 401 with an error message
- The API key is not logged or included in error responses

## Security Headers

The web dashboard sets the following security headers on all responses:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

Additionally, Helmet is enabled for standard middleware protections.

## Rate Limiting

The web dashboard applies rate limiting to API endpoints. When the limit is
exceeded, the server returns HTTP 429.

## Recommendations

- **Local development:** No API key needed (localhost-only access)
- **Team deployment:** Set `FLAREINSPECT_API_KEY` and bind to `0.0.0.0`
- **Production:** Place behind a reverse proxy with TLS termination
