FROM node:22-alpine3.22 AS deps

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:22-alpine3.22

RUN apk add --no-cache dumb-init && \
    addgroup -S flareinspect && \
    adduser -S flareinspect -G flareinspect

WORKDIR /app

ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV NPM_CONFIG_FUND=false

COPY --from=deps --chown=flareinspect:flareinspect /app/node_modules ./node_modules
COPY --chown=flareinspect:flareinspect . .

RUN mkdir -p /app/output /app/logs /app/web/data/assessments && \
    chmod 755 src/cli/index.js src/cli/interactive.js src/cli/welcome.js

USER flareinspect

LABEL org.opencontainers.image.title="FlareInspect" \
      org.opencontainers.image.description="Cloudflare Security Assessment CLI and web dashboard" \
      org.opencontainers.image.vendor="IONSEC.IO" \
      org.opencontainers.image.version="1.2.1" \
      org.opencontainers.image.source="https://github.com/ionsec/flareinspect" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/bin/dumb-init", "--", "node", "src/cli/index.js"]
CMD []

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node src/cli/index.js --version > /dev/null || exit 1
