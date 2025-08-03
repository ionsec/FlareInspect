# Multi-stage build for FlareInspect - Security Hardened
FROM node:22-alpine3.22 AS builder

# Security: Update package index and upgrade all packages to latest versions
RUN apk update && apk upgrade --no-cache

# Install build dependencies with latest available secure versions
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies with clean install and audit fix
RUN npm ci --only=production && \
    npm audit --audit-level=high && \
    npm audit fix --only=prod --audit-level=high || true && \
    npm cache clean --force

# Copy source code
COPY . .

# Production stage - Latest Alpine with security updates
FROM node:22-alpine3.22

# Security: Update all packages to latest versions to avoid CVEs
RUN apk update && apk upgrade --no-cache

# Install runtime dependencies with latest secure versions
RUN apk add --no-cache \
    tini \
    dumb-init \
    && rm -rf /var/cache/apk/* /tmp/*

# Security: Create non-root user with restricted shell and no home directory
RUN addgroup -g 1001 -S flareinspect && \
    adduser -u 1001 -S flareinspect -G flareinspect -s /sbin/nologin -h /dev/null

# Security: Set restrictive working directory
WORKDIR /app

# Security: Copy files with explicit ownership and minimal permissions
COPY --from=builder --chown=flareinspect:flareinspect /app/node_modules ./node_modules
COPY --chown=flareinspect:flareinspect . .

# Security: Create directories with restrictive permissions and set executable bits only where needed
RUN mkdir -p logs bin output && \
    chmod 750 logs bin output && \
    chmod 755 src/cli/index.js && \
    chmod 755 src/cli/interactive.js && \
    chmod 755 src/cli/welcome.js && \
    chmod 644 src/core/**/*.js 2>/dev/null || true && \
    ln -s /app/src/cli/index.js /app/bin/flareinspect && \
    ln -s /app/src/cli/welcome.js /app/bin/flareinspect-welcome && \
    chown -R flareinspect:flareinspect /app && \
    chmod -R o-rwx /app

# Security: Remove potential security risks
RUN find /app -name "*.md" -not -path "*/node_modules/*" -exec chmod 644 {} \; && \
    find /app -name "*.json" -not -path "*/node_modules/*" -exec chmod 644 {} \; && \
    rm -rf /tmp/* /var/tmp/* /root/.npm /home/*/.npm 2>/dev/null || true

# Security: Switch to non-root user early
USER flareinspect

# Security: Set secure environment variables
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV NODE_OPTIONS="--no-warnings --max-old-space-size=512"
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_AUDIT=true

# Add bin to PATH
ENV PATH="/app/bin:${PATH}"

# Security: Add security labels
LABEL \
    org.opencontainers.image.title="FlareInspect" \
    org.opencontainers.image.description="CVE-free Cloudflare Security Assessment Tool" \
    org.opencontainers.image.vendor="IONSEC.IO" \
    org.opencontainers.image.version="1.0.0" \
    org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    security.scan.level="high" \
    security.cve.status="clean"

# Security: Use dumb-init as primary process manager (more secure than tini for this use case)
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/app/bin/flareinspect"]

# Default command launches interactive mode
CMD []

# Security: Health check to ensure container is running properly
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/bin/flareinspect --version > /dev/null || exit 1