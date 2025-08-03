# Multi-stage build for FlareInspect
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Production stage
FROM node:20-alpine

# Install runtime dependencies
RUN apk add --no-cache tini

# Create non-root user
RUN addgroup -g 1001 -S flareinspect && \
    adduser -u 1001 -S flareinspect -G flareinspect

# Set working directory
WORKDIR /app

# Copy from builder
COPY --from=builder --chown=flareinspect:flareinspect /app/node_modules ./node_modules
COPY --chown=flareinspect:flareinspect . .

# Create necessary directories and set permissions
RUN mkdir -p logs bin && \
    chmod +x src/cli/index.js && \
    chmod +x src/cli/interactive.js && \
    chmod +x src/cli/welcome.js && \
    ln -s /app/src/cli/index.js /app/bin/flareinspect && \
    ln -s /app/src/cli/welcome.js /app/bin/flareinspect-welcome && \
    chown -R flareinspect:flareinspect /app

# Switch to non-root user
USER flareinspect

# Set environment variables
ENV NODE_ENV=production
ENV LOG_LEVEL=info

# Add bin to PATH
ENV PATH="/app/bin:${PATH}"

# Use tini as entrypoint with flareinspect
ENTRYPOINT ["/sbin/tini", "--", "/app/bin/flareinspect"]

# Default command launches interactive mode
CMD []