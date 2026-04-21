# syntax=docker/dockerfile:1.6

# ─── Stage 1: build SPA ───────────────────────────────────────────────────────
FROM docker.io/library/node:20-alpine AS builder
WORKDIR /app

# Install deps first to leverage layer cache.
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

# Build the static bundle.
COPY . .
RUN npm run build

# ─── Stage 2: serve static + proxy API/WS ─────────────────────────────────────
FROM docker.io/library/nginx:1.27-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Health endpoint (nginx default returns 200 on / when SPA is loaded).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O - http://127.0.0.1/ > /dev/null || exit 1

EXPOSE 80
