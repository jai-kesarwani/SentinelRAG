# =============================================================================
# SentinelRAG Frontend Dockerfile
# Multi-Stage Build: Node.js 20 Builder -> Nginx 1.27 Alpine Static Server
# =============================================================================

# --- Stage 1: Build Frontend Assets ---
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package descriptors for layer caching
COPY package.json package-lock.json ./

# Install project dependencies
RUN npm ci

# Copy full frontend source code
COPY . .

# Build production assets using TypeScript and Vite
RUN npm run build

# --- Stage 2: Serve via Nginx ---
FROM nginx:1.27-alpine

# Install curl for container health check
RUN apk add --no-cache curl

# Copy compiled SPA static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration for SPA routing and API reverse proxy
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose HTTP port
EXPOSE 80

# Health check ensuring Nginx serves the root index page
HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

