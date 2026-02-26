# ==============================================================================
# Rust Voice Agent - Production Dockerfile
#
# Multi-stage build:
#   1. Build custom Caddy with rate limiting
#   2. Build frontend
#   3. Build Rust binary
#   4. Run with Caddy reverse proxy
# ==============================================================================

# Stage 1: Build custom Caddy with rate limiting
FROM caddy:2-builder AS caddy-build

RUN xcaddy build \
    --with github.com/mholt/caddy-ratelimit

# Stage 2: Build frontend
FROM node:24-alpine AS frontend-build

RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /build/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# Stage 3: Build Rust binary
FROM rust:1.85-alpine AS rust-build

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# Create dummy main.rs so cargo can fetch dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
# Remove the dummy build artifacts
RUN rm -rf src target/release/deps/rust_voice_agent* target/release/rust-voice-agent*

# Copy real source and build
COPY src/ ./src/
COPY deepgram.toml ./
RUN cargo build --release

# Stage 4: Production image with Caddy
FROM alpine:3.20

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Copy custom Caddy with rate limiting
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy

WORKDIR /app

# Copy Rust binary
COPY --from=rust-build /build/target/release/rust-voice-agent ./rust-voice-agent
COPY --from=rust-build /build/deepgram.toml ./deepgram.toml

# Copy built frontend
COPY --from=frontend-build /build/frontend/dist ./frontend/dist

# Copy Caddy configuration and start script
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

# Set environment variables
ENV BACKEND_PORT=8081
ENV PORT=8081
ENV HOST=0.0.0.0
ENV BACKEND_CMD="./rust-voice-agent"

EXPOSE 8080

CMD ["./start.sh"]
