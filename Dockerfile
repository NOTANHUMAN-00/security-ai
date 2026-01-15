# ==============================================================================
# SENTINEL-X MULTI-STAGE DOCKERFILE
# ==============================================================================
# 
# Build and run with zero dependencies:
#   docker build -t sentinel-x .
#   docker run -p 8080:8080 -e TARGET_URL=http://your-app:3000 sentinel-x
#
# ==============================================================================

# --- Stage 1: Build the WASM Client ---
FROM golang:1.23-alpine AS wasm-builder
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build WASM client
ENV GOOS=js 
ENV GOARCH=wasm
RUN go build -o /build/sentinel-client.wasm ./pkg/wasm/main.go

# Copy the WASM exec helper from Go installation
RUN cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" /build/

# --- Stage 2: Build the Sentinel-X Server ---
FROM golang:1.23-alpine AS server-builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build all server variants
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/sentinel-x ./cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/sentinel-pro ./cmd/sentinel-pro/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/sentinel-ultimate ./cmd/sentinel-ultimate/main.go

# --- Stage 3: The Final "Tiny" Image ---
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user for security
RUN addgroup -g 1000 sentinel && \
    adduser -u 1000 -G sentinel -s /bin/sh -D sentinel

WORKDIR /app

# Copy binaries from builder
COPY --from=server-builder /build/sentinel-x .
COPY --from=server-builder /build/sentinel-pro .
COPY --from=server-builder /build/sentinel-ultimate .

# Copy WASM files
COPY --from=wasm-builder /build/sentinel-client.wasm ./static/
COPY --from=wasm-builder /build/wasm_exec.js ./static/

# Copy config
COPY configs/config.yaml ./configs/

# Create directories
RUN mkdir -p /app/data /app/logs && \
    chown -R sentinel:sentinel /app

# Switch to non-root user
USER sentinel

# Environment variables with defaults
ENV TARGET_URL=http://localhost:3000
ENV LISTEN_PORT=8080
ENV PROTECTION_LEVEL=high
ENV REDIS_URL=""

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${LISTEN_PORT}/sentinel/stats || exit 1

# Expose ports
EXPOSE 8080

# Default command (can be overridden)
CMD ["./sentinel-x"]

# ==============================================================================
# USAGE EXAMPLES:
# ==============================================================================
#
# 1. Build the image:
#    docker build -t sentinel-x .
#
# 2. Run with environment variables:
#    docker run -p 8080:8080 \
#      -e TARGET_URL=http://my-app:3000 \
#      -e PROTECTION_LEVEL=high \
#      sentinel-x
#
# 3. Run the Pro version:
#    docker run -p 8080:8080 sentinel-x ./sentinel-pro
#
# 4. Run the Ultimate version:
#    docker run -p 8080:8080 sentinel-x ./sentinel-ultimate
#
# 5. With Redis for persistence:
#    docker run -p 8080:8080 \
#      -e TARGET_URL=http://my-app:3000 \
#      -e REDIS_URL=redis://redis:6379 \
#      sentinel-x
#
# ==============================================================================
