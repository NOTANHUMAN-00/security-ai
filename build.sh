#!/bin/bash
# Sentinel-X Build Script

echo "========================================"
echo "Building Sentinel-X WAF"
echo "========================================"

# Set variables
BINARY_NAME="sentinel-x"
WASM_NAME="solver.wasm"
VERSION="1.0.0"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
fi

# Build the main server
echo ""
echo "[1/3] Building server binary..."
CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build \
    -ldflags="-w -s -X main.Version=$VERSION" \
    -o $BINARY_NAME \
    ./cmd/server

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to build server"
    exit 1
fi
echo "      Success: $BINARY_NAME"

# Build the WASM module
echo ""
echo "[2/3] Building WASM module..."
mkdir -p static
GOOS=js GOARCH=wasm go build -o static/$WASM_NAME ./pkg/wasm

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to build WASM"
    exit 1
fi
echo "      Success: static/$WASM_NAME"

# Copy WASM exec helper
echo ""
echo "[3/3] Copying WASM helper..."
GOROOT=$(go env GOROOT)
cp "$GOROOT/misc/wasm/wasm_exec.js" static/wasm_exec.js 2>/dev/null

if [ $? -ne 0 ]; then
    echo "WARNING: Could not copy wasm_exec.js"
else
    echo "      Success: static/wasm_exec.js"
fi

echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "To run: ./$BINARY_NAME"
echo ""
