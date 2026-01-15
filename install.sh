#!/bin/bash
# ==============================================================================
# SENTINEL-X ONE-LINE INSTALLER
# ==============================================================================
#
# Install Sentinel-X with a single command:
#   curl -sL https://raw.githubusercontent.com/YOUR_USER/sentinel-x/main/install.sh | bash
#
# Or download and run:
#   chmod +x install.sh && ./install.sh
#
# ==============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                           ║"
echo "║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗             ║"
echo "║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║             ║"
echo "║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║             ║"
echo "║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║             ║"
echo "║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗        ║"
echo "║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝        ║"
echo "║                                                                           ║"
echo "║                    🛡️ Anti-Bot WAF Installer 🛡️                          ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS and Architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac
    
    case $OS in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        mingw*|msys*|cygwin*)
            OS="windows"
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS: $OS${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${BLUE}📦 Detected platform: ${OS}-${ARCH}${NC}"
}

# Check dependencies
check_dependencies() {
    echo -e "${YELLOW}🔍 Checking dependencies...${NC}"
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}❌ curl is required but not installed.${NC}"
        echo "   Install with: apt install curl (Ubuntu) or brew install curl (Mac)"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All dependencies satisfied${NC}"
}

# Download binary
download_binary() {
    local VERSION="${1:-latest}"
    local REPO="YOUR_GITHUB_USER/sentinel-x"
    local BINARY_NAME="sentinel-x"
    
    if [ "$OS" = "windows" ]; then
        BINARY_NAME="sentinel-x.exe"
    fi
    
    echo -e "${YELLOW}⬇️  Downloading Sentinel-X...${NC}"
    
    # Get latest release URL if version is "latest"
    if [ "$VERSION" = "latest" ]; then
        DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/sentinel-x-${OS}-${ARCH}"
    else
        DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/sentinel-x-${OS}-${ARCH}"
    fi
    
    # Download binary
    if curl -fsSL -o "${BINARY_NAME}" "${DOWNLOAD_URL}" 2>/dev/null; then
        chmod +x "${BINARY_NAME}"
        echo -e "${GREEN}✅ Downloaded ${BINARY_NAME}${NC}"
    else
        echo -e "${RED}❌ Download failed. Building from source...${NC}"
        build_from_source
    fi
}

# Build from source (fallback)
build_from_source() {
    echo -e "${YELLOW}🔨 Building from source...${NC}"
    
    if ! command -v go &> /dev/null; then
        echo -e "${RED}❌ Go is required for building from source.${NC}"
        echo "   Install from: https://go.dev/dl/"
        exit 1
    fi
    
    # Clone repo
    git clone --depth=1 https://github.com/YOUR_GITHUB_USER/sentinel-x.git /tmp/sentinel-x
    cd /tmp/sentinel-x
    
    # Build
    go build -ldflags="-s -w" -o sentinel-x ./cmd/server/main.go
    mv sentinel-x "$OLDPWD/"
    cd "$OLDPWD"
    rm -rf /tmp/sentinel-x
    
    echo -e "${GREEN}✅ Built from source${NC}"
}

# Create default config
create_config() {
    echo -e "${YELLOW}📝 Creating configuration...${NC}"
    
    mkdir -p configs
    
    cat > configs/config.yaml << 'EOF'
# ==============================================================================
# SENTINEL-X CONFIGURATION
# ==============================================================================

# Your backend application URL
target_url: "http://localhost:3000"

# Listen address and port
listen_addr: ":8080"

# Protection level: low, medium, high, paranoid
protection_level: "high"

# Redis URL for persistent storage (optional)
# redis_url: "redis://localhost:6379"

# Enable P2P threat sharing
p2p_enabled: true

# Dashboard settings
dashboard:
  enabled: true
  username: "admin"
  password: "changeme123"  # CHANGE THIS!

# Webhook alerts (optional)
# webhooks:
#   discord: "https://discord.com/api/webhooks/..."
#   slack: "https://hooks.slack.com/..."

# Rate limiting
rate_limit:
  requests_per_minute: 60
  burst: 10

# Tarpit settings
tarpit:
  enabled: true
  delay_ms: 100
  max_duration_s: 300

# Honeypot paths
honeypots:
  - "/wp-admin"
  - "/wp-login.php"
  - "/.env"
  - "/.git"
  - "/phpmyadmin"
  - "/admin"
  - "/actuator"

# Geofencing (optional)
# blocked_countries:
#   - "XX"  # Country code
EOF

    echo -e "${GREEN}✅ Config created at configs/config.yaml${NC}"
}

# Create systemd service (Linux only)
create_service() {
    if [ "$OS" != "linux" ]; then
        return
    fi
    
    echo -e "${YELLOW}🔧 Creating systemd service...${NC}"
    
    INSTALL_DIR="$(pwd)"
    
    sudo tee /etc/systemd/system/sentinel-x.service > /dev/null << EOF
[Unit]
Description=Sentinel-X Anti-Bot WAF
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/sentinel-x
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    echo -e "${GREEN}✅ Systemd service created${NC}"
    echo -e "${BLUE}   Start with: sudo systemctl start sentinel-x${NC}"
    echo -e "${BLUE}   Auto-start: sudo systemctl enable sentinel-x${NC}"
}

# Print success message
print_success() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                           ║${NC}"
    echo -e "${GREEN}║                    ✅ INSTALLATION COMPLETE! ✅                          ║${NC}"
    echo -e "${GREEN}║                                                                           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo ""
    echo -e "  1. Edit your config:"
    echo -e "     ${YELLOW}nano configs/config.yaml${NC}"
    echo ""
    echo -e "  2. Set your backend URL:"
    echo -e "     ${YELLOW}target_url: \"http://your-app:3000\"${NC}"
    echo ""
    echo -e "  3. Start Sentinel-X:"
    echo -e "     ${YELLOW}./sentinel-x${NC}"
    echo ""
    echo -e "  4. View stats:"
    echo -e "     ${YELLOW}curl http://localhost:8080/sentinel/stats${NC}"
    echo ""
    if [ "$OS" = "linux" ]; then
        echo -e "${CYAN}Run as Service:${NC}"
        echo -e "     ${YELLOW}sudo systemctl start sentinel-x${NC}"
        echo -e "     ${YELLOW}sudo systemctl enable sentinel-x${NC}"
        echo ""
    fi
    echo -e "${CYAN}Documentation:${NC}"
    echo -e "     https://github.com/YOUR_GITHUB_USER/sentinel-x"
    echo ""
}

# Main installation
main() {
    echo -e "${YELLOW}🛡️ Installing Sentinel-X...${NC}"
    echo ""
    
    detect_platform
    check_dependencies
    download_binary "${1:-latest}"
    create_config
    
    if [ "$OS" = "linux" ] && [ "$EUID" -eq 0 ]; then
        create_service
    fi
    
    print_success
}

# Run main with optional version argument
main "$@"
