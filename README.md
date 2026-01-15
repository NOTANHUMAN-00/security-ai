<div align="center">

# 🛡️ Sentinel-X

### **Enterprise Anti-Bot WAF & Reverse Proxy**

*Advanced bot detection and protection system with 13 layers of defense*

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](Dockerfile)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/NOTANHUMAN-00/security-ai/pulls)

[**Documentation**](#-documentation) • [**Quick Start**](#-quick-start) • [**Features**](#-features) • [**Contributing**](#-contributing)

</div>

---

## ⚠️ IMPORTANT NOTICE

> **🚧 THIS PROJECT IS UNDER ACTIVE DEVELOPMENT**
> 
> Sentinel-X is currently in **alpha/beta** stage. While it contains advanced security features, please note:
> 
> - ✅ **DO** test thoroughly in development environments
> - ✅ **DO** report bugs and issues on GitHub
> - ✅ **DO** review the code before deploying
> - ❌ **DO NOT** deploy to production without extensive testing
> - ❌ **DO NOT** use as your sole security layer
> - ❌ **DO NOT** assume it's bug-free or production-ready
>
> **Always conduct security audits and penetration testing before production use.**

---

## 📖 Table of Contents

- [What is Sentinel-X?](#-what-is-sentinel-x)
- [Quick Start](#-quick-start)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 What is Sentinel-X?

Sentinel-X is an **open-source, AI-powered Web Application Firewall (WAF)** designed to protect your web applications from bots, scrapers, and automated attacks. It acts as a reverse proxy that sits between the internet and your application, intelligently filtering malicious traffic while allowing legitimate users through.

```
Internet → [Sentinel-X WAF] → Your Application
              ↓
         Bots Trapped
       (Tarpit/Block/Ban)
```

### Key Capabilities

- 🔍 **Multi-Layer Detection**: 13 distinct detection layers from network to browser fingerprinting
- 🪤 **Advanced Deception**: Tarpits, honeypots, and poison injection to trap and confuse bots
- 🚀 **High Performance**: <5ms latency overhead, handles 10,000+ req/s
- 🌐 **P2P Threat Sharing**: Distributed intelligence network for real-time threat detection
- 🔧 **Easy Integration**: Works as a reverse proxy with any backend application

---

## ⚡ Quick Start

### Prerequisites

- Go 1.24 or higher (for building from source)
- Docker (optional, for containerized deployment)
- Redis (optional, for persistent bans and rate limiting)

### Option 1: Docker (Recommended)

```bash
docker run -p 8080:8080 \
  -e TARGET_URL=http://your-app:3000 \
  ghcr.io/notanhuman-00/security-ai:latest
```

### Option 2: Docker Compose

```yaml
version: '3.8'
services:
  sentinel-x:
    build: .
    ports:
      - "8080:8080"
    environment:
      - TARGET_URL=http://your-app:3000
      - PROTECTION_LEVEL=high
    volumes:
      - ./configs:/app/configs
```

```bash
docker-compose up -d
```

### Option 3: Build from Source

```bash
# Clone the repository
git clone https://github.com/NOTANHUMAN-00/security-ai.git
cd security-ai

# Build the binary
go build -o sentinel-x ./pkg/core/cmd/main.go

# Run with default settings
./sentinel-x -target http://localhost:3000
```

### Option 4: Pre-built Binary

Download the latest release from the [Releases page](https://github.com/NOTANHUMAN-00/security-ai/releases).

```bash
# Linux
chmod +x sentinel-x-linux-amd64
./sentinel-x-linux-amd64 -target http://localhost:3000

# Windows
sentinel-x-windows-amd64.exe -target http://localhost:3000
```

---

## 🔥 Features

### 13 Layers of Bot Detection

| Layer | Technology | Detection Capability |
|-------|------------|---------------------|
| **Network** | TTL/MSS Analysis | VPN detection, proxy detection, OS fingerprinting |
| **TLS** | JA3 Fingerprinting | Python requests, Go http, curl, wget |
| **HTTP/2** | Frame Analysis | Library-specific patterns |
| **Headers** | Order Detection | Browser vs automation tool signatures |
| **Challenge** | Proof-of-Work (Argon2/SHA256) | CPU-based verification |
| **WASM** | Proof-of-Space | Memory verification |
| **Browser** | Canvas/Audio Fingerprinting | Device-specific hashing |
| **Behavior** | Mouse Entropy Analysis | Human vs robotic movement |
| **Hardware** | Battery/WebGPU API | Server detection |
| **Persistence** | ETag Supercookies | Tracking across sessions |
| **AI Defense** | LLM Poison Injection | Corrupt AI scraper training data |
| **Deception** | Honeypots + Tarpit | Trap and waste attacker time |
| **P2P** | Threat Intelligence Sharing | Distributed defense network |

### Defense Mechanisms

#### 🔍 Detection
- JA3/JA3S TLS fingerprinting
- HTTP header order analysis
- Browser fingerprinting (Canvas, WebGL, Audio)
- Behavioral biometrics (mouse, touch, keyboard)
- Hardware API detection (Battery, WebGPU, Device Memory)

#### 🪤 Deception
- **Tarpit**: Infinite loops with slow drip, chunked encoding, gzip bombs
- **Honeypots**: Fake admin panels, hidden links, trap URLs
- **Poison Injection**: Corrupt data for AI/ML scrapers
- **Redirect Maze**: Endless redirects for aggressive crawlers

#### 🛡️ Protection
- Rate limiting (per IP, per session)
- Geo-blocking capabilities
- IP ban management (manual and automatic)
- Whitelist/blacklist system
- P2P threat intelligence sharing

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SENTINEL-X WAF                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │   TLS    │ │  Header  │ │  Canvas  │ │  Tarpit  │           │
│  │Fingerprint│ │ Analysis │ │   Hash   │ │  Engine  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│                              │                                  │
│              ┌───────────────┼───────────────┐                  │
│              ▼               ▼               ▼                  │
│         ┌────────┐     ┌────────────┐   ┌────────┐             │
│         │  PASS  │     │ CHALLENGE  │   │ BLOCK  │             │
│         └────────┘     └────────────┘   └────────┘             │
└─────────────┬───────────────┬───────────────┬───────────────────┘
              │               │               │
              ▼               │               ▼
┌─────────────────────┐       │       ┌───────────────────┐
│  YOUR APPLICATION   │       │       │ Tarpit / 403 / Ban│
└─────────────────────┘       │       └───────────────────┘
                              │
                              ▼
                        ┌──────────┐
                        │ JS/WASM  │
                        │Challenge │
                        └──────────┘
```

---

## 💾 Installation

### System Requirements

- **OS**: Linux, Windows, macOS
- **Memory**: Minimum 512MB RAM (1GB+ recommended)
- **CPU**: 1+ cores (2+ recommended for high traffic)
- **Network**: Public IP or behind reverse proxy

### Building from Source

```bash
# Clone repository
git clone https://github.com/NOTANHUMAN-00/security-ai.git
cd security-ai

# Install dependencies
go mod download

# Build
go build -o sentinel-x ./pkg/core/cmd/main.go

# Verify build
./sentinel-x --help
```

### Docker Build

```bash
# Build image
docker build -t sentinel-x:latest .

# Run container
docker run -p 8080:8080 \
  -e TARGET_URL=http://backend:3000 \
  -e PROTECTION_LEVEL=high \
  sentinel-x:latest
```

---

## ⚙️ Configuration

### Command-Line Flags

```bash
sentinel-x \
  -listen :8080 \
  -target http://localhost:3000 \
  -redis localhost:6379 \
  -difficulty 4
```

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8080` | Address to listen on |
| `-target` | `http://localhost:3000` | Backend application URL |
| `-redis` | `localhost:6379` | Redis server address |
| `-difficulty` | `4` | PoW difficulty (trailing zeros) |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_URL` | `http://localhost:3000` | Backend URL |
| `LISTEN_ADDR` | `:8080` | Listen address |
| `PROTECTION_LEVEL` | `high` | `low`, `medium`, `high`, `paranoid` |
| `REDIS_URL` | - | Redis connection string |
| `P2P_ENABLED` | `true` | Enable P2P threat sharing |
| `DASHBOARD_USER` | `admin` | Dashboard username |
| `DASHBOARD_PASS` | - | Dashboard password (required) |

### Configuration File

Create `configs/config.yaml`:

```yaml
# Target application
target_url: "http://localhost:3000"
listen_addr: ":8080"

# Protection level: low, medium, high, paranoid
protection_level: "high"

# Redis for persistent storage
redis_url: "redis://localhost:6379"

# Rate limiting
rate_limit:
  requests_per_minute: 60
  burst: 10
  
# Geo-blocking
geo_blocking:
  enabled: true
  blocked_countries: ["CN", "RU"]
  
# Honeypot paths
honeypots:
  - "/wp-admin"
  - "/wp-login.php"
  - "/.env"
  - "/.git/config"
  - "/admin"
  - "/phpmyadmin"

# Webhook notifications
webhooks:
  discord: "https://discord.com/api/webhooks/..."
  slack: "https://hooks.slack.com/services/..."
  
# P2P threat sharing
p2p:
  enabled: true
  port: 8081
  peers:
    - "peer1.example.com:8081"
    - "peer2.example.com:8081"
```

---

## 🔌 API Documentation

### Dashboard & Statistics

Access the dashboard at: `http://localhost:8080/sentinel/stats`

```bash
curl http://localhost:8080/sentinel/stats
```

**Response:**
```json
{
  "total_requests": 15473,
  "blocked_requests": 892,
  "tarpitted": 456,
  "honeypot_triggered": 23,
  "pow_challenges": 1234,
  "pow_solved": 1156,
  "banned_ips": 47,
  "p2p_blocks_shared": 156,
  "avg_latency_ms": 2.3
}
```

### Ban Management

#### Ban an IP
```bash
curl -X POST http://localhost:8080/sentinel/ban \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "reason": "Suspicious activity",
    "duration": "24h"
  }'
```

#### Unban an IP
```bash
curl -X DELETE http://localhost:8080/sentinel/ban/1.2.3.4
```

#### List Banned IPs
```bash
curl http://localhost:8080/sentinel/bans
```

### Whitelist Management

#### Add to Whitelist
```bash
curl -X POST http://localhost:8080/sentinel/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "4.3.2.1"}'
```

#### Remove from Whitelist
```bash
curl -X DELETE http://localhost:8080/sentinel/whitelist/4.3.2.1
```

---

## 🧪 Testing

### Tested Against

| Tool | Result |
|------|--------|
| Python `requests` | ✅ **TARPITTED** |
| `curl` / `wget` | ✅ **TARPITTED** |
| `curl_cffi` (TLS spoofing) | ✅ **TARPITTED** |
| Puppeteer (Headless) | ✅ **TARPITTED** |
| Puppeteer + Stealth | ✅ **DETECTED** |
| Playwright | ✅ **DETECTED** |
| Selenium | ✅ **DETECTED** |
| Scrapy | ✅ **BLOCKED** |

### Running Tests

```bash
# Unit tests
go test ./...

# Integration tests
cd tests
npm install
npm run test

# Red team tests (requires testing environment)
cd tests/red_team
node attack_browser.js
python3 attack_requests.py
```

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Latency Overhead | <5ms (avg 2-3ms) |
| Memory Usage | ~50MB base |
| Throughput | 10,000+ req/s |
| Concurrent Connections | 100,000+ |
| CPU Usage | <10% on 2 cores |

---

## 🚀 Production Deployment

### With Nginx

```nginx
upstream sentinel {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://sentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Systemd Service

Create `/etc/systemd/system/sentinel-x.service`:

```ini
[Unit]
Description=Sentinel-X WAF
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/sentinel-x
ExecStart=/opt/sentinel-x/sentinel-x -listen :8080 -target http://localhost:3000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable sentinel-x
sudo systemctl start sentinel-x
sudo systemctl status sentinel-x
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel-x
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sentinel-x
  template:
    metadata:
      labels:
        app: sentinel-x
    spec:
      containers:
      - name: sentinel-x
        image: ghcr.io/notanhuman-00/security-ai:latest
        ports:
        - containerPort: 8080
        env:
        - name: TARGET_URL
          value: "http://backend-service:3000"
        - name: PROTECTION_LEVEL
          value: "high"
        resources:
          requests:
            memory: "256Mi"
            cpu: "500m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: sentinel-x
spec:
  selector:
    app: sentinel-x
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

---

## 🤝 Contributing

**We welcome contributions!** This is an open-source project under active development.

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Write clear, documented code
- Add tests for new features
- Follow Go best practices
- Update documentation as needed
- Run `go fmt` and `go vet` before committing

### Areas Needing Help

- 🐛 **Bug fixes** and stability improvements
- 📝 **Documentation** enhancements
- 🧪 **Testing** coverage expansion
- 🎨 **UI/UX** for dashboard
- 🌐 **Internationalization**
- 🔒 **Security** audits and improvements

### Reporting Issues

Found a bug? Have a feature request? [Open an issue](https://github.com/NOTANHUMAN-00/security-ai/issues) with:

- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Go version, etc.)

---

## 🛡️ Security

### Responsible Disclosure

If you discover a security vulnerability, please **DO NOT** open a public issue. Instead:

1. Email: saifeeleap@gmail.com
2. Include detailed description and PoC if possible
3. Allow time for patch development before disclosure

### Security Best Practices

- ✅ Run behind a reverse proxy (Nginx, Caddy)
- ✅ Enable HTTPS with valid certificates
- ✅ Use strong passwords for dashboard
- ✅ Regular updates and security audits
- ✅ Monitor logs and alerts
- ❌ Don't expose Redis to public internet
- ❌ Don't use as sole security measure

---

## 📊 Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Advanced CAPTCHA integration
- [ ] GraphQL protection
- [ ] WebSocket inspection
- [ ] Real-time dashboard UI
- [ ] Mobile app for monitoring
- [ ] Cloud-native threat intelligence
- [ ] Browser extension for testing

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by various WAF projects and security research
- Built with ❤️ for the security community
- Special thanks to all contributors

---

<div align="center">

**⚠️ Remember: Always test thoroughly before production deployment ⚠️**

[Report Bug](https://github.com/NOTANHUMAN-00/security-ai/issues) • [Request Feature](https://github.com/NOTANHUMAN-00/security-ai/issues) • [Contribute](https://github.com/NOTANHUMAN-00/security-ai/pulls)

**Made with ❤️ for open source security**

</div>
