# Security AI - Sentinel-X

This repository contains both the Sentinel-X WAF (backend) and its marketing website (frontend).

## 🌐 Website Deployment

The React website is located in the `security-ai-main/` directory.

### Deploy to Vercel

1. Connect this repository to Vercel
2. Vercel will automatically detect the configuration
3. The website will be built from `security-ai-main/` directory

Or manually:
```bash
cd security-ai-main
npm install
npm run build
# Deploy the build/ folder
```

### Local Development

```bash
cd security-ai-main
npm install
npm start
# Opens at http://localhost:3000
```

## 🛡️ WAF (Web Application Firewall)

See the full [README.md](./README.md) for complete WAF documentation, installation, and deployment instructions.

### Quick Start WAF

```bash
# Docker
docker run -p 8080:8080 \
  -e TARGET_URL=http://your-app:3000 \
  ghcr.io/notanhuman-00/security-ai:latest

# From source
go build -o sentinel-x ./pkg/core/cmd/main.go
./sentinel-x -target http://localhost:3000
```

## 📁 Repository Structure

```
.
├── security-ai-main/      # React marketing website
│   ├── src/              # React components
│   ├── public/           # Static assets
│   └── package.json      # Website dependencies
│
├── pkg/                  # Go WAF source code
├── internal/             # Internal packages
├── static/               # WAF static assets
├── tests/                # Test suites
└── README.md            # Full WAF documentation
```

## 🚀 Contributing

See [README.md](./README.md) for contribution guidelines.

## 📜 License

MIT License - See [LICENSE](./LICENSE)
