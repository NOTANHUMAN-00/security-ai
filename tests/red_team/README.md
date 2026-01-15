# ============================================================================
# SENTINEL-X RED TEAM TESTING SUITE - README
# ============================================================================
#
# This directory contains attack scripts to verify Sentinel-X defenses.
# Run these AGAINST your own Sentinel-X instance to verify it works.
#
# ============================================================================

## 📋 Test Suite Overview

| File | Purpose | Install |
|------|---------|---------|
| `attack_basic.py` | Basic Python attacks (JA3, headers) | `pip install requests` |
| `attack_advanced.py` | Advanced TLS spoofing | `pip install curl_cffi` |
| `attack_browser.js` | Headless browser attacks | `npm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth` |
| `stress_test.js` | Load/stress testing | Install k6 from https://k6.io |

## 🚀 Quick Start

### 1. Start Sentinel-X
```bash
cd sentinel-x
go build -o sentinel.exe ./cmd/server
./sentinel.exe
# Or use the standalone versions:
# ./sentinel-ultimate.exe
# ./sentinel-pro.exe
```

### 2. Run Basic Tests
```bash
cd tests/red_team
python attack_basic.py http://localhost:8080
```

### 3. Run Advanced TLS Tests
```bash
pip install curl_cffi
python attack_advanced.py http://localhost:8080
```

### 4. Run Headless Browser Tests
```bash
npm install
node attack_browser.js http://localhost:8080
```

### 5. Run Stress Tests
```bash
# Install k6 first
k6 run stress_test.js
# Or with custom load
k6 run --vus 200 --duration 60s stress_test.js
```

## ✅ Expected Results

### Phase 1: Basic Python (attack_basic.py)

| Test | Expected Result |
|------|-----------------|
| Standard Python Request | BLOCKED (JA3/User-Agent mismatch) |
| Spoofed User-Agent | BLOCKED (JA3 still mismatches) |
| Curl-Style Request | BLOCKED or CHALLENGED |
| Honeypot Paths | BLOCKED + IP BANNED |
| Rate Limiting | Triggered after N requests |

### Phase 2: Advanced TLS (attack_advanced.py)

| Test | Expected Result |
|------|-----------------|
| Chrome TLS Impersonation | CHALLENGED (JA3 passed, but PoW/WASM triggers) |
| Firefox TLS Impersonation | CHALLENGED |
| TLS/UA Mismatch | BLOCKED (suspicious mismatch) |

### Phase 3: Headless Browser (attack_browser.js)

| Test | Expected Result |
|------|-----------------|
| Basic Headless | CHALLENGED or BLOCKED (Battery/WebGPU check) |
| Stealth Plugin | Still DETECTED (other signals) |
| Mouse Simulation | Low entropy detected |
| Battery API | Fails (headless has no battery) |
| WebGL Fingerprint | SwiftShader detected (server GPU) |

### Phase 4: Stress Test (stress_test.js)

| Metric | Expected |
|--------|----------|
| Server Crashes (500) | 0% |
| Blocked Requests | High (WAF active) |
| P95 Response Time | <2000ms |

## 🎯 What Each Test Validates

### JA3/TLS Fingerprinting
- attack_basic.py → Python's TLS fingerprint differs from Chrome
- attack_advanced.py → Tests if curl_cffi can fake Chrome's TLS

### Header Analysis
- Missing Chrome headers (sec-ch-ua, sec-fetch-*)
- Header order detection
- User-Agent/TLS mismatch

### Hardware Detection
- Battery API (servers don't have batteries)
- WebGL/GPU (servers use SwiftShader)
- Entropy (robotic mouse movements)

### Deception Layers
- Honeypot paths trigger bans
- Tarpit holds connections open
- Poison cookies detect return visitors

### Stability
- Server handles 200+ concurrent connections
- No memory leaks under load
- Rate limiting protects resources

## 🔧 Customization

Edit the TARGET_URL in each script:

```python
# Python scripts
TARGET_URL = "http://your-server:8080"
```

```javascript
// JavaScript scripts
const TARGET_URL = process.argv[2] || 'http://localhost:8080';
```

## 📊 Interpreting Results

### ✅ GREEN (PASS)
- Request was BLOCKED (403)
- Request was RATE LIMITED (429)
- Request was CHALLENGED (PoW/WASM page)
- Request TIMED OUT (Tarpit)

### ❌ RED (FAIL)
- Request returned 200 with real content
- Request bypassed all defenses
- Server crashed (500)

## 🔒 Security Notes

**ONLY run these tests against:**
- Your own Sentinel-X instance
- Systems you have permission to test
- Non-production environments

**NEVER run against:**
- Third-party websites
- Production systems without authorization
- Systems you don't own/control

## 📈 Release Checklist

Before releasing Sentinel-X, verify:

- [ ] Standard Python → BLOCKED
- [ ] curl_cffi Chrome → CHALLENGED
- [ ] Puppeteer Stealth → DETECTED
- [ ] 200 VUs for 60s → NO CRASHES
- [ ] Honeypot → INSTANT BAN
- [ ] Rate Limit → TRIGGERED
- [ ] Dashboard → SHOWING STATS

If all checks pass, your WAF is ready! 🎉
