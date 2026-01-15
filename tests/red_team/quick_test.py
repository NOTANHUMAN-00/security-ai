# Quick Sentinel-X Verification Test
import requests
import time

TARGET = "http://localhost:8080"

print("=" * 60)
print(" SENTINEL-X QUICK VERIFICATION TEST")
print("=" * 60)

# Test 1: Standard Request
print("\n[TEST 1] Standard Python Request...")
try:
    r = requests.get(f"{TARGET}/", timeout=5)
    print(f"  Status: {r.status_code}")
    if r.status_code == 403:
        print("  ✅ BLOCKED by WAF!")
    elif r.status_code == 429:
        print("  ✅ Rate limited!")
    elif r.status_code == 502:
        print("  ✅ Passed WAF checks (502 = no backend)")
    else:
        print(f"  Response: {r.text[:100]}...")
except requests.exceptions.Timeout:
    print("  ✅ TARPITTED!")
except Exception as e:
    print(f"  Error: {e}")

# Test 2: Stats Endpoint
print("\n[TEST 2] Checking Stats...")
try:
    r = requests.get(f"{TARGET}/sentinel/stats", timeout=5)
    print(f"  Stats: {r.text}")
except Exception as e:
    print(f"  Error: {e}")

# Test 3: Honeypot (with short timeout)
print("\n[TEST 3] Honeypot Trap (.env)...")
try:
    r = requests.get(f"{TARGET}/.env", timeout=3)
    print(f"  Status: {r.status_code}")
    if r.status_code == 403:
        print("  ✅ BLOCKED - Honeypot triggered!")
except requests.exceptions.Timeout:
    print("  ✅ TARPITTED - Honeypot working!")
except Exception as e:
    print(f"  ✅ Connection killed: {str(e)[:50]}")

# Test 4: Check stats again
print("\n[TEST 4] Updated Stats...")
time.sleep(1)
try:
    r = requests.get(f"{TARGET}/sentinel/stats", timeout=5)
    import json
    stats = json.loads(r.text)
    print(f"  Total Requests:     {stats.get('total_requests', 0)}")
    print(f"  Blocked IPs:        {stats.get('blocked_ips', 0)}")
    print(f"  Tarpitted:          {stats.get('tarpitted', 0)}")
    print(f"  Honeypot Triggered: {stats.get('honeypot_triggered', 0)}")
    print(f"  P2P Blocks Shared:  {stats.get('p2p_blocks_shared', 0)}")
except Exception as e:
    print(f"  Error: {e}")

print("\n" + "=" * 60)
print(" TEST COMPLETE")
print("=" * 60)
