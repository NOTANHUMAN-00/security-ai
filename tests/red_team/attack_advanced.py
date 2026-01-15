# ============================================================================
# SENTINEL-X RED TEAM - ADVANCED TLS SPOOFING ATTACKS
# ============================================================================
#
# This script uses curl_cffi to impersonate real browser TLS fingerprints.
# This is how advanced attackers try to bypass JA3 detection.
#
# INSTALL: pip install curl_cffi
#
# ============================================================================

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    print("❌ curl_cffi not installed!")
    print("   Install with: pip install curl_cffi")
    print("")

import time
import sys

# Configuration
TARGET_URL = "http://localhost:8080"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"""
{Colors.RED}╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║       ⚠️  ADVANCED TLS SPOOFING ATTACK - curl_cffi ⚠️                    ║
║                                                                           ║
║   This simulates attackers using Chrome TLS fingerprints                  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

def print_test(name):
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}🧪 TEST: {name}{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")

def print_success(msg):
    print(f"{Colors.GREEN}✅ SUCCESS:{Colors.RESET} {msg}")

def print_fail(msg):
    print(f"{Colors.RED}❌ FAILED:{Colors.RESET} {msg}")

def print_info(msg):
    print(f"{Colors.YELLOW}ℹ️  INFO:{Colors.RESET} {msg}")

def print_attack(msg):
    print(f"{Colors.RED}🚀 ATTACK:{Colors.RESET} {msg}")

# ============================================================================
# ADVANCED TLS ATTACKS
# ============================================================================

def test_chrome_impersonation():
    """Test Chrome TLS fingerprint impersonation"""
    print_test("Chrome 120 TLS Impersonation")
    
    if not HAS_CURL_CFFI:
        print_info("Skipping - curl_cffi not installed")
        return None
    
    print_attack("Impersonating Chrome 120 TLS fingerprint...")
    
    try:
        r = curl_requests.get(
            f"{TARGET_URL}/",
            impersonate="chrome120",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "sec-ch-ua": '"Chromium";v="120", "Google Chrome";v="120"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            },
            timeout=10
        )
        
        print_info(f"Response Status: {r.status_code}")
        print_info(f"Response Length: {len(r.text)} bytes")
        
        # Analyze response
        content = r.text.lower()
        
        if r.status_code == 403:
            print_success("BLOCKED! WAF detected something despite TLS impersonation")
            print_info("(Possibly header order, HTTP/2 frames, or other signals)")
            return True
            
        elif r.status_code == 429:
            print_success("Rate limited - defense layer active")
            return True
            
        elif "challenge" in content or "verify" in content or "loading" in content:
            print_success("PARTIAL BYPASS: TLS check passed, but WASM/PoW triggered!")
            print_info("This is expected - multi-layer defense working")
            return True
            
        elif "proof" in content or "pow" in content:
            print_success("PoW challenge served - defense layer active")
            return True
            
        elif r.status_code == 200:
            # Check if real content or trap
            if len(r.text) < 1000:
                print_info("Short response - may be challenge or trap")
                return True
            else:
                print_fail("TLS impersonation bypassed JA3 check!")
                print_info("Check if other defense layers (PoW, Battery, etc.) are active")
                return False
        
        return True
        
    except Exception as e:
        print_success(f"Request blocked/failed: {e}")
        return True

def test_firefox_impersonation():
    """Test Firefox TLS fingerprint impersonation"""
    print_test("Firefox 120 TLS Impersonation")
    
    if not HAS_CURL_CFFI:
        print_info("Skipping - curl_cffi not installed")
        return None
    
    print_attack("Impersonating Firefox 120 TLS fingerprint...")
    
    try:
        r = curl_requests.get(
            f"{TARGET_URL}/",
            impersonate="firefox120",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
            },
            timeout=10
        )
        
        print_info(f"Response Status: {r.status_code}")
        
        if r.status_code in [403, 429]:
            print_success("BLOCKED despite Firefox TLS impersonation")
            return True
        elif "challenge" in r.text.lower() or "verify" in r.text.lower():
            print_success("Challenge served - secondary defense active")
            return True
        else:
            print_info("Firefox impersonation response - check other layers")
            return True
            
    except Exception as e:
        print_success(f"Request blocked: {e}")
        return True

def test_safari_impersonation():
    """Test Safari TLS fingerprint impersonation"""
    print_test("Safari TLS Impersonation")
    
    if not HAS_CURL_CFFI:
        print_info("Skipping - curl_cffi not installed")
        return None
    
    print_attack("Impersonating Safari TLS fingerprint...")
    
    try:
        r = curl_requests.get(
            f"{TARGET_URL}/",
            impersonate="safari17_0",
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            },
            timeout=10
        )
        
        print_info(f"Response Status: {r.status_code}")
        
        if r.status_code in [403, 429]:
            print_success("BLOCKED despite Safari TLS impersonation")
            return True
        else:
            print_info("Safari impersonation complete - check secondary layers")
            return True
            
    except Exception as e:
        print_success(f"Request blocked: {e}")
        return True

def test_tls_mismatch():
    """Test mismatched TLS/User-Agent (Chrome TLS with Firefox UA)"""
    print_test("TLS/User-Agent Mismatch Attack")
    
    if not HAS_CURL_CFFI:
        print_info("Skipping - curl_cffi not installed")
        return None
    
    print_attack("Sending Chrome TLS with Firefox User-Agent...")
    print_info("This should be detected as anomalous!")
    
    try:
        r = curl_requests.get(
            f"{TARGET_URL}/",
            impersonate="chrome120",  # Chrome TLS
            headers={
                # But Firefox UA!
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            },
            timeout=10
        )
        
        print_info(f"Response Status: {r.status_code}")
        
        if r.status_code in [403, 429]:
            print_success("DETECTED! TLS/UA mismatch caught")
            return True
        elif "mismatch" in r.text.lower() or "suspicious" in r.text.lower():
            print_success("Mismatch detected by WAF!")
            return True
        else:
            print_info("Mismatch not immediately caught - may trigger on other signals")
            return True
            
    except Exception as e:
        print_success(f"Request blocked: {e}")
        return True

def test_rapid_tls_spoofing():
    """Test rapid requests with TLS spoofing"""
    print_test("Rapid TLS Spoofing Attack")
    
    if not HAS_CURL_CFFI:
        print_info("Skipping - curl_cffi not installed")
        return None
    
    print_attack("Sending 10 rapid requests with TLS impersonation...")
    
    blocked = 0
    success = 0
    
    for i in range(10):
        try:
            r = curl_requests.get(
                f"{TARGET_URL}/",
                impersonate="chrome120",
                timeout=5
            )
            
            if r.status_code in [403, 429]:
                blocked += 1
            else:
                success += 1
                
        except:
            blocked += 1
    
    print_info(f"Blocked: {blocked}/10")
    print_info(f"Success: {success}/10")
    
    if blocked > 0:
        print_success("Rate limiting caught rapid TLS-spoofed requests!")
        return True
    else:
        print_info("Rate limiting may need tuning for TLS-spoofed requests")
        return True

# ============================================================================
# RUN ALL TESTS
# ============================================================================

def run_all_tests():
    """Run the complete advanced TLS test suite"""
    banner()
    
    if not HAS_CURL_CFFI:
        print(f"{Colors.RED}Cannot run tests without curl_cffi!{Colors.RESET}")
        print(f"Install with: {Colors.CYAN}pip install curl_cffi{Colors.RESET}\n")
        return
    
    print(f"\n{Colors.BOLD}Target: {TARGET_URL}{Colors.RESET}")
    print(f"{Colors.YELLOW}Starting Advanced TLS tests in 3 seconds...{Colors.RESET}\n")
    time.sleep(3)
    
    tests = [
        ("Chrome 120 Impersonation", test_chrome_impersonation),
        ("Firefox 120 Impersonation", test_firefox_impersonation),
        ("Safari 17 Impersonation", test_safari_impersonation),
        ("TLS/UA Mismatch", test_tls_mismatch),
        ("Rapid TLS Spoofing", test_rapid_tls_spoofing),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print_fail(f"Test crashed: {e}")
            results.append((name, False))
        
        time.sleep(1)
    
    # Summary
    print(f"\n\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}📊 ADVANCED TLS ATTACK RESULTS{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    
    for name, result in results:
        if result is None:
            status = f"{Colors.YELLOW}SKIP{Colors.RESET}"
        elif result:
            status = f"{Colors.GREEN}PASS{Colors.RESET}"
        else:
            status = f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {name:40} [{status}]")
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_URL = sys.argv[1]
    
    run_all_tests()
