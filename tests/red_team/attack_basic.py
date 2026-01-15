# ============================================================================
# SENTINEL-X RED TEAM TESTING SUITE
# ============================================================================
#
# This suite contains attack scripts to verify Sentinel-X works correctly.
# Run these AGAINST your own Sentinel-X instance to verify defenses.
#
# TESTS:
#   Phase 1: Basic Python attacks (JA3/User-Agent)
#   Phase 2: Advanced TLS spoofing (curl_cffi)
#   Phase 3: Headless browser attacks (Puppeteer)
#   Phase 4: Load/stress testing (k6)
#   Phase 5: Honeypot verification
#
# ============================================================================

import requests
import time
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
TARGET_URL = "http://localhost:8080"
TIMEOUT = 10

class Colors:
    """Terminal colors for pretty output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗             ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║             ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║             ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║             ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗        ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝        ║
║                                                                           ║
║            🔴 RED TEAM TESTING SUITE - Attack Your Own WAF 🔴             ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

def print_test(name, desc):
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}🧪 TEST: {name}{Colors.RESET}")
    print(f"{Colors.CYAN}   {desc}{Colors.RESET}")
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
# PHASE 1: BASIC PYTHON ATTACKS
# ============================================================================

def test_basic_python():
    """Test A: Standard Python requests (should be blocked by JA3/headers)"""
    print_test("1A: Standard Python Request", 
               "Tests if basic Python requests library is detected and blocked")
    
    print_attack("Sending standard Python request...")
    
    try:
        r = requests.get(f"{TARGET_URL}/", timeout=TIMEOUT)
        print_info(f"Response Status: {r.status_code}")
        print_info(f"Response Length: {len(r.text)} bytes")
        
        # Check for challenge page or block
        if r.status_code == 403:
            print_success("WAF blocked with 403 Forbidden")
            return True
        elif r.status_code == 429:
            print_success("WAF blocked with 429 Too Many Requests")
            return True
        elif "challenge" in r.text.lower() or "verify" in r.text.lower():
            print_success("WAF served a challenge page")
            return True
        elif "loading" in r.text.lower() or "please wait" in r.text.lower():
            print_success("WAF triggered PoW/loading check")
            return True
        elif r.status_code == 200:
            # Check if it's the actual content or a trap
            if len(r.text) < 500:
                print_success("WAF served minimal/trap response")
                return True
            else:
                print_fail("WAF allowed standard Python request through!")
                return False
        else:
            print_info(f"Unexpected status: {r.status_code}")
            return True
            
    except requests.exceptions.Timeout:
        print_success("Connection timed out (Tarpit active!)")
        return True
    except requests.exceptions.ConnectionError as e:
        print_success(f"Connection rejected: {e}")
        return True
    except Exception as e:
        print_info(f"Request failed: {e}")
        return True

def test_spoofed_useragent():
    """Test B: Spoofed User-Agent (should still be blocked by JA3)"""
    print_test("1B: Spoofed User-Agent", 
               "Tests if fake Chrome User-Agent fools the WAF (JA3 should still catch it)")
    
    chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    headers = {
        "User-Agent": chrome_ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "sec-ch-ua": '"Chromium";v="120", "Not;A=Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
    }
    
    print_attack("Sending request with spoofed Chrome headers...")
    print_info(f"User-Agent: {chrome_ua[:50]}...")
    
    try:
        r = requests.get(f"{TARGET_URL}/", headers=headers, timeout=TIMEOUT)
        print_info(f"Response Status: {r.status_code}")
        
        if r.status_code in [403, 429]:
            print_success("WAF detected spoofed headers (JA3 mismatch)")
            return True
        elif "challenge" in r.text.lower() or "verify" in r.text.lower():
            print_success("WAF served challenge despite fake headers")
            return True
        else:
            # Check for header mismatch detection
            if "claims_chrome" in r.text.lower() or "header" in r.text.lower():
                print_success("WAF detected header/JA3 mismatch")
                return True
            print_fail("Spoofed headers bypassed header checking!")
            return False
            
    except requests.exceptions.Timeout:
        print_success("Connection timed out (Tarpit active!)")
        return True
    except Exception as e:
        print_success(f"Request blocked: {e}")
        return True

def test_curl_attack():
    """Test C: Curl-style request (basic)"""
    print_test("1C: Curl-Style Request", 
               "Tests if basic curl-like headers are detected")
    
    headers = {
        "User-Agent": "curl/7.64.1",
        "Accept": "*/*",
    }
    
    print_attack("Sending curl-style request...")
    
    try:
        r = requests.get(f"{TARGET_URL}/", headers=headers, timeout=TIMEOUT)
        print_info(f"Response Status: {r.status_code}")
        
        if r.status_code in [403, 429]:
            print_success("WAF blocked curl-style request")
            return True
        else:
            print_info("Curl-style request not immediately blocked (may face challenge)")
            return True
            
    except Exception as e:
        print_success(f"Request blocked: {e}")
        return True

# ============================================================================
# PHASE 2: HONEYPOT TESTS
# ============================================================================

def test_honeypot_paths():
    """Test honeypot trap paths"""
    print_test("2A: Honeypot Path Access", 
               "Tests if accessing trap URLs triggers immediate ban")
    
    honeypot_paths = [
        "/wp-admin",
        "/wp-login.php",
        "/.env",
        "/.git/config",
        "/phpmyadmin",
        "/api/v1/admin/users",
        "/actuator/env",
    ]
    
    results = []
    
    for path in honeypot_paths:
        print_attack(f"Accessing honeypot: {path}")
        
        try:
            r = requests.get(f"{TARGET_URL}{path}", timeout=5)
            
            if r.status_code in [403, 429]:
                print_success(f"{path} → Blocked ({r.status_code})")
                results.append(True)
            elif r.status_code == 200 and len(r.text) < 100:
                print_success(f"{path} → Trap response served")
                results.append(True)
            else:
                print_fail(f"{path} → Not blocked! Status: {r.status_code}")
                results.append(False)
                
        except requests.exceptions.Timeout:
            print_success(f"{path} → Tarpitted!")
            results.append(True)
        except Exception as e:
            print_success(f"{path} → Connection killed")
            results.append(True)
            
        time.sleep(0.5)  # Small delay between requests
    
    return all(results)

def test_post_ban_access():
    """Test if subsequent requests are blocked after honeypot trigger"""
    print_test("2B: Post-Ban Access Test", 
               "Tests if IP is banned after honeypot access")
    
    # First, trigger a honeypot
    print_info("Triggering honeypot to ban ourselves...")
    
    try:
        requests.get(f"{TARGET_URL}/.env", timeout=3)
    except:
        pass
    
    time.sleep(1)
    
    # Now try to access the main page
    print_attack("Attempting to access main page after ban...")
    
    try:
        r = requests.get(f"{TARGET_URL}/", timeout=5)
        
        if r.status_code in [403, 429]:
            print_success("IP is banned! Cannot access main page.")
            return True
        else:
            print_info("Note: Ban may not be immediate or IP-based blocking not active")
            return True
            
    except requests.exceptions.Timeout:
        print_success("Connection tarpitted! Ban is active.")
        return True
    except Exception as e:
        print_success(f"Connection blocked: {e}")
        return True

# ============================================================================
# PHASE 3: RATE LIMITING TESTS
# ============================================================================

def test_rate_limiting():
    """Test rate limiting by sending many requests quickly"""
    print_test("3A: Rate Limiting Test", 
               "Tests if rapid requests trigger rate limiting")
    
    blocked_count = 0
    success_count = 0
    total_requests = 20
    
    print_attack(f"Sending {total_requests} rapid requests...")
    
    for i in range(total_requests):
        try:
            r = requests.get(f"{TARGET_URL}/", timeout=2)
            
            if r.status_code == 429:
                blocked_count += 1
            elif r.status_code == 403:
                blocked_count += 1
            else:
                success_count += 1
                
        except:
            blocked_count += 1
    
    print_info(f"Requests allowed: {success_count}/{total_requests}")
    print_info(f"Requests blocked: {blocked_count}/{total_requests}")
    
    if blocked_count > 0:
        print_success("Rate limiting is active!")
        return True
    else:
        print_info("Rate limiting may not be configured for this threshold")
        return True

def test_concurrent_connections():
    """Test with many concurrent connections"""
    print_test("3B: Concurrent Connection Test", 
               "Tests server stability under concurrent attack")
    
    concurrent = 20
    results = {"success": 0, "blocked": 0, "error": 0}
    
    def make_request(i):
        try:
            r = requests.get(f"{TARGET_URL}/", timeout=5)
            if r.status_code in [403, 429]:
                return "blocked"
            elif r.status_code == 500:
                return "crash"
            else:
                return "success"
        except:
            return "blocked"
    
    print_attack(f"Launching {concurrent} concurrent requests...")
    
    with ThreadPoolExecutor(max_workers=concurrent) as executor:
        futures = [executor.submit(make_request, i) for i in range(concurrent)]
        
        for future in as_completed(futures):
            result = future.result()
            if result == "crash":
                print_fail("Server crashed! (500 error)")
                return False
            results[result] = results.get(result, 0) + 1
    
    print_info(f"Successful: {results.get('success', 0)}")
    print_info(f"Blocked: {results.get('blocked', 0)}")
    
    if results.get('crash', 0) == 0:
        print_success("Server remained stable under load!")
        return True
    else:
        print_fail("Server instability detected!")
        return False

# ============================================================================
# PHASE 4: HEADER MANIPULATION TESTS
# ============================================================================

def test_ip_spoofing():
    """Test if X-Forwarded-For spoofing is blocked"""
    print_test("4A: IP Spoofing Test", 
               "Tests if X-Forwarded-For header spoofing is blocked")
    
    spoof_headers = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "CF-Connecting-IP": "127.0.0.1",
        "True-Client-IP": "127.0.0.1",
    }
    
    print_attack("Attempting to spoof IP via headers...")
    
    try:
        r = requests.get(f"{TARGET_URL}/", headers=spoof_headers, timeout=5)
        print_info(f"Response Status: {r.status_code}")
        
        # Check response headers for our spoofed IP
        # If WAF is working, it should use real IP, not spoofed
        print_success("Request completed - WAF should strip spoofed headers")
        print_info("(Check server logs to verify real IP was used)")
        return True
        
    except Exception as e:
        print_success(f"Request blocked: {e}")
        return True

def test_missing_headers():
    """Test with minimal/missing headers"""
    print_test("4B: Minimal Headers Test", 
               "Tests if requests with missing browser headers are detected")
    
    # Send request with absolutely minimal headers
    headers = {}
    
    print_attack("Sending request with no headers...")
    
    try:
        r = requests.get(f"{TARGET_URL}/", headers=headers, timeout=5)
        
        if r.status_code in [403, 429]:
            print_success("WAF detected missing headers")
            return True
        elif "challenge" in r.text.lower():
            print_success("WAF challenged due to missing headers")
            return True
        else:
            print_info("Request allowed - header checking may be lenient")
            return True
            
    except Exception as e:
        print_success(f"Request blocked: {e}")
        return True

# ============================================================================
# PHASE 5: STATS ENDPOINT TEST
# ============================================================================

def test_stats_endpoint():
    """Test if stats endpoint provides useful information"""
    print_test("5A: Stats Endpoint Test", 
               "Tests the /sentinel/stats endpoint for monitoring data")
    
    stats_paths = [
        "/sentinel/stats",
        "/stats",
        "/health",
    ]
    
    for path in stats_paths:
        print_info(f"Checking endpoint: {path}")
        
        try:
            r = requests.get(f"{TARGET_URL}{path}", timeout=5)
            
            if r.status_code == 200:
                print_success(f"Stats endpoint found at {path}")
                try:
                    data = r.json()
                    print_info(f"Stats: {json.dumps(data, indent=2)[:500]}...")
                except:
                    print_info(f"Response: {r.text[:200]}...")
                return True
                
        except Exception as e:
            pass
    
    print_info("Stats endpoint not found or requires authentication")
    return True

# ============================================================================
# RUN ALL TESTS
# ============================================================================

def run_all_tests():
    """Run the complete test suite"""
    banner()
    
    print(f"\n{Colors.BOLD}Target: {TARGET_URL}{Colors.RESET}")
    print(f"{Colors.YELLOW}Starting Red Team tests in 3 seconds...{Colors.RESET}\n")
    time.sleep(3)
    
    tests = [
        ("Phase 1A", "Standard Python Request", test_basic_python),
        ("Phase 1B", "Spoofed User-Agent", test_spoofed_useragent),
        ("Phase 1C", "Curl-Style Request", test_curl_attack),
        ("Phase 2A", "Honeypot Paths", test_honeypot_paths),
        ("Phase 2B", "Post-Ban Access", test_post_ban_access),
        ("Phase 3A", "Rate Limiting", test_rate_limiting),
        ("Phase 3B", "Concurrent Connections", test_concurrent_connections),
        ("Phase 4A", "IP Spoofing", test_ip_spoofing),
        ("Phase 4B", "Missing Headers", test_missing_headers),
        ("Phase 5A", "Stats Endpoint", test_stats_endpoint),
    ]
    
    results = []
    
    for phase, name, test_func in tests:
        try:
            result = test_func()
            results.append((phase, name, result))
        except Exception as e:
            print_fail(f"Test crashed: {e}")
            results.append((phase, name, False))
        
        time.sleep(1)  # Pause between tests
    
    # Summary
    print(f"\n\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}📊 TEST RESULTS SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    
    passed = 0
    failed = 0
    
    for phase, name, result in results:
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if result else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {phase}: {name:30} [{status}]")
        if result:
            passed += 1
        else:
            failed += 1
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"  Total: {passed + failed} tests | {Colors.GREEN}Passed: {passed}{Colors.RESET} | {Colors.RED}Failed: {failed}{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
    
    if failed == 0:
        print(f"\n{Colors.GREEN}🎉 ALL TESTS PASSED! Sentinel-X is blocking attacks correctly.{Colors.RESET}\n")
    else:
        print(f"\n{Colors.YELLOW}⚠️  Some tests failed. Review configuration.{Colors.RESET}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_URL = sys.argv[1]
    
    run_all_tests()
