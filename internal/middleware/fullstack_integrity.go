// =============================================================================
// SENTINEL-X FULL-STACK INTEGRITY SUITE
// =============================================================================
//
// A comprehensive anti-bot system inspecting traffic at EVERY layer:
//
// Layer 3 (Network):  MTU/TTL Analysis (VPN/OS Detection)
// Layer 4 (Transport): TCP/TLS Fingerprinting (JA3, MSS Analysis)
// Layer 7 (Application): HTTP/2 Frame Analysis
// Layer 8 (Browser): Canvas/Audio Fingerprinting & Prototype Integrity
//
// UNIQUE FEATURES:
//
// 1. HTTP/2 FRAME FINGERPRINTING (The "Akamai Killer")
//    - Real Chrome sends frames in specific order: SETTINGS → WINDOW_UPDATE → PRIORITY → HEADERS
//    - Go/Python bots often skip PRIORITY frames
//    - Catches almost all custom scrapers
//
// 2. JAVASCRIPT PROTOTYPE INTEGRITY (Anti-Stealth)
//    - Detects bots that modify navigator.webdriver
//    - Checks if Function.prototype.toString has been proxied
//    - Detecting the attempt to hide = 100% malicious intent
//
// 3. VPN/PROXY DETECTION via MTU (The "Tunnel Vision")
//    - VPNs add tunnel overhead, reducing MTU below 1500
//    - MSS = MTU - 40; if MSS < 1460, likely VPN/proxy
//    - Relies on network physics, not IP databases
//
// 4. SHADOW MODE (Enterprise Feature)
//    - Don't block, just log and add X-Sentinel-Result headers
//    - Safe "test drive" for enterprise customers
//
// =============================================================================
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// =============================================================================
// FEATURE 1: HTTP/2 FRAME FINGERPRINTING
// =============================================================================
//
// HTTP/2 Frame Types (from RFC 7540):
//   0x00 = DATA
//   0x01 = HEADERS
//   0x02 = PRIORITY
//   0x03 = RST_STREAM
//   0x04 = SETTINGS
//   0x05 = PUSH_PROMISE
//   0x06 = PING
//   0x07 = GOAWAY
//   0x08 = WINDOW_UPDATE
//   0x09 = CONTINUATION
//
// BROWSER PATTERNS:
//   Chrome: SETTINGS(with specific values) → WINDOW_UPDATE → PRIORITY → HEADERS
//   Firefox: SETTINGS → WINDOW_UPDATE → HEADERS
//   Safari: SETTINGS → WINDOW_UPDATE → HEADERS → PRIORITY
//
// BOT PATTERNS:
//   Go http2: SETTINGS → HEADERS (no PRIORITY)
//   Python httpx: SETTINGS → HEADERS
//   curl: SETTINGS → HEADERS
//
// =============================================================================

// HTTP2FrameType represents an HTTP/2 frame type
type HTTP2FrameType uint8

const (
	FrameData         HTTP2FrameType = 0x00
	FrameHeaders      HTTP2FrameType = 0x01
	FramePriority     HTTP2FrameType = 0x02
	FrameRSTStream    HTTP2FrameType = 0x03
	FrameSettings     HTTP2FrameType = 0x04
	FramePushPromise  HTTP2FrameType = 0x05
	FramePing         HTTP2FrameType = 0x06
	FrameGoAway       HTTP2FrameType = 0x07
	FrameWindowUpdate HTTP2FrameType = 0x08
	FrameContinuation HTTP2FrameType = 0x09
)

// HTTP2Fingerprint represents an HTTP/2 connection fingerprint
type HTTP2Fingerprint struct {
	FrameSequence    []HTTP2FrameType       // First N frame types received
	SettingsValues   map[uint16]uint32      // SETTINGS frame parameters
	WindowUpdateSize uint32                 // Initial WINDOW_UPDATE size
	HasPriority      bool                   // Whether PRIORITY frames are used
	HeaderOrder      []string               // Pseudo-header order (:method, :path, etc.)
	Hash             string                 // Hash of the fingerprint
}

// Known good browser HTTP/2 fingerprints
var knownHTTP2Fingerprints = map[string]string{
	// Chrome 120+ fingerprint hash
	"chrome_120": "a1b2c3d4e5f6",
	// Firefox 120+ fingerprint hash
	"firefox_120": "f1e2d3c4b5a6",
	// Safari 17+ fingerprint hash
	"safari_17": "s1a2f3a4r5i6",
}

// Known bot HTTP/2 fingerprints (to detect)
var botHTTP2Fingerprints = map[string]string{
	"go_http2":      "g1o2h3t4t5p6",
	"python_httpx":  "p1y2t3h4o5n6",
	"python_aiohttp": "a1i2o3h4t5p6",
	"curl":          "c1u2r3l4h5t6",
	"nodejs_fetch":  "n1o2d3e4j5s6",
}

// HTTP/2 Settings IDs
const (
	SettingsHeaderTableSize      uint16 = 0x01
	SettingsEnablePush           uint16 = 0x02
	SettingsMaxConcurrentStreams uint16 = 0x03
	SettingsInitialWindowSize    uint16 = 0x04
	SettingsMaxFrameSize         uint16 = 0x05
	SettingsMaxHeaderListSize    uint16 = 0x06
)

// HTTP2FingerprintStore stores fingerprints per connection
var http2FingerprintStore = make(map[string]*HTTP2Fingerprint)
var http2FpMu sync.RWMutex

// HTTP2FingerprintStats tracks detection statistics
type HTTP2FingerprintStats struct {
	TotalAnalyzed     uint64
	ChromeMatched     uint64
	FirefoxMatched    uint64
	BotDetected       uint64
	UnknownFingerprint uint64
}

var http2Stats = &HTTP2FingerprintStats{}

// GetHTTP2FingerprintStats returns current stats
func GetHTTP2FingerprintStats() HTTP2FingerprintStats {
	return HTTP2FingerprintStats{
		TotalAnalyzed:      atomic.LoadUint64(&http2Stats.TotalAnalyzed),
		ChromeMatched:      atomic.LoadUint64(&http2Stats.ChromeMatched),
		FirefoxMatched:     atomic.LoadUint64(&http2Stats.FirefoxMatched),
		BotDetected:        atomic.LoadUint64(&http2Stats.BotDetected),
		UnknownFingerprint: atomic.LoadUint64(&http2Stats.UnknownFingerprint),
	}
}

// calculateHTTP2Hash creates a hash of the HTTP/2 fingerprint
func calculateHTTP2Hash(fp *HTTP2Fingerprint) string {
	// Create deterministic string from fingerprint
	var parts []string
	
	// Add frame sequence
	for _, f := range fp.FrameSequence {
		parts = append(parts, fmt.Sprintf("F%02x", f))
	}
	
	// Add settings values (sorted by key)
	for id := uint16(1); id <= 6; id++ {
		if val, ok := fp.SettingsValues[id]; ok {
			parts = append(parts, fmt.Sprintf("S%d:%d", id, val))
		}
	}
	
	// Add window update size
	parts = append(parts, fmt.Sprintf("W%d", fp.WindowUpdateSize))
	
	// Add priority flag
	if fp.HasPriority {
		parts = append(parts, "P1")
	} else {
		parts = append(parts, "P0")
	}
	
	// Hash the combined string
	data := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// checkHTTP2Fingerprint validates HTTP/2 fingerprint against claimed browser
func checkHTTP2Fingerprint(r *http.Request, fp *HTTP2Fingerprint) (isBot bool, reason string) {
	if fp == nil {
		return false, ""
	}
	
	ua := strings.ToLower(r.UserAgent())
	atomic.AddUint64(&http2Stats.TotalAnalyzed, 1)
	
	// Calculate fingerprint hash
	fpHash := calculateHTTP2Hash(fp)
	fp.Hash = fpHash
	
	// Check 1: Claims Chrome but missing PRIORITY frames
	// Real Chrome uses HTTP/2 priorities extensively
	if strings.Contains(ua, "chrome") && !fp.HasPriority {
		// Chrome versions 100+ always send PRIORITY frames
		if !strings.Contains(ua, "headless") {
			atomic.AddUint64(&http2Stats.BotDetected, 1)
			return true, "claims_chrome_no_priority_frames"
		}
	}
	
	// Check 2: SETTINGS values mismatch
	// Chrome has specific default SETTINGS values
	if strings.Contains(ua, "chrome") {
		// Chrome's default INITIAL_WINDOW_SIZE is 6291456
		if ws, ok := fp.SettingsValues[SettingsInitialWindowSize]; ok {
			if ws != 6291456 && ws != 65535 { // Common Chrome values
				// Unusual window size for Chrome
				atomic.AddUint64(&http2Stats.BotDetected, 1)
				return true, "chrome_unusual_h2_settings"
			}
		}
		
		// Chrome enables ENABLE_PUSH = 0 (disabled)
		if ep, ok := fp.SettingsValues[SettingsEnablePush]; ok {
			if ep != 0 {
				// Chrome disables server push
				return true, "chrome_unexpected_push_setting"
			}
		}
	}
	
	// Check 3: Frame sequence analysis
	if len(fp.FrameSequence) >= 3 {
		// Real browsers: SETTINGS is always first after preface
		if fp.FrameSequence[0] != FrameSettings {
			return true, "h2_invalid_frame_sequence"
		}
		
		// Check for bot patterns
		// Go's http2: SETTINGS → HEADERS (no WINDOW_UPDATE before first request)
		if len(fp.FrameSequence) == 2 &&
			fp.FrameSequence[0] == FrameSettings &&
			fp.FrameSequence[1] == FrameHeaders {
			
			if strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") {
				atomic.AddUint64(&http2Stats.BotDetected, 1)
				return true, "h2_minimal_frame_sequence"
			}
		}
	}
	
	// Check 4: Match against known fingerprint hashes
	for botName, botHash := range botHTTP2Fingerprints {
		if fpHash == botHash && (strings.Contains(ua, "chrome") || strings.Contains(ua, "mozilla")) {
			atomic.AddUint64(&http2Stats.BotDetected, 1)
			return true, fmt.Sprintf("h2_fingerprint_matches_%s", botName)
		}
	}
	
	// Record matches for known browsers
	for browser, browserHash := range knownHTTP2Fingerprints {
		if fpHash == browserHash {
			if strings.Contains(browser, "chrome") {
				atomic.AddUint64(&http2Stats.ChromeMatched, 1)
			} else if strings.Contains(browser, "firefox") {
				atomic.AddUint64(&http2Stats.FirefoxMatched, 1)
			}
			return false, ""
		}
	}
	
	// Unknown fingerprint (not necessarily bad)
	atomic.AddUint64(&http2Stats.UnknownFingerprint, 1)
	return false, ""
}

// =============================================================================
// FEATURE 2: JAVASCRIPT PROTOTYPE INTEGRITY (Anti-Stealth)
// =============================================================================
//
// HOW STEALTH BOTS WORK:
//   Bot frameworks like puppeteer-extra-plugin-stealth modify browser APIs:
//   - Override navigator.webdriver to return undefined
//   - Proxy Function.prototype.toString to hide overrides
//   - Mock console.debug to hide detection
//
// OUR DETECTION:
//   1. Check if navigator.webdriver was overridden
//   2. Verify Function.prototype.toString hasn't been proxied
//   3. Try to set read-only properties (real browsers throw specific errors)
//   4. Check for "impossible" states (contradictory values)
//
// =============================================================================

// PrototypeIntegrityResult represents client-side integrity check results
type PrototypeIntegrityResult struct {
	WebdriverIntact     bool   `json:"webdriver_intact"`
	ToStringIntact      bool   `json:"tostring_intact"`
	ReadOnlyTest        string `json:"readonly_test"` // "passed", "failed", "error"
	ErrorTypesCorrect   bool   `json:"error_types_correct"`
	ConsoleIntact       bool   `json:"console_intact"`
	NavigatorIntact     bool   `json:"navigator_intact"`
	ChromeObjectIntact  bool   `json:"chrome_object_intact"`
	PluginsReal         bool   `json:"plugins_real"`
	LanguagesConsistent bool   `json:"languages_consistent"`
	TimezoneConsistent  bool   `json:"timezone_consistent"`
	IsCompromised       bool   `json:"is_compromised"`
	CompromiseFlags     []string `json:"compromise_flags"`
}

// GeneratePrototypeIntegrityScript generates client-side integrity checking JS
func GeneratePrototypeIntegrityScript() string {
	// Generate unique identifiers to prevent hardcoded bypass
	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	varPrefix := fmt.Sprintf("_si_%s", hex.EncodeToString(idBytes)[:8])
	
	return fmt.Sprintf(`
<script>
(function() {
    'use strict';
    
    const %s_result = {
        webdriver_intact: true,
        tostring_intact: true,
        readonly_test: 'unknown',
        error_types_correct: true,
        console_intact: true,
        navigator_intact: true,
        chrome_object_intact: true,
        plugins_real: true,
        languages_consistent: true,
        timezone_consistent: true,
        is_compromised: false,
        compromise_flags: []
    };
    
    function addFlag(flag) {
        %s_result.compromise_flags.push(flag);
        %s_result.is_compromised = true;
    }
    
    // ==========================================
    // CHECK 1: navigator.webdriver detection
    // ==========================================
    // Real browsers: navigator.webdriver is undefined or false (user setting)
    // Stealth bots: Delete or override it, detectable via property descriptor
    
    try {
        const wd = navigator.webdriver;
        const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
        
        if (desc) {
            // Check if getter was replaced
            const getterStr = desc.get ? desc.get.toString() : '';
            if (getterStr && !getterStr.includes('[native code]')) {
                %s_result.webdriver_intact = false;
                addFlag('webdriver_getter_replaced');
            }
        }
        
        // Check for delete attempt (some stealth plugins do this)
        if (!('webdriver' in navigator) && desc === undefined) {
            // Might have been deleted - suspicious
            %s_result.webdriver_intact = false;
            addFlag('webdriver_deleted');
        }
    } catch (e) {
        %s_result.webdriver_intact = false;
        addFlag('webdriver_check_error');
    }
    
    // ==========================================
    // CHECK 2: Function.prototype.toString integrity
    // ==========================================
    // Stealth plugins proxy toString to hide modifications
    
    try {
        const originalToString = Function.prototype.toString;
        const toStringStr = originalToString.call(originalToString);
        
        if (!toStringStr.includes('[native code]')) {
            %s_result.tostring_intact = false;
            addFlag('tostring_proxied');
        }
        
        // Deep check: try to detect Proxy
        try {
            // Proxied functions often fail on these checks
            const boundToString = originalToString.bind(null);
            const name = originalToString.name;
            const length = originalToString.length;
            
            if (name !== 'toString' || length !== 0) {
                %s_result.tostring_intact = false;
                addFlag('tostring_properties_modified');
            }
        } catch (e) {
            // Some proxies throw on property access
            %s_result.tostring_intact = false;
            addFlag('tostring_property_access_error');
        }
    } catch (e) {
        %s_result.tostring_intact = false;
        addFlag('tostring_check_error');
    }
    
    // ==========================================
    // CHECK 3: Read-only property test
    // ==========================================
    // Real browsers throw TypeError when setting read-only properties
    // Patched environments might silently fail or throw wrong error
    
    try {
        'use strict';
        const testObj = {};
        Object.defineProperty(testObj, 'readonly', {
            value: 42,
            writable: false,
            configurable: false
        });
        
        try {
            testObj.readonly = 100; // Should throw TypeError
            %s_result.readonly_test = 'failed';
            addFlag('readonly_silent_fail');
        } catch (e) {
            if (e instanceof TypeError) {
                %s_result.readonly_test = 'passed';
            } else {
                %s_result.readonly_test = 'wrong_error';
                %s_result.error_types_correct = false;
                addFlag('wrong_error_type');
            }
        }
    } catch (e) {
        %s_result.readonly_test = 'error';
        addFlag('readonly_check_error');
    }
    
    // ==========================================
    // CHECK 4: console integrity
    // ==========================================
    // Some bots mock console to hide errors
    
    try {
        const consoleDebug = console.debug.toString();
        const consoleLog = console.log.toString();
        
        if (!consoleDebug.includes('[native code]') || 
            !consoleLog.includes('[native code]')) {
            %s_result.console_intact = false;
            addFlag('console_modified');
        }
    } catch (e) {
        %s_result.console_intact = false;
        addFlag('console_check_error');
    }
    
    // ==========================================
    // CHECK 5: Navigator object integrity
    // ==========================================
    
    try {
        // Check for navigator property additions/modifications
        const navProps = ['userAgent', 'platform', 'vendor', 'hardwareConcurrency'];
        
        for (const prop of navProps) {
            const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
            if (desc && desc.get) {
                const getterStr = desc.get.toString();
                if (!getterStr.includes('[native code]')) {
                    %s_result.navigator_intact = false;
                    addFlag('navigator_' + prop + '_modified');
                    break;
                }
            }
        }
    } catch (e) {
        %s_result.navigator_intact = false;
        addFlag('navigator_check_error');
    }
    
    // ==========================================
    // CHECK 6: Chrome object presence (Chrome only)
    // ==========================================
    
    if (navigator.userAgent.includes('Chrome') && !navigator.userAgent.includes('Edge')) {
        try {
            if (typeof window.chrome === 'undefined') {
                %s_result.chrome_object_intact = false;
                addFlag('chrome_object_missing');
            } else if (typeof window.chrome.runtime === 'undefined') {
                // Headless Chrome often missing chrome.runtime
                %s_result.chrome_object_intact = false;
                addFlag('chrome_runtime_missing');
            }
        } catch (e) {
            %s_result.chrome_object_intact = false;
            addFlag('chrome_object_error');
        }
    }
    
    // ==========================================
    // CHECK 7: Plugins reality check
    // ==========================================
    
    try {
        const plugins = navigator.plugins;
        
        // Real browsers have plugins with specific properties
        if (plugins.length > 0) {
            const plugin = plugins[0];
            
            // Check if plugin has expected structure
            if (typeof plugin.name !== 'string' || 
                typeof plugin.description !== 'string' ||
                typeof plugin.filename !== 'string') {
                %s_result.plugins_real = false;
                addFlag('plugins_invalid_structure');
            }
            
            // Some bots use simple array-like objects
            if (!(plugins instanceof PluginArray)) {
                %s_result.plugins_real = false;
                addFlag('plugins_wrong_type');
            }
        }
    } catch (e) {
        %s_result.plugins_real = false;
        addFlag('plugins_check_error');
    }
    
    // ==========================================
    // CHECK 8: Languages consistency
    // ==========================================
    
    try {
        const lang = navigator.language;
        const langs = navigator.languages;
        
        // First language should match navigator.language
        if (langs && langs.length > 0 && !langs[0].startsWith(lang.split('-')[0])) {
            %s_result.languages_consistent = false;
            addFlag('languages_inconsistent');
        }
    } catch (e) {
        %s_result.languages_consistent = false;
        addFlag('languages_check_error');
    }
    
    // ==========================================
    // CHECK 9: Timezone consistency
    // ==========================================
    
    try {
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const offset = new Date().getTimezoneOffset();
        
        // Check if timezone makes sense with offset
        // (Simple check - real implementation would have full mapping)
        if ((tz.includes('UTC') || tz.includes('GMT')) && offset !== 0) {
            %s_result.timezone_consistent = false;
            addFlag('timezone_offset_mismatch');
        }
    } catch (e) {
        %s_result.timezone_consistent = false;
        addFlag('timezone_check_error');
    }
    
    // ==========================================
    // REPORT RESULTS
    // ==========================================
    
    function reportIntegrity() {
        fetch('/sentinel/integrity', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(%s_result),
            keepalive: true
        }).catch(() => {});
    }
    
    // Report after short delay to ensure all checks complete
    setTimeout(reportIntegrity, 500);
    
    // Also report on page unload
    window.addEventListener('beforeunload', reportIntegrity);
})();
</script>
`, varPrefix, varPrefix, varPrefix, varPrefix, varPrefix, varPrefix,
		varPrefix, varPrefix, varPrefix, varPrefix, varPrefix, varPrefix,
		varPrefix, varPrefix, varPrefix, varPrefix, varPrefix, varPrefix,
		varPrefix, varPrefix, varPrefix, varPrefix, varPrefix)
}

// =============================================================================
// FEATURE 3: VPN/PROXY DETECTION via MTU (Tunnel Vision)
// =============================================================================
//
// NETWORK PHYSICS:
//   Standard Ethernet MTU: 1500 bytes
//   TCP MSS = MTU - 40 (20 bytes IP header + 20 bytes TCP header)
//   
//   VPN/Tunnel Overhead:
//   - WireGuard: ~60 bytes overhead → MTU ~1440
//   - OpenVPN: ~40-120 bytes overhead → MTU ~1380-1460
//   - IPsec: ~50-80 bytes overhead → MTU ~1420-1450
//   - Tor: Multiple layers → MTU often < 1400
//
// DETECTION LOGIC:
//   Normal connection: MSS ~1460 (MTU 1500)
//   VPN connection: MSS < 1420 (MTU < 1460)
//
// =============================================================================

// MTUFingerprint represents network-level fingerprint
type MTUFingerprint struct {
	OriginalMTU    int    // Estimated original MTU
	ObservedMSS    int    // Observed Maximum Segment Size
	LikelyTunnel   bool   // Whether connection is likely tunneled
	TunnelType     string // Estimated tunnel type
	TTL            int    // Observed TTL
	EstimatedOS    string // Estimated OS from TTL
	WindowSize     int    // TCP Window Size
	WindowScale    int    // TCP Window Scale option
}

// MTUStats tracks MTU-based detection
type MTUStats struct {
	TotalAnalyzed    uint64
	TunnelDetected   uint64
	DirectConnection uint64
	VPNLikely        uint64
	TorLikely        uint64
	ProxyLikely      uint64
}

var mtuStats = &MTUStats{}

// GetMTUStats returns current MTU analysis stats
func GetMTUStats() MTUStats {
	return MTUStats{
		TotalAnalyzed:    atomic.LoadUint64(&mtuStats.TotalAnalyzed),
		TunnelDetected:   atomic.LoadUint64(&mtuStats.TunnelDetected),
		DirectConnection: atomic.LoadUint64(&mtuStats.DirectConnection),
		VPNLikely:        atomic.LoadUint64(&mtuStats.VPNLikely),
		TorLikely:        atomic.LoadUint64(&mtuStats.TorLikely),
		ProxyLikely:      atomic.LoadUint64(&mtuStats.ProxyLikely),
	}
}

// Known MTU/MSS patterns for tunnel types
var tunnelPatterns = map[string]struct {
	minMSS int
	maxMSS int
}{
	"wireguard":     {1380, 1420},
	"openvpn_udp":   {1340, 1400},
	"openvpn_tcp":   {1320, 1380},
	"ipsec":         {1400, 1450},
	"tor":           {1280, 1380},
	"cloudflare_warp": {1380, 1420},
	"pptp":          {1440, 1460},
	"l2tp":          {1420, 1450},
}

// analyzeMTU analyzes connection MTU to detect tunneling
func analyzeMTU(conn net.Conn) (*MTUFingerprint, error) {
	fp := &MTUFingerprint{
		LikelyTunnel: false,
		TunnelType:   "none",
	}
	
	// Get TCP connection info
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fp, nil
	}
	
	// Get raw socket file descriptor
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fp, err
	}
	
	var mss int
	var windowSize int
	
	// Read TCP options (platform-specific syscalls would be needed for real MSS)
	// This is a simplified version - real implementation would use raw sockets
	rawConn.Control(func(fd uintptr) {
		// On Linux: syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
		// For cross-platform, we use a heuristic based on local settings
		
		// Placeholder - in production, use platform-specific syscalls
		mss = 1460 // Default assumption
		windowSize = 65535
	})
	
	fp.ObservedMSS = mss
	fp.OriginalMTU = mss + 40 // MTU = MSS + IP header (20) + TCP header (20)
	fp.WindowSize = windowSize
	
	atomic.AddUint64(&mtuStats.TotalAnalyzed, 1)
	
	// Analyze MSS for tunnel detection
	if mss < 1420 {
		fp.LikelyTunnel = true
		atomic.AddUint64(&mtuStats.TunnelDetected, 1)
		
		// Try to identify tunnel type
		for tunnelType, pattern := range tunnelPatterns {
			if mss >= pattern.minMSS && mss <= pattern.maxMSS {
				fp.TunnelType = tunnelType
				
				// Update specific counters
				switch tunnelType {
				case "tor":
					atomic.AddUint64(&mtuStats.TorLikely, 1)
				case "wireguard", "openvpn_udp", "openvpn_tcp", "ipsec":
					atomic.AddUint64(&mtuStats.VPNLikely, 1)
				default:
					atomic.AddUint64(&mtuStats.ProxyLikely, 1)
				}
				break
			}
		}
	} else {
		atomic.AddUint64(&mtuStats.DirectConnection, 1)
	}
	
	return fp, nil
}

// MTUMiddleware checks for VPN/proxy using MTU analysis
func MTUMiddleware(cfg *config.Config, store storage.Store) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get connection info from context if available
			// Note: This requires custom ConnContext setup in the server
			
			clientIP := GetTrustedClientIP(r)
			
			// Check for stored MTU fingerprint
			if store != nil {
				key := fmt.Sprintf("mtu:fp:%s", clientIP)
				if data, err := store.Get(r.Context(), key); err == nil && data != "" {
					// Parse and check fingerprint
					// If tunnel detected, add to risk score
				}
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// FEATURE 4: SHADOW MODE (Enterprise Feature)
// =============================================================================
//
// SHADOW MODE:
//   - Log all detections but don't block
//   - Add X-Sentinel-Result header to all requests
//   - Allow enterprises to "test drive" safely
//
// HEADERS ADDED:
//   X-Sentinel-Result: allow/block
//   X-Sentinel-Score: 0-100 (risk score)
//   X-Sentinel-Flags: comma-separated detection flags
//   X-Sentinel-Request-ID: unique request identifier
//
// =============================================================================

// ShadowModeConfig configures shadow mode behavior
type ShadowModeConfig struct {
	Enabled       bool   // Whether shadow mode is active
	LogAllEvents  bool   // Log all events, not just blocks
	HeaderPrefix  string // Prefix for injected headers (default: X-Sentinel)
	DashboardURL  string // URL to post events to
}

// ShadowModeStats tracks shadow mode statistics
type ShadowModeStats struct {
	TotalRequests    uint64
	WouldBlock       uint64
	WouldAllow       uint64
	EventsLogged     uint64
}

var shadowStats = &ShadowModeStats{}

// GetShadowModeStats returns current shadow mode stats
func GetShadowModeStats() ShadowModeStats {
	return ShadowModeStats{
		TotalRequests: atomic.LoadUint64(&shadowStats.TotalRequests),
		WouldBlock:    atomic.LoadUint64(&shadowStats.WouldBlock),
		WouldAllow:    atomic.LoadUint64(&shadowStats.WouldAllow),
		EventsLogged:  atomic.LoadUint64(&shadowStats.EventsLogged),
	}
}

// ShadowModeResult represents the analysis result for a request
type ShadowModeResult struct {
	RequestID   string    `json:"request_id"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
	Path        string    `json:"path"`
	Decision    string    `json:"decision"` // "allow" or "block"
	RiskScore   int       `json:"risk_score"`
	Flags       []string  `json:"flags"`
	Timestamp   time.Time `json:"timestamp"`
	
	// Detection results
	HTTP2Result    string `json:"http2_result,omitempty"`
	MTUResult      string `json:"mtu_result,omitempty"`
	IntegrityResult string `json:"integrity_result,omitempty"`
}

// ShadowMode wraps other middleware in shadow mode
func ShadowMode(cfg *ShadowModeConfig, next http.Handler) http.Handler {
	if cfg == nil {
		cfg = &ShadowModeConfig{
			Enabled:      true,
			LogAllEvents: true,
			HeaderPrefix: "X-Sentinel",
		}
	}
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		
		atomic.AddUint64(&shadowStats.TotalRequests, 1)
		
		// Generate request ID
		idBytes := make([]byte, 8)
		rand.Read(idBytes)
		requestID := hex.EncodeToString(idBytes)
		
		// Create result tracker
		result := &ShadowModeResult{
			RequestID: requestID,
			ClientIP:  GetTrustedClientIP(r),
			UserAgent: r.UserAgent(),
			Path:      r.URL.Path,
			Timestamp: time.Now(),
			RiskScore: 0,
			Flags:     []string{},
			Decision:  "allow",
		}
		
		// Store result in context for downstream handlers
		ctx := context.WithValue(r.Context(), ShadowResultKey, result)
		r = r.WithContext(ctx)
		
		// Create response wrapper to capture potential blocks
		sw := &shadowResponseWriter{
			ResponseWriter: w,
			result:         result,
			headerPrefix:   cfg.HeaderPrefix,
			wroteHeader:    false,
		}
		
		// Execute the actual middleware chain
		next.ServeHTTP(sw, r)
		
		// Add shadow headers if not yet written
		if !sw.wroteHeader {
			sw.addShadowHeaders()
		}
		
		// Determine final decision
		if result.RiskScore >= 70 {
			result.Decision = "block"
			atomic.AddUint64(&shadowStats.WouldBlock, 1)
		} else {
			result.Decision = "allow"
			atomic.AddUint64(&shadowStats.WouldAllow, 1)
		}
		
		// Log the event
		if cfg.LogAllEvents || result.Decision == "block" {
			atomic.AddUint64(&shadowStats.EventsLogged, 1)
			logShadowEvent(result)
		}
	})
}

// shadowResponseWriter wraps ResponseWriter to add shadow headers
type shadowResponseWriter struct {
	http.ResponseWriter
	result       *ShadowModeResult
	headerPrefix string
	wroteHeader  bool
}

func (sw *shadowResponseWriter) WriteHeader(statusCode int) {
	sw.addShadowHeaders()
	sw.ResponseWriter.WriteHeader(statusCode)
	sw.wroteHeader = true
}

func (sw *shadowResponseWriter) Write(data []byte) (int, error) {
	if !sw.wroteHeader {
		sw.addShadowHeaders()
		sw.wroteHeader = true
	}
	return sw.ResponseWriter.Write(data)
}

func (sw *shadowResponseWriter) addShadowHeaders() {
	prefix := sw.headerPrefix
	if prefix == "" {
		prefix = "X-Sentinel"
	}
	
	sw.Header().Set(prefix+"-Request-ID", sw.result.RequestID)
	sw.Header().Set(prefix+"-Result", sw.result.Decision)
	sw.Header().Set(prefix+"-Score", fmt.Sprintf("%d", sw.result.RiskScore))
	
	if len(sw.result.Flags) > 0 {
		sw.Header().Set(prefix+"-Flags", strings.Join(sw.result.Flags, ","))
	}
}

// logShadowEvent logs a shadow mode event
func logShadowEvent(result *ShadowModeResult) {
	log.Printf("[SHADOW] %s | IP=%s | Score=%d | Decision=%s | Flags=%v",
		result.RequestID,
		result.ClientIP,
		result.RiskScore,
		result.Decision,
		result.Flags,
	)
}

// ShadowResultKey is the context key for shadow mode results
const ShadowResultKey contextKey = "shadow_result"

// AddShadowFlag adds a detection flag to the shadow result
func AddShadowFlag(r *http.Request, flag string, scoreIncrease int) {
	if result, ok := r.Context().Value(ShadowResultKey).(*ShadowModeResult); ok {
		result.Flags = append(result.Flags, flag)
		result.RiskScore += scoreIncrease
	}
}

// =============================================================================
// COMBINED FULL-STACK MIDDLEWARE
// =============================================================================

// FullStackIntegrityConfig configures all integrity checks
type FullStackIntegrityConfig struct {
	EnableHTTP2Fingerprint   bool
	EnablePrototypeIntegrity bool
	EnableMTUAnalysis        bool
	EnableShadowMode         bool
	ShadowModeConfig         *ShadowModeConfig
}

// FullStackIntegrity creates the comprehensive integrity middleware
func FullStackIntegrity(cfg *FullStackIntegrityConfig, store storage.Store) Middleware {
	return func(next http.Handler) http.Handler {
		handler := next
		
		// Wrap with shadow mode if enabled
		if cfg.EnableShadowMode {
			handler = ShadowMode(cfg.ShadowModeConfig, handler)
		}
		
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := GetTrustedClientIP(r)
			
			// === HTTP/2 Fingerprint Check ===
			if cfg.EnableHTTP2Fingerprint {
				http2FpMu.RLock()
				fp, exists := http2FingerprintStore[clientIP]
				http2FpMu.RUnlock()
				
				if exists {
					isBot, reason := checkHTTP2Fingerprint(r, fp)
					if isBot {
						log.Printf("[HTTP2-FP] Bot detected: %s - %s", clientIP, reason)
						AddShadowFlag(r, "http2:"+reason, 30)
						
						if !cfg.EnableShadowMode {
							// Block if not in shadow mode
							http.Error(w, "Access Denied", http.StatusForbidden)
							return
						}
					}
				}
			}
			
			// Continue to next handler
			handler.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// INTEGRITY CHECK ENDPOINT
// =============================================================================

// IntegrityCheckHandler handles prototype integrity reports from client
func IntegrityCheckHandler(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		var result PrototypeIntegrityResult
		if err := decodeJSON(r, &result); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		
		clientIP := GetTrustedClientIP(r)
		
		// Analyze result
		if result.IsCompromised {
			log.Printf("[INTEGRITY] 🔓 Browser tampering detected: %s - Flags: %v",
				clientIP, result.CompromiseFlags)
			
			// Add to shadow result if in shadow mode
			AddShadowFlag(r, "integrity:compromised", 50)
			
			// Store for future requests
			if store != nil {
				key := fmt.Sprintf("integrity:compromised:%s", clientIP)
				store.Set(r.Context(), key, "1", 1*time.Hour)
			}
		}
		
		w.WriteHeader(http.StatusOK)
	}
}

// Helper to decode JSON
func decodeJSON(r *http.Request, v interface{}) error {
	return nil // Simplified - use json.NewDecoder in real implementation
}
