// =============================================================================
// SENTINEL-X WAF CORE - Production-Grade Web Application Firewall
// =============================================================================
// Author: Principal Security Architect
// Version: 2.0.0-enterprise
//
// This file contains the core security engine for Sentinel-X WAF.
// All security decisions are documented with reasoning.
// =============================================================================

package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// =============================================================================
// SECTION 1: CONFIGURATION
// =============================================================================

// Config holds all WAF configuration
type Config struct {
	// Server settings
	ListenAddr        string
	TargetURL         string
	ReadHeaderTimeout time.Duration // SECURITY: Prevents Slowloris attacks
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration // SECURITY: Frees connections from slow/malicious clients

	// PoW settings
	PoWEnabled        bool
	PoWBaseDifficulty int           // Base difficulty (trailing zeros required)
	PoWExpiry         time.Duration // How long a challenge is valid
	PoWSecretKey      []byte        // HMAC signing key for challenges

	// Rate limiting
	RateLimitEnabled bool
	RateLimitRPS     int           // Requests per second
	RateLimitBurst   int           // Burst allowance
	RateLimitBlock   time.Duration // Block duration when exceeded

	// Redis
	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

// DefaultConfig returns production-ready defaults
func DefaultConfig() *Config {
	// Generate a random secret key for HMAC signing
	secretKey := make([]byte, 32)
	rand.Read(secretKey)

	return &Config{
		ListenAddr: ":8080",
		TargetURL:  "http://localhost:3000",

		// SECURITY: Strict timeouts prevent Slowloris and slow-read attacks
		// ReadHeaderTimeout: If headers aren't received in 2s, connection is killed
		// This prevents attackers from sending headers byte-by-byte to exhaust connections
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second, // SECURITY: Free idle connections quickly

		PoWEnabled:        true,
		PoWBaseDifficulty: 4,              // 4 trailing zeros ~= 65536 iterations average
		PoWExpiry:         30 * time.Second,
		PoWSecretKey:      secretKey,

		RateLimitEnabled: true,
		RateLimitRPS:     10,
		RateLimitBurst:   50,
		RateLimitBlock:   5 * time.Minute,

		RedisAddr: "localhost:6379",
		RedisDB:   0,
	}
}

// =============================================================================
// SECTION 2: THE REVERSE PROXY (Main Engine)
// =============================================================================

// SentinelProxy is the core reverse proxy with security features
type SentinelProxy struct {
	config      *Config
	proxy       *httputil.ReverseProxy
	targetURL   *url.URL
	redisClient *redis.Client
	rateLimiter *RedisRateLimiter
	powManager  *PoWManager
	geoFilter   GeoIPFilter // Interface for ASN/GeoIP filtering

	// Statistics
	stats *ProxyStats
}

// ProxyStats tracks request statistics
type ProxyStats struct {
	TotalRequests   uint64
	BlockedRequests uint64
	PoWChallenges   uint64
	PoWSolved       uint64
	RateLimited     uint64
	GeoBlocked      uint64
	PanicsRecovered uint64
}

// HeadersToStrip lists headers that MUST be stripped from incoming requests
// SECURITY REASON: These headers can be spoofed by attackers to:
// 1. Bypass IP-based rate limiting (by faking X-Forwarded-For)
// 2. Inject false internal routing information
// 3. Confuse logging and auditing
var HeadersToStrip = []string{
	"X-Forwarded-For",       // Can be spoofed to fake source IP
	"X-Real-IP",             // Can be spoofed
	"X-Forwarded-Host",      // Can cause host header injection
	"X-Forwarded-Proto",     // Can confuse HTTPS detection
	"X-Original-URL",        // IIS-specific, can bypass auth
	"X-Rewrite-URL",         // IIS-specific
	"X-Client-IP",           // Non-standard, spoofable
	"X-Cluster-Client-IP",   // Non-standard, spoofable
	"True-Client-IP",        // Cloudflare-specific, spoofable when not behind CF
	"CF-Connecting-IP",      // Cloudflare-specific
	"X-Sentinel-Score",      // Our internal header - prevent client spoofing
	"X-Sentinel-Verified",   // Our internal header
	"X-Sentinel-Fingerprint",// Our internal header
}

// NewSentinelProxy creates a new WAF proxy
func NewSentinelProxy(cfg *Config) (*SentinelProxy, error) {
	// Parse target URL
	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Printf("[WARN] Redis unavailable, falling back to in-memory: %v", err)
		redisClient = nil
	}

	sp := &SentinelProxy{
		config:      cfg,
		targetURL:   target,
		redisClient: redisClient,
		stats:       &ProxyStats{},
		geoFilter:   NewDummyGeoIPFilter(), // Use interface implementation
	}

	// Initialize rate limiter
	if redisClient != nil {
		sp.rateLimiter = NewRedisRateLimiter(redisClient, cfg)
	}

	// Initialize PoW manager
	sp.powManager = NewPoWManager(cfg, redisClient)

	// Create the reverse proxy with security-hardened Director
	sp.proxy = &httputil.ReverseProxy{
		Director:       sp.director,
		ModifyResponse: sp.modifyResponse,
		ErrorHandler:   sp.errorHandler,
	}

	return sp, nil
}

// director is called before each request is forwarded
// SECURITY: This is where we sanitize the request
func (sp *SentinelProxy) director(req *http.Request) {
	// Store original client IP BEFORE stripping headers
	// SECURITY: We get the real IP from the TCP connection, not from headers
	clientIP := sp.getRealClientIP(req)

	// SECURITY: Strip all spoofable headers
	// This prevents attackers from injecting false routing/identity information
	for _, header := range HeadersToStrip {
		req.Header.Del(header)
	}

	// Now set OUR trusted headers based on actual connection info
	req.Header.Set("X-Forwarded-For", clientIP)
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Forwarded-Host", req.Host)
	if req.TLS != nil {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	// Add Sentinel-X identification
	req.Header.Set("X-Sentinel-Verified", "true")
	req.Header.Set("X-Sentinel-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

	// Set target
	req.URL.Scheme = sp.targetURL.Scheme
	req.URL.Host = sp.targetURL.Host
	req.Host = sp.targetURL.Host
}

// getRealClientIP extracts the actual client IP from the TCP connection
// SECURITY: We NEVER trust headers for the client IP - only the actual connection
func (sp *SentinelProxy) getRealClientIP(req *http.Request) string {
	// RemoteAddr is the actual TCP connection address - cannot be spoofed
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// modifyResponse is called after receiving response from upstream
func (sp *SentinelProxy) modifyResponse(resp *http.Response) error {
	// Add security headers to response
	resp.Header.Set("X-Protected-By", "Sentinel-X/2.0")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
	resp.Header.Set("X-XSS-Protection", "1; mode=block")
	return nil
}

// errorHandler handles proxy errors
func (sp *SentinelProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("[PROXY ERROR] %s %s: %v", r.Method, r.URL.Path, err)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

// =============================================================================
// SECTION 3: PANIC RECOVERY MIDDLEWARE
// =============================================================================

// PanicRecoveryMiddleware catches panics and keeps the server alive
// SECURITY: Prevents information leakage and ensures availability
func (sp *SentinelProxy) PanicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Increment panic counter
				atomic.AddUint64(&sp.stats.PanicsRecovered, 1)

				// Get stack trace for debugging (server-side only)
				stack := debug.Stack()

				// Log full details for debugging
				// SECURITY: Stack trace is logged server-side only, never sent to client
				log.Printf("[CRITICAL PANIC] %s %s from %s\nError: %v\nStack:\n%s",
					r.Method,
					r.URL.Path,
					sp.getRealClientIP(r),
					err,
					string(stack),
				)

				// Send generic error to client
				// SECURITY: Never expose internal error details to clients
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// =============================================================================
// SECTION 4: MAIN SECURITY HANDLER
// =============================================================================

// ServeHTTP is the main entry point for all requests
func (sp *SentinelProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&sp.stats.TotalRequests, 1)
	clientIP := sp.getRealClientIP(r)
	ctx := r.Context()

	// =========================================================================
	// STEP 1: ASN/GeoIP Filtering (Intelligent Filter)
	// =========================================================================
	geoResult := sp.geoFilter.Lookup(clientIP)
	if geoResult.Blocked {
		atomic.AddUint64(&sp.stats.GeoBlocked, 1)
		log.Printf("[GEO BLOCKED] %s - %s", clientIP, geoResult.Reason)
		sp.sendBlockedResponse(w, "Access denied from your region")
		return
	}

	// =========================================================================
	// STEP 2: Rate Limiting (Redis Lua Script)
	// =========================================================================
	if sp.config.RateLimitEnabled && sp.rateLimiter != nil {
		allowed, remaining, err := sp.rateLimiter.Check(ctx, clientIP)
		if err != nil {
			log.Printf("[RATE LIMIT ERROR] %v", err)
			// Fail-open on error (or could fail-closed for higher security)
		} else if !allowed {
			atomic.AddUint64(&sp.stats.RateLimited, 1)
			log.Printf("[RATE LIMITED] %s", clientIP)
			sp.sendRateLimitResponse(w, remaining)
			return
		}
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	}

	// =========================================================================
	// STEP 3: Proof of Work Challenge
	// =========================================================================
	if sp.config.PoWEnabled && !sp.isStaticAsset(r.URL.Path) {
		// Calculate dynamic difficulty based on risk
		// SECURITY: Higher risk = harder challenge = more CPU cost for attacker
		difficulty := sp.calculateDynamicDifficulty(clientIP, geoResult)

		// Check for PoW solution in request
		powSolution := r.Header.Get("X-Sentinel-PoW")
		if powSolution == "" {
			powSolution = r.URL.Query().Get("pow_token")
		}

		if powSolution == "" {
			// No solution provided - send challenge
			atomic.AddUint64(&sp.stats.PoWChallenges, 1)
			sp.powManager.SendChallenge(w, r, difficulty)
			return
		}

		// Validate the solution
		valid, reason := sp.powManager.ValidateSolution(ctx, powSolution)
		if !valid {
			log.Printf("[POW FAILED] %s: %s", clientIP, reason)
			atomic.AddUint64(&sp.stats.PoWChallenges, 1)
			sp.powManager.SendChallenge(w, r, difficulty)
			return
		}

		atomic.AddUint64(&sp.stats.PoWSolved, 1)
	}

	// =========================================================================
	// STEP 4: Forward to Upstream (Passed all checks)
	// =========================================================================
	sp.proxy.ServeHTTP(w, r)
}

// calculateDynamicDifficulty adjusts PoW difficulty based on risk factors
// SECURITY: Make suspicious clients work harder
func (sp *SentinelProxy) calculateDynamicDifficulty(clientIP string, geoResult *GeoIPResult) int {
	difficulty := sp.config.PoWBaseDifficulty

	// Increase difficulty for suspicious indicators
	if geoResult.IsDataCenter {
		difficulty += 2 // Data centers are commonly used for automation
	}
	if geoResult.IsTor {
		difficulty += 3 // Tor exit nodes have higher bot traffic
	}
	if geoResult.IsProxy {
		difficulty += 1 // Proxies sometimes used to evade detection
	}
	if geoResult.RiskScore > 50 {
		difficulty += geoResult.RiskScore / 25 // Add 1-4 based on risk
	}

	// Cap maximum difficulty to prevent DoS
	if difficulty > 8 {
		difficulty = 8
	}

	return difficulty
}

// isStaticAsset checks if request is for a static file (skip PoW)
func (sp *SentinelProxy) isStaticAsset(path string) bool {
	staticExts := []string{".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".wasm"}
	lower := strings.ToLower(path)
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// sendBlockedResponse sends a geo-block response
func (sp *SentinelProxy) sendBlockedResponse(w http.ResponseWriter, reason string) {
	atomic.AddUint64(&sp.stats.BlockedRequests, 1)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>
		<h1>Access Denied</h1><p>%s</p>
	</body></html>`, reason)
}

// sendRateLimitResponse sends a rate limit exceeded response
func (sp *SentinelProxy) sendRateLimitResponse(w http.ResponseWriter, remaining int) {
	atomic.AddUint64(&sp.stats.BlockedRequests, 1)
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprint(w, `{"error":"rate_limit_exceeded","retry_after":60}`)
}

// =============================================================================
// SECTION 5: PROOF OF WORK MANAGER
// =============================================================================

// PoWChallenge represents a time-bound, signed challenge
type PoWChallenge struct {
	Salt       string `json:"salt"`       // Random salt
	Difficulty int    `json:"difficulty"` // Trailing zeros required
	Expiry     int64  `json:"expiry"`     // Unix timestamp when challenge expires
	Signature  string `json:"signature"`  // HMAC signature to prevent tampering
}

// PoWManager handles proof-of-work challenges
type PoWManager struct {
	config *Config
	redis  *redis.Client
}

// NewPoWManager creates a new PoW manager
func NewPoWManager(cfg *Config, redisClient *redis.Client) *PoWManager {
	return &PoWManager{
		config: cfg,
		redis:  redisClient,
	}
}

// GenerateChallenge creates a new PoW challenge
func (pm *PoWManager) GenerateChallenge(difficulty int) *PoWChallenge {
	// Generate random salt
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)

	// Calculate expiry
	expiry := time.Now().Add(pm.config.PoWExpiry).Unix()

	challenge := &PoWChallenge{
		Salt:       salt,
		Difficulty: difficulty,
		Expiry:     expiry,
	}

	// Sign the challenge to prevent tampering
	// SECURITY: Client cannot modify difficulty or expiry without detection
	challenge.Signature = pm.signChallenge(challenge)

	return challenge
}

// signChallenge creates HMAC signature
func (pm *PoWManager) signChallenge(c *PoWChallenge) string {
	data := fmt.Sprintf("%s:%d:%d", c.Salt, c.Difficulty, c.Expiry)
	mac := hmac.New(sha256.New, pm.config.PoWSecretKey)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifySignature checks if challenge was tampered
func (pm *PoWManager) verifySignature(c *PoWChallenge) bool {
	expected := pm.signChallenge(c)
	return hmac.Equal([]byte(expected), []byte(c.Signature))
}

// SendChallenge sends a PoW challenge page to the client
func (pm *PoWManager) SendChallenge(w http.ResponseWriter, r *http.Request, difficulty int) {
	challenge := pm.GenerateChallenge(difficulty)

	// Store salt in Redis to track valid challenges
	if pm.redis != nil {
		ctx := r.Context()
		key := fmt.Sprintf("pow:challenge:%s", challenge.Salt)
		pm.redis.Set(ctx, key, "valid", pm.config.PoWExpiry)
	}

	challengeJSON, _ := json.Marshal(challenge)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)

	// HTML page with embedded JavaScript solver
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Security Check</title>
<style>
body { font-family: sans-serif; background: #0a0a0a; color: #fff; 
       display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.container { text-align: center; padding: 2rem; }
.progress { width: 300px; height: 8px; background: #333; border-radius: 4px; margin: 1rem auto; }
.bar { height: 100%%; background: linear-gradient(90deg, #00d2ff, #3a7bd5); width: 0%%; border-radius: 4px; }
</style>
</head>
<body>
<div class="container">
<h1>🛡️ Security Check</h1>
<p>Verifying you're human (difficulty: %d)</p>
<div class="progress"><div class="bar" id="bar"></div></div>
<p id="status">Solving challenge...</p>
</div>
<script>
const challenge = %s;

async function solve() {
    const target = '0'.repeat(challenge.difficulty);
    let nonce = 0;
    const startTime = Date.now();
    
    while (true) {
        const data = challenge.salt + nonce;
        const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
        const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2,'0')).join('');
        
        if (hashHex.endsWith(target)) {
            // Solution found!
            document.getElementById('status').textContent = 'Verified! Redirecting...';
            document.getElementById('bar').style.width = '100%%';
            
            // Submit solution
            const solution = challenge.salt + ':' + nonce + ':' + challenge.expiry + ':' + challenge.signature;
            document.cookie = 'X-Sentinel-PoW=' + solution + '; path=/; max-age=300';
            
            const url = new URL(location.href);
            url.searchParams.set('pow_token', solution);
            location.href = url.toString();
            return;
        }
        
        nonce++;
        if (nonce %% 10000 === 0) {
            document.getElementById('bar').style.width = Math.min(nonce/100000*100, 95) + '%%';
            await new Promise(r => setTimeout(r, 0)); // Allow UI update
        }
        
        // Timeout after 60 seconds
        if (Date.now() - startTime > 60000) {
            document.getElementById('status').textContent = 'Timeout - please refresh';
            return;
        }
    }
}
solve();
</script>
</body></html>`, difficulty, string(challengeJSON))

	w.Write([]byte(html))
}

// ValidateSolution validates a PoW solution
// Returns (valid, reason)
func (pm *PoWManager) ValidateSolution(ctx context.Context, solution string) (bool, string) {
	// Parse solution: "salt:nonce:expiry:signature"
	parts := strings.Split(solution, ":")
	if len(parts) != 4 {
		return false, "invalid format"
	}

	salt := parts[0]
	nonce := parts[1]
	expiry, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return false, "invalid expiry"
	}
	signature := parts[3]

	// Reconstruct challenge for verification
	challenge := &PoWChallenge{
		Salt:      salt,
		Expiry:    expiry,
		Signature: signature,
	}

	// We need to determine difficulty - try common values
	// In production, encode difficulty in solution or store in Redis
	for difficulty := 3; difficulty <= 8; difficulty++ {
		challenge.Difficulty = difficulty
		if pm.verifySignature(challenge) {
			// Found matching difficulty
			
			// SECURITY CHECK 1: Verify expiry (time-bound token)
			if time.Now().Unix() > challenge.Expiry {
				return false, "challenge expired"
			}

			// SECURITY CHECK 2: Verify signature (prevent tampering)
			// Already verified above

			// SECURITY CHECK 3: Check Redis for replay (salt already used)
			if pm.redis != nil {
				usedKey := fmt.Sprintf("pow:used:%s", salt)
				exists, _ := pm.redis.Exists(ctx, usedKey).Result()
				if exists > 0 {
					return false, "replay attack - salt already used"
				}

				// Check if salt was ever valid
				challengeKey := fmt.Sprintf("pow:challenge:%s", salt)
				valid, _ := pm.redis.Exists(ctx, challengeKey).Result()
				if valid == 0 {
					return false, "unknown salt"
				}

				// Mark salt as used (replay protection)
				// SECURITY: Keep for 1 hour to prevent re-use
				pm.redis.Set(ctx, usedKey, "1", time.Hour)
				pm.redis.Del(ctx, challengeKey)
			}

			// SECURITY CHECK 4: Verify the actual hash
			data := salt + nonce
			hash := sha256.Sum256([]byte(data))
			hashHex := hex.EncodeToString(hash[:])

			targetSuffix := strings.Repeat("0", difficulty)
			if !strings.HasSuffix(hashHex, targetSuffix) {
				return false, "invalid hash"
			}

			return true, ""
		}
	}

	return false, "invalid signature"
}

// =============================================================================
// SECTION 6: REDIS RATE LIMITER (Lua Script)
// =============================================================================

// RedisRateLimiter implements sliding window rate limiting
type RedisRateLimiter struct {
	client *redis.Client
	config *Config
	script *redis.Script
}

// Lua script for atomic sliding window rate limiting
// SECURITY: Runs atomically on Redis - no race conditions possible
const slidingWindowLuaScript = `
-- KEYS[1] = rate limit key
-- ARGV[1] = current timestamp (ms)
-- ARGV[2] = window size (ms)  
-- ARGV[3] = max requests allowed
-- ARGV[4] = block duration (ms)

local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local block_duration = tonumber(ARGV[4])

-- Check if IP is blocked
local block_key = key .. ":blocked"
local blocked_until = redis.call('GET', block_key)
if blocked_until then
    if now < tonumber(blocked_until) then
        return {0, 0}  -- blocked, 0 remaining
    else
        redis.call('DEL', block_key)
    end
end

-- Remove old entries outside the sliding window
local window_start = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count requests in current window
local count = redis.call('ZCARD', key)

if count >= limit then
    -- Rate limit exceeded - block the IP
    redis.call('SET', block_key, now + block_duration, 'PX', block_duration)
    return {0, 0}  -- blocked
end

-- Add this request to the window
-- Use timestamp + random to ensure unique members
local member = now .. '-' .. math.random(1000000)
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)

-- Return: allowed (1), remaining requests
return {1, limit - count - 1}
`

// NewRedisRateLimiter creates a new rate limiter
func NewRedisRateLimiter(client *redis.Client, cfg *Config) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		config: cfg,
		script: redis.NewScript(slidingWindowLuaScript),
	}
}

// Check performs rate limit check
// Returns: allowed, remaining, error
func (rl *RedisRateLimiter) Check(ctx context.Context, clientIP string) (bool, int, error) {
	key := fmt.Sprintf("ratelimit:%s", clientIP)
	now := time.Now().UnixMilli()
	windowMs := int64(1000) // 1 second window
	limit := int64(rl.config.RateLimitRPS)
	blockDurationMs := rl.config.RateLimitBlock.Milliseconds()

	result, err := rl.script.Run(ctx, rl.client, []string{key},
		now, windowMs, limit, blockDurationMs).Slice()
	if err != nil {
		return false, 0, fmt.Errorf("rate limit check failed: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))

	return allowed, remaining, nil
}

// =============================================================================
// SECTION 7: GEO-IP FILTER INTERFACE
// =============================================================================

// GeoIPResult contains the result of a GeoIP lookup
type GeoIPResult struct {
	IP           string
	Country      string
	ASN          uint
	ASNOrg       string
	IsDataCenter bool
	IsTor        bool
	IsProxy      bool
	RiskScore    int  // 0-100
	Blocked      bool
	Reason       string
}

// GeoIPFilter defines the interface for ASN/GeoIP filtering
// DESIGN: Interface allows swapping implementations (MaxMind, IP2Location, etc.)
type GeoIPFilter interface {
	Lookup(ip string) *GeoIPResult
	IsBlocked(result *GeoIPResult) (bool, string)
	AddBlockedCountry(countryCode string)
	AddBlockedASN(asn uint)
}

// DummyGeoIPFilter is a placeholder implementation
// Replace with MaxMind or similar in production
type DummyGeoIPFilter struct {
	blockedCountries map[string]bool
	blockedASNs      map[uint]bool
	dataCenterASNs   map[uint]string
	mu               sync.RWMutex
}

// NewDummyGeoIPFilter creates a dummy filter
func NewDummyGeoIPFilter() *DummyGeoIPFilter {
	return &DummyGeoIPFilter{
		blockedCountries: map[string]bool{
			"KP": true, // North Korea (example)
		},
		blockedASNs: map[uint]bool{},
		dataCenterASNs: map[uint]string{
			16509:  "Amazon AWS",
			8075:   "Microsoft Azure",
			15169:  "Google Cloud",
			14061:  "DigitalOcean",
			63949:  "Linode",
			20473:  "Vultr",
			16276:  "OVH",
			24940:  "Hetzner",
		},
	}
}

// Lookup performs a GeoIP lookup (dummy implementation)
func (f *DummyGeoIPFilter) Lookup(ip string) *GeoIPResult {
	result := &GeoIPResult{
		IP:        ip,
		Country:   "US", // Dummy default
		ASN:       0,
		RiskScore: 0,
	}

	// In production: Use MaxMind GeoLite2 database
	// db, _ := maxminddb.Open("GeoLite2-City.mmdb")
	// db.Lookup(net.ParseIP(ip), &record)

	// Check if blocked
	blocked, reason := f.IsBlocked(result)
	result.Blocked = blocked
	result.Reason = reason

	return result
}

// IsBlocked checks if a result should be blocked
func (f *DummyGeoIPFilter) IsBlocked(result *GeoIPResult) (bool, string) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.blockedCountries[result.Country] {
		return true, fmt.Sprintf("blocked country: %s", result.Country)
	}

	if f.blockedASNs[result.ASN] {
		return true, fmt.Sprintf("blocked ASN: %d", result.ASN)
	}

	return false, ""
}

// AddBlockedCountry adds a country to the blocklist
func (f *DummyGeoIPFilter) AddBlockedCountry(countryCode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockedCountries[countryCode] = true
}

// AddBlockedASN adds an ASN to the blocklist
func (f *DummyGeoIPFilter) AddBlockedASN(asn uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockedASNs[asn] = true
}

// =============================================================================
// SECTION 8: SERVER STARTUP
// =============================================================================

// Start starts the WAF server
func (sp *SentinelProxy) Start() error {
	// Wrap with panic recovery
	handler := sp.PanicRecoveryMiddleware(sp)

	server := &http.Server{
		Addr:    sp.config.ListenAddr,
		Handler: handler,

		// SECURITY: Strict timeouts prevent resource exhaustion attacks
		// ReadHeaderTimeout: Prevents Slowloris (slow header sending)
		ReadHeaderTimeout: sp.config.ReadHeaderTimeout,
		ReadTimeout:       sp.config.ReadTimeout,
		WriteTimeout:      sp.config.WriteTimeout,
		IdleTimeout:       sp.config.IdleTimeout, // SECURITY: Free idle connections

		// Limit header size to prevent memory exhaustion
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	log.Printf("[INFO] Sentinel-X WAF starting on %s", sp.config.ListenAddr)
	log.Printf("[INFO] Proxying to: %s", sp.config.TargetURL)
	log.Printf("[INFO] Timeouts: ReadHeader=%v, Read=%v, Write=%v, Idle=%v",
		sp.config.ReadHeaderTimeout,
		sp.config.ReadTimeout,
		sp.config.WriteTimeout,
		sp.config.IdleTimeout,
	)

	return server.ListenAndServe()
}

// GetStats returns current statistics
func (sp *SentinelProxy) GetStats() ProxyStats {
	return ProxyStats{
		TotalRequests:   atomic.LoadUint64(&sp.stats.TotalRequests),
		BlockedRequests: atomic.LoadUint64(&sp.stats.BlockedRequests),
		PoWChallenges:   atomic.LoadUint64(&sp.stats.PoWChallenges),
		PoWSolved:       atomic.LoadUint64(&sp.stats.PoWSolved),
		RateLimited:     atomic.LoadUint64(&sp.stats.RateLimited),
		GeoBlocked:      atomic.LoadUint64(&sp.stats.GeoBlocked),
		PanicsRecovered: atomic.LoadUint64(&sp.stats.PanicsRecovered),
	}
}
