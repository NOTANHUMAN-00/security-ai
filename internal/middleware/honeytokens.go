// =============================================================================
// ACTIVE BETRAYAL: Inject poison pills that only bots will swallow
//
// Concept: Instead of passively detecting bots, we TRICK them into revealing
//          themselves by planting irresistible "bait" that real browsers ignore.
//
// The Poison Cookies:
//   - Set cookies like "admin_session_id" or "debug_mode=true"
//   - Make them HttpOnly: false (so bots can read them)
//   - Hide references in meta tags, comments, or display:none elements
//   - Real browsers/users won't touch them
//   - Bots scraping the page WILL try to use them
//
// The Trigger:
//   - Any request that comes back WITH these specific cookies = PERMANENT BAN
//   - The bot identified itself by falling for our trap
//
// Honey-Token Types:
//   1. Poison Cookies: Fake admin/debug cookies
//   2. Hidden Links: Invisible links only bots follow
//   3. Fake API Endpoints: /api/internal/debug that returns "sensitive" data
//   4. Meta Tag Traps: Fake tokens in HTML comments/meta tags
//   5. Form Field Traps: Auto-fill fields that capture bot activity
//
// =============================================================================
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// =============================================================================
// HONEY-TOKEN CONFIGURATION
// =============================================================================

// HoneyToken represents a planted bait token
type HoneyToken struct {
	Name      string    // Cookie/parameter name
	Value     string    // Token value
	Type      string    // "cookie", "link", "api", "form"
	PlantedAt time.Time // When it was planted
	ClientIP  string    // Who received it
}

// HoneyTokenStats tracks honey token statistics
type HoneyTokenStats struct {
	TokensPlanted   uint64
	TokensTriggered uint64
	BotsCaught      uint64
	UniqueIPsCaught uint64
}

var globalHoneyStats = &HoneyTokenStats{}
var honeyCaughtIPs = make(map[string]time.Time)
var honeyCaughtMu sync.RWMutex

// GetHoneyTokenStats returns current stats
func GetHoneyTokenStats() HoneyTokenStats {
	honeyCaughtMu.RLock()
	uniqueIPs := len(honeyCaughtIPs)
	honeyCaughtMu.RUnlock()

	return HoneyTokenStats{
		TokensPlanted:   atomic.LoadUint64(&globalHoneyStats.TokensPlanted),
		TokensTriggered: atomic.LoadUint64(&globalHoneyStats.TokensTriggered),
		BotsCaught:      atomic.LoadUint64(&globalHoneyStats.BotsCaught),
		UniqueIPsCaught: uint64(uniqueIPs),
	}
}

// =============================================================================
// POISON COOKIE NAMES - These look irresistible to bots
// =============================================================================

var PoisonCookieNames = []string{
	"admin_session_id",
	"debug_mode",
	"internal_auth",
	"staff_token",
	"bypass_captcha",
	"super_user",
	"dev_access",
	"api_key_internal",
	"admin_bypass",
	"test_mode",
}

var PoisonParameterNames = []string{
	"api_key",
	"secret_token",
	"admin_key",
	"debug_password",
	"bypass_auth",
}

// =============================================================================
// HONEY-TOKEN MIDDLEWARE
// =============================================================================

// HoneyTokenMiddleware implements the active betrayal system
type HoneyTokenMiddleware struct {
	config         *config.Config
	store          storage.Store
	activeTokens   map[string]*HoneyToken // token value -> token info
	tokenMu        sync.RWMutex
	permanentBans  map[string]time.Time // IPs permanently banned
	banMu          sync.RWMutex
}

// HoneyTokens creates the honey-token middleware
func HoneyTokens(cfg *config.Config, store storage.Store) Middleware {
	htm := &HoneyTokenMiddleware{
		config:        cfg,
		store:         store,
		activeTokens:  make(map[string]*HoneyToken),
		permanentBans: make(map[string]time.Time),
	}

	// Start cleanup goroutine
	go htm.cleanupOldTokens()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := GetTrustedClientIP(r)

			// Check if this IP is permanently banned
			if htm.isPermaBanned(clientIP) {
				log.Printf("[HONEYTRAP] 🍯 Blocked permanently banned bot: %s", clientIP)
				http.Error(w, "Access Denied", http.StatusForbidden)
				return
			}

			// Check for poison cookies/parameters in request (THE TRIGGER)
			if htm.checkForPoisonTokens(r) {
				// BOT CAUGHT! They used our poison token!
				atomic.AddUint64(&globalHoneyStats.TokensTriggered, 1)
				atomic.AddUint64(&globalHoneyStats.BotsCaught, 1)

				// Permanent ban
				htm.permanentBan(clientIP)

				log.Printf("[HONEYTRAP] 🍯🚨 BOT CAUGHT! IP: %s used a poison token - PERMANENTLY BANNED", clientIP)

				// Return a fake "success" to waste their time
				htm.sendFakeSuccess(w)
				return
			}

			// Wrap response to inject honey tokens
			hw := &honeyTokenResponseWriter{
				ResponseWriter: w,
				htm:            htm,
				clientIP:       clientIP,
				headerWritten:  false,
			}

			next.ServeHTTP(hw, r)
		})
	}
}

// checkForPoisonTokens checks if the request contains any of our poison tokens
func (htm *HoneyTokenMiddleware) checkForPoisonTokens(r *http.Request) bool {
	// Check cookies
	for _, name := range PoisonCookieNames {
		if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
			// Verify this was actually one of our tokens
			htm.tokenMu.RLock()
			_, exists := htm.activeTokens[cookie.Value]
			htm.tokenMu.RUnlock()

			if exists {
				log.Printf("[HONEYTRAP] Poison cookie triggered: %s=%s", name, cookie.Value)
				return true
			}

			// Even if not our exact token, using these cookie names is suspicious
			return true
		}
	}

	// Check query parameters
	for _, name := range PoisonParameterNames {
		if value := r.URL.Query().Get(name); value != "" {
			htm.tokenMu.RLock()
			_, exists := htm.activeTokens[value]
			htm.tokenMu.RUnlock()

			if exists {
				log.Printf("[HONEYTRAP] Poison parameter triggered: %s=%s", name, value)
				return true
			}
		}
	}

	// Check for access to hidden trap links
	trapPaths := []string{
		"/api/internal/debug",
		"/admin/config",
		"/.env",
		"/wp-admin/",
		"/.git/config",
		"/actuator/env",
		"/api/v1/admin",
	}

	for _, path := range trapPaths {
		if strings.HasPrefix(r.URL.Path, path) {
			// This is a trap endpoint - record and analyze
			log.Printf("[HONEYTRAP] Trap path accessed: %s from %s", r.URL.Path, GetTrustedClientIP(r))
			// Don't immediately ban, but increase suspicion score
			return false // Let them continue but mark as suspicious
		}
	}

	return false
}

// permanentBan adds an IP to the permanent ban list
func (htm *HoneyTokenMiddleware) permanentBan(ip string) {
	htm.banMu.Lock()
	defer htm.banMu.Unlock()

	htm.permanentBans[ip] = time.Now()

	// Also record in global caught list
	honeyCaughtMu.Lock()
	honeyCaughtIPs[ip] = time.Now()
	honeyCaughtMu.Unlock()

	// Store in Redis for persistence
	if htm.store != nil {
		key := fmt.Sprintf("honey:banned:%s", ip)
		htm.store.Set(context.Background(), key, "1", 24*time.Hour*365) // 1 year
	}
}

// isPermaBanned checks if an IP is permanently banned
func (htm *HoneyTokenMiddleware) isPermaBanned(ip string) bool {
	htm.banMu.RLock()
	_, banned := htm.permanentBans[ip]
	htm.banMu.RUnlock()

	if banned {
		return true
	}

	// Also check Redis
	if htm.store != nil {
		key := fmt.Sprintf("honey:banned:%s", ip)
		exists, _ := htm.store.Exists(context.Background(), key)
		if exists {
			// Cache locally
			htm.banMu.Lock()
			htm.permanentBans[ip] = time.Now()
			htm.banMu.Unlock()
			return true
		}
	}

	return false
}

// sendFakeSuccess sends a fake success response to waste bot's time
func (htm *HoneyTokenMiddleware) sendFakeSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// Send a fake "successful" response with enticing but useless data
	fakeResponses := []string{
		`{"status":"success","admin_access":true,"session_valid":true,"data":{"users_count":15234,"revenue":"$1,234,567"}}`,
		`{"authenticated":true,"role":"super_admin","permissions":["all"],"api_key":"fake-key-for-bots-only"}`,
		`{"debug_mode":"enabled","internal_endpoints":["/fake/endpoint1","/fake/endpoint2"],"secrets":{"db":"localhost"}}`,
	}

	// Randomly select a fake response
	bytes := make([]byte, 1)
	rand.Read(bytes)
	response := fakeResponses[int(bytes[0])%len(fakeResponses)]

	w.Write([]byte(response))
}

// cleanupOldTokens periodically cleans up old tokens
func (htm *HoneyTokenMiddleware) cleanupOldTokens() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		htm.tokenMu.Lock()
		now := time.Now()
		for value, token := range htm.activeTokens {
			if now.Sub(token.PlantedAt) > 24*time.Hour {
				delete(htm.activeTokens, value)
			}
		}
		htm.tokenMu.Unlock()
	}
}

// =============================================================================
// HONEY TOKEN RESPONSE WRITER
// =============================================================================

// honeyTokenResponseWriter wraps ResponseWriter to inject honey tokens
type honeyTokenResponseWriter struct {
	http.ResponseWriter
	htm           *HoneyTokenMiddleware
	clientIP      string
	headerWritten bool
}

// WriteHeader injects poison cookies before writing headers
func (hw *honeyTokenResponseWriter) WriteHeader(statusCode int) {
	if !hw.headerWritten {
		hw.injectPoisonCookies()
		hw.headerWritten = true
	}
	hw.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures headers are written first
func (hw *honeyTokenResponseWriter) Write(data []byte) (int, error) {
	if !hw.headerWritten {
		hw.injectPoisonCookies()
		hw.headerWritten = true
	}
	return hw.ResponseWriter.Write(data)
}

// injectPoisonCookies plants poison cookies in the response
func (hw *honeyTokenResponseWriter) injectPoisonCookies() {
	// Generate a unique token value
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	tokenValue := hex.EncodeToString(tokenBytes)

	// Store the token so we can detect when it's used
	hw.htm.tokenMu.Lock()
	hw.htm.activeTokens[tokenValue] = &HoneyToken{
		Name:      "admin_session_id",
		Value:     tokenValue,
		Type:      "cookie",
		PlantedAt: time.Now(),
		ClientIP:  hw.clientIP,
	}
	hw.htm.tokenMu.Unlock()
	atomic.AddUint64(&globalHoneyStats.TokensPlanted, 1)

	// Set the poison cookie
	// NOTE: HttpOnly=false intentionally - we WANT bots to be able to read it!
	// This is the trap - real browsers ignore it, bots try to use it
	http.SetCookie(hw.ResponseWriter, &http.Cookie{
		Name:     "admin_session_id",
		Value:    tokenValue,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: false, // Intentionally false - the trap!
		Secure:   false, // Allow on HTTP for wider bot coverage
		SameSite: http.SameSiteLaxMode,
	})

	// Also set a "debug_mode" cookie
	debugTokenBytes := make([]byte, 8)
	rand.Read(debugTokenBytes)
	debugToken := hex.EncodeToString(debugTokenBytes)

	hw.htm.tokenMu.Lock()
	hw.htm.activeTokens[debugToken] = &HoneyToken{
		Name:      "debug_mode",
		Value:     debugToken,
		Type:      "cookie",
		PlantedAt: time.Now(),
		ClientIP:  hw.clientIP,
	}
	hw.htm.tokenMu.Unlock()

	http.SetCookie(hw.ResponseWriter, &http.Cookie{
		Name:     "debug_mode",
		Value:    "true_" + debugToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

// Flush implements http.Flusher
func (hw *honeyTokenResponseWriter) Flush() {
	if flusher, ok := hw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// =============================================================================
// HONEY TOKEN HTML INJECTION
// =============================================================================

// GenerateHoneyTokenHTML generates hidden HTML elements with honey traps
func GenerateHoneyTokenHTML() template.HTML {
	// Generate unique tokens for this page load
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	linkBytes := make([]byte, 8)
	rand.Read(linkBytes)
	linkToken := hex.EncodeToString(linkBytes)

	// Create hidden traps that only bots will interact with
	html := fmt.Sprintf(`
<!-- Internal Configuration - Do Not Modify -->
<meta name="admin-token" content="%s" data-auth="internal-only">
<meta name="api-key" content="sk_live_%s" data-env="production">

<!-- Debug endpoint: /api/internal/debug?key=%s -->
<!-- Admin panel: /admin/dashboard?token=%s -->

<div style="display:none !important;visibility:hidden;position:absolute;left:-9999px;">
    <a href="/admin/users?auth=%s" id="admin-link">Admin Panel</a>
    <a href="/api/internal/export?key=%s">Export Data</a>
    <form action="/api/login" method="post">
        <input type="text" name="admin_username" value="root">
        <input type="password" name="admin_password" value="supersecret123">
        <input type="hidden" name="bypass_token" value="%s">
    </form>
</div>

<script type="text/template" id="hidden-config">
{
    "apiKey": "%s",
    "adminEndpoint": "/api/admin/v2",
    "debugMode": true,
    "internalAuth": "%s"
}
</script>

<!-- 
    ============================================
    INTERNAL SYSTEM CONFIGURATION - CONFIDENTIAL
    ============================================
    Admin API Key: %s
    Debug Endpoint: /debug/system?key=%s
    Database: mongodb://admin:password123@localhost:27017
    ============================================
-->
`,
		token, token[:16],
		token, token,
		linkToken, linkToken, token,
		token, token,
		token, token,
	)

	return template.HTML(html)
}

// GenerateFakeRobotstxt generates a robots.txt with honey traps
func GenerateFakeRobotstxt() string {
	return `User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /debug/
Disallow: /.env
Disallow: /wp-admin/
Disallow: /backup/
Disallow: /config/

# Internal endpoints (do not crawl):
# /api/v1/users/export
# /admin/database/dump
# /internal/metrics
# /actuator/env

# Development endpoints:
# /api/debug?key=development
# /admin/config/show
`
}

// =============================================================================
// TRAP ENDPOINT HANDLER
// =============================================================================

// TrapEndpointHandler handles requests to trap endpoints
func TrapEndpointHandler(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := GetTrustedClientIP(r)

		log.Printf("[HONEYTRAP] 🍯 Trap endpoint accessed: %s from %s (UA: %s)",
			r.URL.Path, clientIP, r.UserAgent())

		atomic.AddUint64(&globalHoneyStats.BotsCaught, 1)

		// Record this IP as caught
		honeyCaughtMu.Lock()
		honeyCaughtIPs[clientIP] = time.Now()
		honeyCaughtMu.Unlock()

		// Store in Redis for persistence
		if store != nil {
			key := fmt.Sprintf("honey:trapped:%s", clientIP)
			store.Set(context.Background(), key, r.URL.Path, 24*time.Hour*7) // 1 week
		}

		// Return convincing fake data to waste bot's resources
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		fakeData := `{
    "status": "success",
    "data": {
        "users": [
            {"id": 1, "email": "admin@example.com", "role": "admin"},
            {"id": 2, "email": "user@example.com", "role": "user"}
        ],
        "config": {
            "debug": true,
            "api_version": "2.0",
            "internal_key": "fake-key-12345"
        },
        "database": {
            "host": "localhost",
            "port": 5432,
            "name": "production"
        }
    },
    "meta": {
        "next_page": "/api/internal/users?page=2",
        "total": 15234
    }
}`
		w.Write([]byte(fakeData))
	}
}
