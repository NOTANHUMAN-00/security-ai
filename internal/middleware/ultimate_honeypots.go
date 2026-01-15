// =============================================================================
// SENTINEL-X ULTIMATE HONEYPOTS - ADVANCED DECEPTION LAYER
// =============================================================================
//
// COMPREHENSIVE TRAP SYSTEM:
//
// 1. HIDDEN LINK TRAPS - CSS-hidden links that only bots find
// 2. INVISIBLE FORM TRAPS - Hidden forms that only bots fill
// 3. FAKE API ENDPOINTS - Juicy-looking endpoints that are traps
// 4. DIRECTORY TRAPS - Common recon paths (.env, .git, wp-admin)
// 5. COOKIE TRAPS - Set trap cookies only bots will follow
// 6. HEADER TRAPS - Check for impossible header combinations
// 7. TIMING TRAPS - Detect requests that are too fast
// 8. ROBOT.TXT TRAPS - Disallowed paths that only bots visit
// 9. SITEMAP TRAPS - Fake entries in sitemap for bots
// 10. JAVASCRIPT TRAPS - Invisible JS-triggered endpoints
//
// =============================================================================
package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// HONEYPOT CONFIGURATION
// =============================================================================

// UltimateHoneypotConfig configures the trap system
type UltimateHoneypotConfig struct {
	Enabled bool
	
	// Trap types to enable
	EnableLinkTraps       bool
	EnableFormTraps       bool
	EnableAPITraps        bool
	EnableDirectoryTraps  bool
	EnableCookieTraps     bool
	EnableTimingTraps     bool
	EnableRobotsTxtTraps  bool
	EnableSitemapTraps    bool
	EnableJSTraps         bool
	
	// Behavior on trap trigger
	BanDuration          time.Duration
	ShareWithP2P         bool
	LogToWebhook         bool
	TarpitOnTrigger      bool
	
	// Custom trap paths
	CustomTrapPaths      []string
	
	// Timing settings
	MinRequestInterval   time.Duration // Requests faster than this = trap
	
	// Cookie trap settings
	TrapCookieName       string
	TrapCookieValue      string
}

// DefaultUltimateHoneypotConfig returns production defaults
func DefaultUltimateHoneypotConfig() *UltimateHoneypotConfig {
	return &UltimateHoneypotConfig{
		Enabled:              true,
		EnableLinkTraps:      true,
		EnableFormTraps:      true,
		EnableAPITraps:       true,
		EnableDirectoryTraps: true,
		EnableCookieTraps:    true,
		EnableTimingTraps:    true,
		EnableRobotsTxtTraps: true,
		EnableSitemapTraps:   true,
		EnableJSTraps:        true,
		BanDuration:          24 * time.Hour,
		ShareWithP2P:         true,
		LogToWebhook:         true,
		TarpitOnTrigger:      true,
		MinRequestInterval:   50 * time.Millisecond,
		TrapCookieName:       "_session_verify",
		TrapCookieValue:      "validate_required",
		CustomTrapPaths:      []string{},
	}
}

// =============================================================================
// TRAP DEFINITIONS
// =============================================================================

// TrapType identifies the type of trap triggered
type TrapType string

const (
	TrapTypeHiddenLink    TrapType = "hidden_link"
	TrapTypeHiddenForm    TrapType = "hidden_form"
	TrapTypeFakeAPI       TrapType = "fake_api"
	TrapTypeDirectory     TrapType = "directory_recon"
	TrapTypeCookie        TrapType = "cookie_trap"
	TrapTypeTiming        TrapType = "timing_anomaly"
	TrapTypeRobotsTxt     TrapType = "robots_txt"
	TrapTypeSitemap       TrapType = "sitemap_trap"
	TrapTypeJavaScript    TrapType = "javascript_trap"
	TrapTypeCustom        TrapType = "custom_trap"
)

// TrapEvent represents a triggered trap
type TrapEvent struct {
	Type        TrapType  `json:"type"`
	Path        string    `json:"path"`
	IP          string    `json:"ip"`
	UserAgent   string    `json:"user_agent"`
	Timestamp   time.Time `json:"timestamp"`
	SessionID   string    `json:"session_id"`
	Fingerprint string    `json:"fingerprint"`
	Headers     map[string]string `json:"headers"`
}

// =============================================================================
// TRAP PATHS
// =============================================================================

// Directory reconnaissance traps
var directoryTraps = []string{
	// WordPress
	"/wp-admin",
	"/wp-admin/",
	"/wp-login.php",
	"/wp-content/uploads/",
	"/wp-includes/",
	"/wp-config.php",
	"/wp-config.php.bak",
	"/wordpress/",
	
	// Git/Version Control
	"/.git",
	"/.git/",
	"/.git/config",
	"/.git/HEAD",
	"/.gitignore",
	"/.svn/",
	"/.hg/",
	
	// Environment/Config files
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.backup",
	"/config.json",
	"/config.yaml",
	"/config.yml",
	"/settings.json",
	"/secrets.json",
	"/credentials.json",
	
	// Backup files
	"/backup.sql",
	"/backup.zip",
	"/db.sql",
	"/database.sql",
	"/.backup",
	"/backup/",
	
	// Admin panels
	"/admin",
	"/admin/",
	"/administrator",
	"/phpmyadmin",
	"/phpmyadmin/",
	"/pma/",
	"/mysql/",
	"/adminer.php",
	"/adminer/",
	
	// Debug/Dev endpoints
	"/debug",
	"/debug/",
	"/_debug",
	"/dev/",
	"/test/",
	"/staging/",
	"/console",
	"/shell",
	"/cmd",
	
	// AWS/Cloud
	"/.aws/credentials",
	"/.aws/config",
	"/aws.yml",
	
	// Actuators (Spring Boot)
	"/actuator",
	"/actuator/env",
	"/actuator/health",
	"/actuator/info",
	"/actuator/mappings",
	"/actuator/configprops",
	"/actuator/beans",
	"/actuator/heapdump",
	
	// Other common
	"/server-status",
	"/server-info",
	"/phpinfo.php",
	"/info.php",
	"/.htaccess",
	"/.htpasswd",
	"/web.config",
	"/crossdomain.xml",
	"/.well-known/security.txt",
	"/security.txt",
	
	// GraphQL/API
	"/graphql",
	"/graphiql",
	"/api/graphql",
	"/__graphql",
	
	// Firebase/Databases
	"/.firebase",
	"/firebase.json",
	"/firestore.rules",
	
	// IDE files
	"/.idea/",
	"/.vscode/",
	"/.vs/",
}

// Fake API endpoints that look tempting to bots
var apiTraps = []string{
	"/api/v1/admin",
	"/api/v1/users",
	"/api/v1/users/list",
	"/api/internal/debug",
	"/api/private/tokens",
	"/api/auth/reset",
	"/api/admin/config",
	"/api/system/logs",
	"/api/database/export",
	"/api/v2/internal",
	"/_api/internal",
	"/internal-api/",
	"/debug-api/",
	"/graphql/admin",
}

// Paths that robots.txt typically disallows
var robotsTxtTraps = []string{
	"/cgi-bin/",
	"/tmp/",
	"/private/",
	"/secret/",
	"/hidden/",
	"/internal/",
	"/restricted/",
}

// =============================================================================
// HONEYPOT MANAGER
// =============================================================================

// UltimateHoneypotStats tracks honeypot statistics
type UltimateHoneypotStats struct {
	TotalTrapsTriggered  uint64
	DirectoryTraps       uint64
	APITraps             uint64
	LinkTraps            uint64
	FormTraps            uint64
	CookieTraps          uint64
	TimingTraps          uint64
	RobotsTraps          uint64
	JSTraps              uint64
	UniqueIPsCaught      uint64
	
	RecentTraps          []TrapEvent
	mu                   sync.RWMutex
}

// UltimateHoneypot manages all trap types
type UltimateHoneypot struct {
	config       *UltimateHoneypotConfig
	stats        *UltimateHoneypotStats
	trapPaths    map[string]TrapType
	bannedIPs    sync.Map // map[ip]time.Time
	ipTimestamps sync.Map // map[ip]time.Time (for timing trap)
	trapTokens   sync.Map // map[token]trapType
	
	// Callbacks
	onTrap       func(event TrapEvent)
	tarpit       *UltimateTarpit
}

// NewUltimateHoneypot creates a new honeypot system
func NewUltimateHoneypot(cfg *UltimateHoneypotConfig) *UltimateHoneypot {
	if cfg == nil {
		cfg = DefaultUltimateHoneypotConfig()
	}
	
	uh := &UltimateHoneypot{
		config:    cfg,
		stats:     &UltimateHoneypotStats{RecentTraps: make([]TrapEvent, 0, 100)},
		trapPaths: make(map[string]TrapType),
	}
	
	uh.initTrapPaths()
	return uh
}

// initTrapPaths builds the trap path lookup map
func (uh *UltimateHoneypot) initTrapPaths() {
	// Add directory traps
	if uh.config.EnableDirectoryTraps {
		for _, path := range directoryTraps {
			uh.trapPaths[path] = TrapTypeDirectory
		}
	}
	
	// Add API traps
	if uh.config.EnableAPITraps {
		for _, path := range apiTraps {
			uh.trapPaths[path] = TrapTypeFakeAPI
		}
	}
	
	// Add robots.txt traps
	if uh.config.EnableRobotsTxtTraps {
		for _, path := range robotsTxtTraps {
			uh.trapPaths[path] = TrapTypeRobotsTxt
		}
	}
	
	// Add custom traps
	for _, path := range uh.config.CustomTrapPaths {
		uh.trapPaths[path] = TrapTypeCustom
	}
}

// SetTarpit sets the tarpit to use on trap trigger
func (uh *UltimateHoneypot) SetTarpit(t *UltimateTarpit) {
	uh.tarpit = t
}

// SetOnTrap sets the callback for trap events
func (uh *UltimateHoneypot) SetOnTrap(fn func(TrapEvent)) {
	uh.onTrap = fn
}

// GetStats returns honeypot statistics
func (uh *UltimateHoneypot) GetStats() UltimateHoneypotStats {
	uh.stats.mu.RLock()
	defer uh.stats.mu.RUnlock()
	
	return UltimateHoneypotStats{
		TotalTrapsTriggered: atomic.LoadUint64(&uh.stats.TotalTrapsTriggered),
		DirectoryTraps:      atomic.LoadUint64(&uh.stats.DirectoryTraps),
		APITraps:            atomic.LoadUint64(&uh.stats.APITraps),
		LinkTraps:           atomic.LoadUint64(&uh.stats.LinkTraps),
		FormTraps:           atomic.LoadUint64(&uh.stats.FormTraps),
		CookieTraps:         atomic.LoadUint64(&uh.stats.CookieTraps),
		TimingTraps:         atomic.LoadUint64(&uh.stats.TimingTraps),
		RobotsTraps:         atomic.LoadUint64(&uh.stats.RobotsTraps),
		JSTraps:             atomic.LoadUint64(&uh.stats.JSTraps),
		UniqueIPsCaught:     atomic.LoadUint64(&uh.stats.UniqueIPsCaught),
		RecentTraps:         uh.stats.RecentTraps,
	}
}

// =============================================================================
// TRAP DETECTION
// =============================================================================

// CheckRequest checks if a request triggers any trap
func (uh *UltimateHoneypot) CheckRequest(r *http.Request) (triggered bool, trapType TrapType, event TrapEvent) {
	if !uh.config.Enabled {
		return false, "", TrapEvent{}
	}
	
	ip := getRealIP(r)
	path := r.URL.Path
	
	// Check if already banned
	if banned, ok := uh.bannedIPs.Load(ip); ok {
		if bannedTime, ok := banned.(time.Time); ok {
			if time.Since(bannedTime) < uh.config.BanDuration {
				return true, TrapTypeDirectory, TrapEvent{Type: TrapTypeDirectory, IP: ip}
			}
		}
	}
	
	// Check path-based traps
	if trapType, exists := uh.trapPaths[path]; exists {
		event = uh.createTrapEvent(trapType, r)
		uh.handleTrap(event)
		return true, trapType, event
	}
	
	// Check with trailing slash variations
	pathVariants := []string{
		strings.TrimSuffix(path, "/"),
		path + "/",
	}
	for _, variant := range pathVariants {
		if trapType, exists := uh.trapPaths[variant]; exists {
			event = uh.createTrapEvent(trapType, r)
			uh.handleTrap(event)
			return true, trapType, event
		}
	}
	
	// Check for partial matches (path prefix)
	for trapPath, trapType := range uh.trapPaths {
		if strings.HasPrefix(path, trapPath) {
			event = uh.createTrapEvent(trapType, r)
			uh.handleTrap(event)
			return true, trapType, event
		}
	}
	
	// Check cookie trap
	if uh.config.EnableCookieTraps {
		if cookie, err := r.Cookie(uh.config.TrapCookieName); err == nil {
			if cookie.Value == uh.config.TrapCookieValue {
				// Cookie trap triggered - this cookie was set as a trap
				event = uh.createTrapEvent(TrapTypeCookie, r)
				uh.handleTrap(event)
				return true, TrapTypeCookie, event
			}
		}
	}
	
	// Check timing trap
	if uh.config.EnableTimingTraps {
		if lastRequest, ok := uh.ipTimestamps.Load(ip); ok {
			if lastTime, ok := lastRequest.(time.Time); ok {
				if time.Since(lastTime) < uh.config.MinRequestInterval {
					// Too fast!
					event = uh.createTrapEvent(TrapTypeTiming, r)
					uh.handleTrap(event)
					return true, TrapTypeTiming, event
				}
			}
		}
		uh.ipTimestamps.Store(ip, time.Now())
	}
	
	// Check for hidden link/form trap tokens
	token := r.URL.Query().Get("_trap_token")
	if token == "" {
		token = r.FormValue("_trap_token")
	}
	if token != "" {
		if trapType, ok := uh.trapTokens.Load(token); ok {
			event = uh.createTrapEvent(trapType.(TrapType), r)
			uh.handleTrap(event)
			return true, trapType.(TrapType), event
		}
	}
	
	// Check for JS trap endpoint
	if uh.config.EnableJSTraps && path == "/sentinel/js-trap" {
		event = uh.createTrapEvent(TrapTypeJavaScript, r)
		uh.handleTrap(event)
		return true, TrapTypeJavaScript, event
	}
	
	return false, "", TrapEvent{}
}

// createTrapEvent creates a trap event from a request
func (uh *UltimateHoneypot) createTrapEvent(trapType TrapType, r *http.Request) TrapEvent {
	headers := make(map[string]string)
	for name, values := range r.Header {
		headers[name] = strings.Join(values, ", ")
	}
	
	// Generate fingerprint
	fp := sha256.Sum256([]byte(r.UserAgent() + getRealIP(r)))
	
	return TrapEvent{
		Type:        trapType,
		Path:        r.URL.Path,
		IP:          getRealIP(r),
		UserAgent:   r.UserAgent(),
		Timestamp:   time.Now(),
		SessionID:   getSessionID(r),
		Fingerprint: hex.EncodeToString(fp[:8]),
		Headers:     headers,
	}
}

// getSessionID extracts or generates a session ID
func getSessionID(r *http.Request) string {
	// Try to get from cookie
	if cookie, err := r.Cookie("_sentinel_session"); err == nil {
		return cookie.Value
	}
	
	// Generate new one
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// handleTrap processes a triggered trap
func (uh *UltimateHoneypot) handleTrap(event TrapEvent) {
	// Update stats
	atomic.AddUint64(&uh.stats.TotalTrapsTriggered, 1)
	
	switch event.Type {
	case TrapTypeDirectory:
		atomic.AddUint64(&uh.stats.DirectoryTraps, 1)
	case TrapTypeFakeAPI:
		atomic.AddUint64(&uh.stats.APITraps, 1)
	case TrapTypeHiddenLink:
		atomic.AddUint64(&uh.stats.LinkTraps, 1)
	case TrapTypeHiddenForm:
		atomic.AddUint64(&uh.stats.FormTraps, 1)
	case TrapTypeCookie:
		atomic.AddUint64(&uh.stats.CookieTraps, 1)
	case TrapTypeTiming:
		atomic.AddUint64(&uh.stats.TimingTraps, 1)
	case TrapTypeRobotsTxt:
		atomic.AddUint64(&uh.stats.RobotsTraps, 1)
	case TrapTypeJavaScript:
		atomic.AddUint64(&uh.stats.JSTraps, 1)
	}
	
	// Check if new IP
	if _, exists := uh.bannedIPs.Load(event.IP); !exists {
		atomic.AddUint64(&uh.stats.UniqueIPsCaught, 1)
	}
	
	// Ban the IP
	uh.bannedIPs.Store(event.IP, time.Now())
	
	// Store in recent traps
	uh.stats.mu.Lock()
	uh.stats.RecentTraps = append(uh.stats.RecentTraps, event)
	if len(uh.stats.RecentTraps) > 100 {
		uh.stats.RecentTraps = uh.stats.RecentTraps[1:]
	}
	uh.stats.mu.Unlock()
	
	// Log
	log.Printf("[HONEYPOT] 🍯 Trap triggered! Type=%s IP=%s Path=%s UA=%s",
		event.Type, event.IP, event.Path, truncateString(event.UserAgent, 50))
	
	// Call callback
	if uh.onTrap != nil {
		uh.onTrap(event)
	}
}

// IsBanned checks if an IP is banned
func (uh *UltimateHoneypot) IsBanned(ip string) bool {
	if banned, ok := uh.bannedIPs.Load(ip); ok {
		if bannedTime, ok := banned.(time.Time); ok {
			return time.Since(bannedTime) < uh.config.BanDuration
		}
	}
	return false
}

// =============================================================================
// TRAP CONTENT GENERATORS
// =============================================================================

// GenerateTrapToken creates a unique trap token
func (uh *UltimateHoneypot) GenerateTrapToken(trapType TrapType) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	uh.trapTokens.Store(token, trapType)
	return token
}

// GenerateHiddenLinkHTML generates hidden link trap HTML
func (uh *UltimateHoneypot) GenerateHiddenLinkHTML() string {
	token := uh.GenerateTrapToken(TrapTypeHiddenLink)
	
	// Multiple hiding techniques
	return fmt.Sprintf(`
<!-- Bot trap - Do not remove -->
<a href="/trap-link?_trap_token=%s" style="position:absolute;left:-9999px;top:-9999px;font-size:0;line-height:0;color:transparent;user-select:none" aria-hidden="true" tabindex="-1">Admin Login</a>
<div style="display:none;visibility:hidden;width:0;height:0;overflow:hidden"><a href="/admin-panel?_trap_token=%s">Dashboard</a></div>
<a href="/secret-api?_trap_token=%s" style="opacity:0;pointer-events:auto;position:absolute;z-index:-1">API Access</a>
<noscript><a href="/nojs-trap?_trap_token=%s">Enable JavaScript</a></noscript>
`, token, token, token, token)
}

// GenerateHiddenFormHTML generates hidden form trap HTML
func (uh *UltimateHoneypot) GenerateHiddenFormHTML() string {
	token := uh.GenerateTrapToken(TrapTypeHiddenForm)
	
	return fmt.Sprintf(`
<!-- Form honeypot -->
<form action="/contact" method="post" style="position:absolute;left:-9999px;top:-9999px">
  <input type="hidden" name="_trap_token" value="%s">
  <label for="hp_email">Leave this empty</label>
  <input type="text" name="email" id="hp_email" autocomplete="off" tabindex="-1">
  <label for="hp_website">Do not fill</label>
  <input type="url" name="website" id="hp_website" autocomplete="off" tabindex="-1">
  <button type="submit">Submit</button>
</form>
`, token)
}

// GenerateCookieTrap returns a trap cookie to set
func (uh *UltimateHoneypot) GenerateCookieTrap() *http.Cookie {
	return &http.Cookie{
		Name:     uh.config.TrapCookieName,
		Value:    uh.config.TrapCookieValue,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: false, // Let bots see it
		SameSite: http.SameSiteLaxMode,
	}
}

// GenerateRobotsTxt generates robots.txt with trap entries
func (uh *UltimateHoneypot) GenerateRobotsTxt() string {
	var sb strings.Builder
	
	sb.WriteString("User-agent: *\n")
	sb.WriteString("Allow: /\n\n")
	
	// Add trap disallows
	if uh.config.EnableRobotsTxtTraps {
		sb.WriteString("# Please respect these restrictions\n")
		for _, path := range robotsTxtTraps {
			sb.WriteString(fmt.Sprintf("Disallow: %s\n", path))
		}
		sb.WriteString("\n")
	}
	
	// Add some extra tempting paths
	sb.WriteString("# Sensitive areas\n")
	sb.WriteString("Disallow: /admin-backup/\n")
	sb.WriteString("Disallow: /db-export/\n")
	sb.WriteString("Disallow: /api/internal/\n")
	sb.WriteString("Disallow: /private-api/\n")
	
	return sb.String()
}

// GenerateSitemapWithTraps generates sitemap with trap entries
func (uh *UltimateHoneypot) GenerateSitemapWithTraps(realEntries []string) string {
	var sb strings.Builder
	
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	
	// Add real entries
	for _, entry := range realEntries {
		sb.WriteString(fmt.Sprintf(`<url><loc>%s</loc></url>`, entry))
	}
	
	// Add trap entries (only bots that ignore robots.txt will visit these)
	if uh.config.EnableSitemapTraps {
		token := uh.GenerateTrapToken(TrapTypeSitemap)
		trapURLs := []string{
			fmt.Sprintf("/hidden-admin?_trap_token=%s", token),
			fmt.Sprintf("/backup-download?_trap_token=%s", token),
			fmt.Sprintf("/user-export?_trap_token=%s", token),
		}
		for _, url := range trapURLs {
			sb.WriteString(fmt.Sprintf(`<url><loc>%s</loc><priority>0.1</priority></url>`, url))
		}
	}
	
	sb.WriteString(`</urlset>`)
	return sb.String()
}

// GenerateJSTrapScript generates JavaScript trap code
func (uh *UltimateHoneypot) GenerateJSTrapScript() string {
	token := uh.GenerateTrapToken(TrapTypeJavaScript)
	
	return fmt.Sprintf(`
<script>
(function() {
	// Create invisible iframe that bots might render
	var trapFrame = document.createElement('iframe');
	trapFrame.src = '/sentinel/js-trap?_trap_token=%s';
	trapFrame.style.cssText = 'width:0;height:0;border:0;position:absolute;left:-9999px';
	trapFrame.setAttribute('aria-hidden', 'true');
	trapFrame.setAttribute('tabindex', '-1');
	
	// Only add after a delay (real users won't trigger)
	setTimeout(function() {
		// Check if user has interacted (real users do, bots don't)
		var hasInteracted = false;
		
		['click', 'scroll', 'keydown', 'mousemove', 'touchstart'].forEach(function(event) {
			document.addEventListener(event, function() {
				hasInteracted = true;
			}, {once: true, passive: true});
		});
		
		// After 5 seconds, if no interaction, might be a bot
		setTimeout(function() {
			if (!hasInteracted) {
				// Silent trap check
				var img = new Image();
				img.src = '/sentinel/js-trap?_trap_token=%s&nointeract=1';
			}
		}, 5000);
	}, 1000);
	
	// Detect automation frameworks
	var automationSigns = [
		window.callPhantom,
		window._phantom,
		window.__nightmare,
		navigator.webdriver,
		window.domAutomation,
		window.domAutomationController,
		document.__webdriver_script_fn,
	];
	
	for (var i = 0; i < automationSigns.length; i++) {
		if (automationSigns[i]) {
			var img = new Image();
			img.src = '/sentinel/js-trap?_trap_token=%s&automation=' + i;
			break;
		}
	}
})();
</script>
`, token, token, token)
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

// UltimateHoneypotMiddleware creates the honeypot middleware
func UltimateHoneypotMiddleware(uh *UltimateHoneypot, tarpit *UltimateTarpit) Middleware {
	uh.SetTarpit(tarpit)
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !uh.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}
			
			// Check if request triggers any trap
			triggered, trapType, event := uh.CheckRequest(r)
			
			if triggered {
				// Respond based on configuration
				if uh.config.TarpitOnTrigger && tarpit != nil {
					// Trap them in the tarpit
					tarpit.Trap(w, r)
					return
				}
				
				// Return fake response based on trap type
				uh.serveFakeResponse(w, r, trapType, event)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// serveFakeResponse serves a convincing fake response to waste bot time
func (uh *UltimateHoneypot) serveFakeResponse(w http.ResponseWriter, r *http.Request, trapType TrapType, event TrapEvent) {
	switch trapType {
	case TrapTypeFakeAPI:
		// Serve fake API response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"error","message":"Authentication required","code":"AUTH_REQUIRED"}`))
		
	case TrapTypeDirectory:
		// Serve fake error that looks real
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"))
		
	default:
		// Generic block response
		http.Error(w, "Access Denied", http.StatusForbidden)
	}
}

// =============================================================================
// SPECIAL ENDPOINT HANDLERS
// =============================================================================

// ServeRobotsTxt serves the robots.txt with traps
func (uh *UltimateHoneypot) ServeRobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(uh.GenerateRobotsTxt()))
}

// ServeSitemap serves the sitemap with traps
func (uh *UltimateHoneypot) ServeSitemap(w http.ResponseWriter, r *http.Request, realEntries []string) {
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(uh.GenerateSitemapWithTraps(realEntries)))
}

// =============================================================================
// HELPERS
// =============================================================================

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
