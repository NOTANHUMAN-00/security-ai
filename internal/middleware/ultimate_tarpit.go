// =============================================================================
// SENTINEL-X ULTIMATE TARPIT - ENHANCED BOT TRAP
// =============================================================================
//
// This is the ENHANCED tarpit that traps bots in multiple ways:
//
// TECHNIQUES:
//   1. SLOW DRIP - Send 1 byte every few seconds (classic)
//   2. CHUNKED INFINITY - Send endless chunked transfer encoding
//   3. GZIP BOMB - Stream compressed data that expands massively
//   4. WEBSOCKET ABYSS - Upgrade to WS, then send pings forever
//   5. REDIRECT MAZE - Send infinite 3xx redirects in a loop
//   6. JAVASCRIPT HELL - Serve JS that creates infinite work
//   7. IFRAME RECURSION - Page that iframes itself infinitely
//   8. SSL RENEGOTIATION - Force endless TLS renegotiations
//
// =============================================================================
package middleware

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// ENHANCED TARPIT CONFIGURATION
// =============================================================================

// UltimateTarpitConfig configures the enhanced tarpit
type UltimateTarpitConfig struct {
	// Basic settings
	Enabled         bool
	MaxConnections  int           // Max concurrent tarpit connections
	BaseDelay       time.Duration // Min delay between bytes
	MaxDelay        time.Duration // Max delay between bytes
	MaxDuration     time.Duration // Max time to hold a connection
	
	// Technique weights (0-100, higher = more likely)
	SlowDripWeight      int
	ChunkedWeight       int
	GzipBombWeight      int
	WebSocketWeight     int
	RedirectMazeWeight  int
	JSHellWeight        int
	IframeWeight        int
	
	// Adaptive settings
	AdaptiveDelay    bool // Adjust delay based on client behavior
	RandomizeContent bool // Randomize response content
	MimicRealServer  bool // Make responses look legitimate
}

// DefaultUltimateTarpitConfig returns production-ready defaults
func DefaultUltimateTarpitConfig() *UltimateTarpitConfig {
	return &UltimateTarpitConfig{
		Enabled:            true,
		MaxConnections:     10000,
		BaseDelay:          50 * time.Millisecond,
		MaxDelay:           5 * time.Second,
		MaxDuration:        30 * time.Minute,
		SlowDripWeight:     30,
		ChunkedWeight:      25,
		GzipBombWeight:     10,
		WebSocketWeight:    10,
		RedirectMazeWeight: 10,
		JSHellWeight:       10,
		IframeWeight:       5,
		AdaptiveDelay:      true,
		RandomizeContent:   true,
		MimicRealServer:    true,
	}
}

// =============================================================================
// ULTIMATE TARPIT MANAGER
// =============================================================================

// UltimateTarpitStats tracks enhanced tarpit statistics
type UltimateTarpitStats struct {
	ActiveConnections  int64
	TotalTrapped       uint64
	TotalTimeWasted    uint64 // seconds
	BytesSent          uint64
	TechniqueUsage     map[string]uint64
	LongestTrap        uint64 // seconds
	mu                 sync.RWMutex
}

// UltimateTarpit is the enhanced bot trap
type UltimateTarpit struct {
	config     *UltimateTarpitConfig
	stats      *UltimateTarpitStats
	semaphore  chan struct{}
	
	// Content generators
	htmlParts  []string
	cssParts   []string
	jsParts    []string
	jsonParts  []string
}

// NewUltimateTarpit creates a new enhanced tarpit
func NewUltimateTarpit(cfg *UltimateTarpitConfig) *UltimateTarpit {
	if cfg == nil {
		cfg = DefaultUltimateTarpitConfig()
	}
	
	ut := &UltimateTarpit{
		config:    cfg,
		stats:     &UltimateTarpitStats{TechniqueUsage: make(map[string]uint64)},
		semaphore: make(chan struct{}, cfg.MaxConnections),
	}
	
	ut.initContentGenerators()
	return ut
}

// initContentGenerators prepares realistic-looking content fragments
func (ut *UltimateTarpit) initContentGenerators() {
	// HTML fragments that look like real page loading
	ut.htmlParts = []string{
		"<!DOCTYPE html><html lang=\"en\"><head>",
		"<meta charset=\"UTF-8\">",
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
		"<title>Loading...</title>",
		"<link rel=\"stylesheet\" href=\"/assets/style.",
		"<script src=\"/assets/app.",
		"</head><body>",
		"<div class=\"container\">",
		"<main id=\"content\">",
		"<section class=\"hero\">",
		"<div class=\"loading-spinner\">",
		"<p>Please wait while we verify your browser...</p>",
		"<div class=\"progress-bar\"><div class=\"progress\" style=\"width:",
		"<script>document.addEventListener('DOMContentLoaded',function(){",
		"setTimeout(function(){location.reload();},",
		"var xhr=new XMLHttpRequest();xhr.open('GET','/api/verify",
		"fetch('/api/challenge').then(r=>r.json()).then(d=>{",
	}
	
	// CSS that looks like real stylesheets
	ut.cssParts = []string{
		"body{margin:0;padding:0;font-family:",
		".container{max-width:1200px;margin:0 auto;}",
		".loading{display:flex;justify-content:center;align-items:center;}",
		"@keyframes spin{from{transform:rotate(0deg);}to{transform:rotate(360deg);}}",
		".spinner{animation:spin 1s linear infinite;width:50px;height:50px;}",
		":root{--primary-color:#",
		"@media(max-width:768px){.container{padding:0 15px;}}",
	}
	
	// JavaScript that creates busy work
	ut.jsParts = []string{
		"(function(){",
		"'use strict';",
		"var _0x",
		"=function(",
		"){return ",
		".toString(",
		").split('').reverse().join('');}",
		"window['",
		"']=function(){",
		"setTimeout(",
		",Math.random()*",
		");};",
	}
	
	// JSON fragments
	ut.jsonParts = []string{
		"{\"status\":\"processing\"",
		",\"progress\":",
		",\"message\":\"",
		"\",\"data\":{",
		"\"items\":[",
		"{\"id\":",
		",\"name\":\"",
		"\",\"value\":",
		"}",
	}
}

// GetStats returns current tarpit stats
func (ut *UltimateTarpit) GetStats() UltimateTarpitStats {
	ut.stats.mu.RLock()
	defer ut.stats.mu.RUnlock()
	
	stats := UltimateTarpitStats{
		ActiveConnections: atomic.LoadInt64(&ut.stats.ActiveConnections),
		TotalTrapped:      atomic.LoadUint64(&ut.stats.TotalTrapped),
		TotalTimeWasted:   atomic.LoadUint64(&ut.stats.TotalTimeWasted),
		BytesSent:         atomic.LoadUint64(&ut.stats.BytesSent),
		LongestTrap:       atomic.LoadUint64(&ut.stats.LongestTrap),
		TechniqueUsage:    make(map[string]uint64),
	}
	
	for k, v := range ut.stats.TechniqueUsage {
		stats.TechniqueUsage[k] = v
	}
	
	return stats
}

// =============================================================================
// TECHNIQUE SELECTION
// =============================================================================

// selectTechnique chooses a trap technique based on weights and request
func (ut *UltimateTarpit) selectTechnique(r *http.Request) string {
	// Check for specific request characteristics
	accept := r.Header.Get("Accept")
	upgrade := r.Header.Get("Upgrade")
	
	// WebSocket upgrade requested - use WS technique
	if strings.EqualFold(upgrade, "websocket") {
		return "websocket"
	}
	
	// API request - use JSON technique
	if strings.Contains(accept, "application/json") {
		return "json_infinity"
	}
	
	// Calculate total weight
	totalWeight := ut.config.SlowDripWeight +
		ut.config.ChunkedWeight +
		ut.config.GzipBombWeight +
		ut.config.RedirectMazeWeight +
		ut.config.JSHellWeight +
		ut.config.IframeWeight
	
	if totalWeight == 0 {
		return "slow_drip"
	}
	
	// Random selection based on weights
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(totalWeight)))
	roll := int(n.Int64())
	
	cumulative := 0
	
	cumulative += ut.config.SlowDripWeight
	if roll < cumulative {
		return "slow_drip"
	}
	
	cumulative += ut.config.ChunkedWeight
	if roll < cumulative {
		return "chunked"
	}
	
	cumulative += ut.config.GzipBombWeight
	if roll < cumulative {
		return "gzip_bomb"
	}
	
	cumulative += ut.config.RedirectMazeWeight
	if roll < cumulative {
		return "redirect_maze"
	}
	
	cumulative += ut.config.JSHellWeight
	if roll < cumulative {
		return "js_hell"
	}
	
	return "iframe_recursion"
}

// =============================================================================
// TRAP EXECUTION
// =============================================================================

// Trap executes the tarpit on a request
func (ut *UltimateTarpit) Trap(w http.ResponseWriter, r *http.Request) {
	// Try to acquire semaphore
	select {
	case ut.semaphore <- struct{}{}:
		defer func() { <-ut.semaphore }()
	default:
		// Too many connections, just hang
		time.Sleep(30 * time.Second)
		return
	}
	
	// Track statistics
	atomic.AddInt64(&ut.stats.ActiveConnections, 1)
	atomic.AddUint64(&ut.stats.TotalTrapped, 1)
	defer atomic.AddInt64(&ut.stats.ActiveConnections, -1)
	
	startTime := time.Now()
	defer func() {
		elapsed := uint64(time.Since(startTime).Seconds())
		atomic.AddUint64(&ut.stats.TotalTimeWasted, elapsed)
		
		// Track longest trap
		for {
			current := atomic.LoadUint64(&ut.stats.LongestTrap)
			if elapsed <= current {
				break
			}
			if atomic.CompareAndSwapUint64(&ut.stats.LongestTrap, current, elapsed) {
				break
			}
		}
	}()
	
	// Select and execute technique
	technique := ut.selectTechnique(r)
	
	ut.stats.mu.Lock()
	ut.stats.TechniqueUsage[technique]++
	ut.stats.mu.Unlock()
	
	// Get the underlying connection if possible
	hijacker, canHijack := w.(http.Hijacker)
	
	switch technique {
	case "slow_drip":
		ut.executeSlowDrip(w, r)
	case "chunked":
		ut.executeChunkedInfinity(w, r)
	case "gzip_bomb":
		ut.executeGzipStream(w, r)
	case "websocket":
		if canHijack {
			ut.executeWebSocketAbyss(hijacker, r)
		} else {
			ut.executeSlowDrip(w, r)
		}
	case "redirect_maze":
		ut.executeRedirectMaze(w, r)
	case "js_hell":
		ut.executeJSHell(w, r)
	case "iframe_recursion":
		ut.executeIframeRecursion(w, r)
	case "json_infinity":
		ut.executeJSONInfinity(w, r)
	default:
		ut.executeSlowDrip(w, r)
	}
}

// =============================================================================
// TECHNIQUE 1: SLOW DRIP (Enhanced)
// =============================================================================

func (ut *UltimateTarpit) executeSlowDrip(w http.ResponseWriter, r *http.Request) {
	// Set headers to prevent caching and indicate content is coming
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Transfer-Encoding", "chunked")
	
	// Don't set Content-Length - allows infinite streaming
	w.WriteHeader(http.StatusOK)
	
	flusher, canFlush := w.(http.Flusher)
	
	deadline := time.Now().Add(ut.config.MaxDuration)
	partIndex := 0
	
	for time.Now().Before(deadline) {
		// Send a small piece of HTML
		var data string
		if partIndex < len(ut.htmlParts) {
			data = ut.htmlParts[partIndex]
			partIndex++
		} else {
			// Generate random-looking content
			data = ut.generateRandomContent()
		}
		
		n, err := w.Write([]byte(data))
		if err != nil {
			return // Client disconnected
		}
		atomic.AddUint64(&ut.stats.BytesSent, uint64(n))
		
		if canFlush {
			flusher.Flush()
		}
		
		// Adaptive delay
		delay := ut.calculateDelay()
		time.Sleep(delay)
	}
}

// =============================================================================
// TECHNIQUE 2: CHUNKED INFINITY
// =============================================================================

func (ut *UltimateTarpit) executeChunkedInfinity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	
	flusher, canFlush := w.(http.Flusher)
	deadline := time.Now().Add(ut.config.MaxDuration)
	
	// Send initial HTML
	initialHTML := `<!DOCTYPE html><html><head><title>Loading</title></head><body><div id="content">`
	w.Write([]byte(initialHTML))
	if canFlush {
		flusher.Flush()
	}
	
	counter := 0
	for time.Now().Before(deadline) {
		counter++
		
		// Send chunks that look like progressive loading
		chunk := fmt.Sprintf(`<div class="item-%d" style="display:none">%s</div>`,
			counter, ut.generateRandomContent())
		
		n, err := w.Write([]byte(chunk))
		if err != nil {
			return
		}
		atomic.AddUint64(&ut.stats.BytesSent, uint64(n))
		
		if canFlush {
			flusher.Flush()
		}
		
		// Occasionally send "progress" updates
		if counter%10 == 0 {
			progress := fmt.Sprintf(`<script>window.loadProgress=%d;</script>`, counter)
			w.Write([]byte(progress))
			if canFlush {
				flusher.Flush()
			}
		}
		
		time.Sleep(ut.calculateDelay())
	}
}

// =============================================================================
// TECHNIQUE 3: GZIP STREAM
// =============================================================================

func (ut *UltimateTarpit) executeGzipStream(w http.ResponseWriter, r *http.Request) {
	// Check if client accepts gzip
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		ut.executeSlowDrip(w, r)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.WriteHeader(http.StatusOK)
	
	flusher, canFlush := w.(http.Flusher)
	gzWriter := gzip.NewWriter(w)
	defer gzWriter.Close()
	
	deadline := time.Now().Add(ut.config.MaxDuration)
	
	for time.Now().Before(deadline) {
		// Write data that compresses well (high ratio = more work for client)
		data := strings.Repeat("A", 1000) + ut.generateRandomContent()
		
		n, err := gzWriter.Write([]byte(data))
		if err != nil {
			return
		}
		atomic.AddUint64(&ut.stats.BytesSent, uint64(n))
		
		// Flush the gzip writer
		gzWriter.Flush()
		
		if canFlush {
			flusher.Flush()
		}
		
		time.Sleep(ut.calculateDelay())
	}
}

// =============================================================================
// TECHNIQUE 4: WEBSOCKET ABYSS
// =============================================================================

func (ut *UltimateTarpit) executeWebSocketAbyss(hijacker http.Hijacker, r *http.Request) {
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	
	// Generate WebSocket accept key
	key := r.Header.Get("Sec-WebSocket-Key")
	acceptKey := generateWebSocketAccept(key)
	
	// Send upgrade response
	response := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n",
		acceptKey,
	)
	bufrw.WriteString(response)
	bufrw.Flush()
	
	deadline := time.Now().Add(ut.config.MaxDuration)
	
	for time.Now().Before(deadline) {
		// Send WebSocket ping frames
		pingFrame := []byte{0x89, 0x00} // Ping frame with no payload
		_, err := conn.Write(pingFrame)
		if err != nil {
			return
		}
		atomic.AddUint64(&ut.stats.BytesSent, 2)
		
		// Occasionally send text frames with "loading" messages
		if mrand.Intn(10) == 0 {
			msg := fmt.Sprintf(`{"status":"processing","progress":%d}`, mrand.Intn(100))
			ut.sendWebSocketTextFrame(conn, msg)
		}
		
		time.Sleep(ut.calculateDelay())
	}
}

func (ut *UltimateTarpit) sendWebSocketTextFrame(conn net.Conn, msg string) {
	data := []byte(msg)
	frame := make([]byte, 2+len(data))
	frame[0] = 0x81 // Text frame, FIN bit set
	frame[1] = byte(len(data))
	copy(frame[2:], data)
	conn.Write(frame)
	atomic.AddUint64(&ut.stats.BytesSent, uint64(len(frame)))
}

// =============================================================================
// TECHNIQUE 5: REDIRECT MAZE
// =============================================================================

func (ut *UltimateTarpit) executeRedirectMaze(w http.ResponseWriter, r *http.Request) {
	// Generate a unique redirect path
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	nextPath := fmt.Sprintf("/verify/%s/%d", base64.URLEncoding.EncodeToString(randomBytes), time.Now().UnixNano())
	
	// Add tracking parameters
	currentAttempt := r.URL.Query().Get("_a")
	attempt := 1
	if currentAttempt != "" {
		fmt.Sscanf(currentAttempt, "%d", &attempt)
		attempt++
	}
	
	// After many redirects, switch to slow drip (so we don't hit browser limits)
	if attempt > 20 {
		ut.executeSlowDrip(w, r)
		return
	}
	
	redirectURL := fmt.Sprintf("%s?_a=%d&_t=%d&_v=%s",
		nextPath,
		attempt,
		time.Now().UnixNano(),
		base64.URLEncoding.EncodeToString(randomBytes),
	)
	
	// Random delay before redirect
	time.Sleep(ut.calculateDelay())
	
	// Use different redirect types
	switch mrand.Intn(4) {
	case 0:
		http.Redirect(w, r, redirectURL, http.StatusFound) // 302
	case 1:
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect) // 307
	case 2:
		http.Redirect(w, r, redirectURL, http.StatusSeeOther) // 303
	default:
		// Meta refresh redirect (slower)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		html := fmt.Sprintf(`<!DOCTYPE html><html><head>
			<meta http-equiv="refresh" content="2;url=%s">
			<title>Redirecting...</title>
		</head><body>
			<p>Verifying your browser... Please wait.</p>
			<script>setTimeout(function(){location.href='%s';},2000);</script>
		</body></html>`, redirectURL, redirectURL)
		w.Write([]byte(html))
	}
}

// =============================================================================
// TECHNIQUE 6: JAVASCRIPT HELL
// =============================================================================

func (ut *UltimateTarpit) executeJSHell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	
	flusher, canFlush := w.(http.Flusher)
	
	// Send initial HTML with heavy JS
	initialHTML := `<!DOCTYPE html>
<html>
<head>
<title>Security Verification</title>
<style>
body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
.container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
.spinner { width: 50px; height: 50px; border: 3px solid #f3f3f3; border-top: 3px solid #3498db; border-radius: 50%; animation: spin 1s linear infinite; margin: 20px auto; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="container">
<h2>Security Verification</h2>
<div class="spinner"></div>
<p id="status">Initializing verification...</p>
<p id="progress">0%</p>
</div>
<script>
(function() {
	var iterations = 0;
	var maxIterations = 1000000;
	
	function heavyWork() {
		var result = 0;
		for (var i = 0; i < 10000; i++) {
			result += Math.sin(i) * Math.cos(i);
			result = Math.sqrt(Math.abs(result));
		}
		return result;
	}
	
	function updateProgress() {
		iterations++;
		var progress = Math.min(99, Math.floor((iterations / maxIterations) * 100));
		document.getElementById('progress').textContent = progress + '%';
		
		var messages = [
			'Analyzing browser fingerprint...',
			'Verifying JavaScript engine...',
			'Checking WebGL capabilities...',
			'Validating canvas hash...',
			'Processing security tokens...',
			'Completing verification...'
		];
		document.getElementById('status').textContent = messages[Math.floor(Math.random() * messages.length)];
	}
	
	function runChallenge() {
		var startTime = Date.now();
		while (Date.now() - startTime < 100) {
			heavyWork();
		}
		updateProgress();
		
		if (iterations < maxIterations) {
			setTimeout(runChallenge, 50);
		}
	}
	
	runChallenge();
`
	w.Write([]byte(initialHTML))
	atomic.AddUint64(&ut.stats.BytesSent, uint64(len(initialHTML)))
	
	if canFlush {
		flusher.Flush()
	}
	
	deadline := time.Now().Add(ut.config.MaxDuration)
	counter := 0
	
	// Keep injecting more JS work
	for time.Now().Before(deadline) {
		counter++
		
		// Inject more work functions
		jsChunk := fmt.Sprintf(`
	function work_%d() { 
		var x = 0; 
		for(var i=0;i<%d;i++) { 
			x += Math.random() * Math.sin(i); 
		} 
		return x; 
	}
	setTimeout(work_%d, %d);
`, counter, 1000+mrand.Intn(9000), counter, 100+mrand.Intn(900))
		
		n, err := w.Write([]byte(jsChunk))
		if err != nil {
			return
		}
		atomic.AddUint64(&ut.stats.BytesSent, uint64(n))
		
		if canFlush {
			flusher.Flush()
		}
		
		time.Sleep(ut.calculateDelay())
	}
	
	// Close the script tag (but never close the HTML properly)
	w.Write([]byte("})();</script>"))
}

// =============================================================================
// TECHNIQUE 7: IFRAME RECURSION
// =============================================================================

func (ut *UltimateTarpit) executeIframeRecursion(w http.ResponseWriter, r *http.Request) {
	depth := 0
	depthStr := r.URL.Query().Get("_d")
	if depthStr != "" {
		fmt.Sscanf(depthStr, "%d", &depth)
	}
	
	// Limit recursion depth to avoid browser crashes
	if depth > 50 {
		ut.executeSlowDrip(w, r)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	
	// Generate random paths for iframes
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	
	nextDepth := depth + 1
	iframeSrc := fmt.Sprintf("%s?_d=%d&_t=%d", r.URL.Path, nextDepth, time.Now().UnixNano())
	
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Verification Layer %d</title>
<style>
body { margin: 0; padding: 0; overflow: hidden; }
iframe { width: 100%%; height: 100%%; border: none; }
.overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.9); display: flex; justify-content: center; align-items: center; z-index: 1000; }
</style>
</head>
<body>
<div class="overlay">
<p>Loading security layer %d...</p>
</div>
<iframe src="%s" sandbox="allow-scripts allow-same-origin"></iframe>
<script>
setTimeout(function() {
	document.querySelector('.overlay').style.display = 'none';
}, 1000);
document.addEventListener('scroll', function() {
	// Infinite scroll effect
	document.body.scrollTop = 0;
});
</script>
</body>
</html>`, depth, depth, iframeSrc)
	
	w.Write([]byte(html))
	atomic.AddUint64(&ut.stats.BytesSent, uint64(len(html)))
}

// =============================================================================
// TECHNIQUE 8: JSON INFINITY (for API requests)
// =============================================================================

func (ut *UltimateTarpit) executeJSONInfinity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	
	flusher, canFlush := w.(http.Flusher)
	deadline := time.Now().Add(ut.config.MaxDuration)
	
	// Start JSON object
	w.Write([]byte(`{"status":"processing","data":[`))
	if canFlush {
		flusher.Flush()
	}
	
	counter := 0
	for time.Now().Before(deadline) {
		counter++
		
		if counter > 1 {
			w.Write([]byte(","))
		}
		
		// Generate fake data items
		item := fmt.Sprintf(`{"id":%d,"hash":"%s","timestamp":%d,"status":"pending","progress":%d}`,
			counter,
			ut.generateRandomHash(),
			time.Now().UnixNano(),
			mrand.Intn(100),
		)
		
		n, err := w.Write([]byte(item))
		if err != nil {
			return
		}
		atomic.AddUint64(&ut.stats.BytesSent, uint64(n))
		
		if canFlush {
			flusher.Flush()
		}
		
		time.Sleep(ut.calculateDelay())
	}
	
	// Never close the JSON array/object
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func (ut *UltimateTarpit) calculateDelay() time.Duration {
	if !ut.config.AdaptiveDelay {
		return ut.config.BaseDelay
	}
	
	// Random delay between base and max
	delayRange := ut.config.MaxDelay - ut.config.BaseDelay
	randomNs := time.Duration(mrand.Int63n(int64(delayRange)))
	return ut.config.BaseDelay + randomNs
}

func (ut *UltimateTarpit) generateRandomContent() string {
	// Generate content that looks like real HTML/CSS/JS
	types := []string{"html", "css", "js", "comment"}
	t := types[mrand.Intn(len(types))]
	
	switch t {
	case "html":
		tags := []string{"div", "span", "p", "section", "article", "aside"}
		tag := tags[mrand.Intn(len(tags))]
		return fmt.Sprintf("<%s class=\"c_%d\" data-id=\"%d\">", tag, mrand.Intn(1000), mrand.Intn(10000))
	case "css":
		return fmt.Sprintf(".e_%d{display:block;margin:%dpx;}", mrand.Intn(1000), mrand.Intn(50))
	case "js":
		return fmt.Sprintf("var v_%d=%d;", mrand.Intn(1000), mrand.Intn(10000))
	default:
		return fmt.Sprintf("<!-- chunk %d -->", mrand.Intn(10000))
	}
}

func (ut *UltimateTarpit) generateRandomHash() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generateWebSocketAccept(key string) string {
	// Simplified - in production use proper SHA1 + base64
	h := make([]byte, 20)
	rand.Read(h)
	return base64.StdEncoding.EncodeToString(h)
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

// UltimateTarpitMiddleware creates a middleware for the enhanced tarpit
func UltimateTarpitMiddleware(ut *UltimateTarpit, shouldTrap func(*http.Request) bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ut.config.Enabled && shouldTrap(r) {
				ut.Trap(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// CONNECTION DRAINER (For persistent connections)
// =============================================================================

// DrainConnection slowly drains a hijacked connection
func (ut *UltimateTarpit) DrainConnection(conn net.Conn) {
	defer conn.Close()
	
	deadline := time.Now().Add(ut.config.MaxDuration)
	
	// Create a buffered reader/writer
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	
	for time.Now().Before(deadline) {
		// Try to read (with timeout) - this tells us if client is still connected
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err := reader.Peek(1)
		if err != nil && err != io.EOF {
			// Timeout is OK, continue draining
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Send a byte
				writer.WriteByte(byte(mrand.Intn(256)))
				writer.Flush()
				atomic.AddUint64(&ut.stats.BytesSent, 1)
				time.Sleep(ut.calculateDelay())
				continue
			}
			return // Real error, client disconnected
		}
		
		if err == io.EOF {
			return // Client closed connection
		}
		
		// Send random byte
		writer.WriteByte(byte(mrand.Intn(256)))
		writer.Flush()
		atomic.AddUint64(&ut.stats.BytesSent, 1)
		
		time.Sleep(ut.calculateDelay())
	}
}
