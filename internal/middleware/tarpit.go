// Package middleware - Tarpit (Infinite Void) Deception System
// =============================================================================
// OFFENSIVE DEFENSE: Instead of blocking bots, we TRAP them
//
// When a high-confidence bot is detected, we don't return 403 Forbidden.
// Smart bots just retry with a new IP. Instead, we:
//
// 1. Return HTTP 200 OK (looks successful to the bot)
// 2. Serve a fake HTML page that looks real
// 3. The page contains tricks that waste the bot's resources:
//    - Infinite scrolling that never ends
//    - "Loading..." spinners that never finish
//    - Slow-drip responses that trickle data byte-by-byte
//    - Fake content generation that runs forever
//    - JavaScript that consumes CPU in loops
//
// This is "The Infinite Void" - bots enter but never leave.
// =============================================================================
package middleware

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"sentinel-x/internal/config"
)

// =============================================================================
// TARPIT CONFIGURATION
// =============================================================================

// TarpitConfig holds tarpit settings
type TarpitConfig struct {
	Enabled           bool          // Enable tarpit feature
	RiskThreshold     int           // Risk score threshold to trigger tarpit (0-100)
	SlowDripEnabled   bool          // Enable slow byte-by-byte response
	SlowDripDelayMs   int           // Delay between bytes in slow drip mode
	InfiniteLoopJS    bool          // Include CPU-burning JavaScript
	FakeContentLength int           // Fake Content-Length header (tricks bots into waiting)
	MaxTrapDuration   time.Duration // Maximum time to keep a bot trapped
}

// DefaultTarpitConfig returns sensible defaults
func DefaultTarpitConfig() *TarpitConfig {
	return &TarpitConfig{
		Enabled:           true,
		RiskThreshold:     85, // Only trap high-confidence bots
		SlowDripEnabled:   true,
		SlowDripDelayMs:   100, // 100ms between bytes
		InfiniteLoopJS:    true,
		FakeContentLength: 1024 * 1024 * 10, // Fake 10MB response
		MaxTrapDuration:   5 * time.Minute,
	}
}

// =============================================================================
// TARPIT STATISTICS
// =============================================================================

// TarpitStats tracks tarpit usage
type TarpitStats struct {
	BotsTrapped      uint64
	TotalTrapTime    uint64 // Total seconds bots spent trapped
	CurrentlyTrapped int64  // Currently active traps
	TrapAborted      uint64 // Bots that disconnected
}

var globalTarpitStats = &TarpitStats{}

// GetTarpitStats returns current tarpit statistics
func GetTarpitStats() TarpitStats {
	return TarpitStats{
		BotsTrapped:      atomic.LoadUint64(&globalTarpitStats.BotsTrapped),
		TotalTrapTime:    atomic.LoadUint64(&globalTarpitStats.TotalTrapTime),
		CurrentlyTrapped: atomic.LoadInt64(&globalTarpitStats.CurrentlyTrapped),
		TrapAborted:      atomic.LoadUint64(&globalTarpitStats.TrapAborted),
	}
}

// =============================================================================
// TARPIT MIDDLEWARE
// =============================================================================

// TarpitMiddleware implements the Infinite Void trap
type TarpitMiddleware struct {
	config     *config.Config
	tarpitCfg  *TarpitConfig
}

// Tarpit creates the tarpit middleware
// This should be placed AFTER bot detection to use the risk score
func Tarpit(cfg *config.Config) Middleware {
	tarpitCfg := DefaultTarpitConfig()

	tm := &TarpitMiddleware{
		config:    cfg,
		tarpitCfg: tarpitCfg,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if tarpit is disabled
			if !tarpitCfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for trusted IPs
			if isTrusted, ok := r.Context().Value(IsTrustedKey).(bool); ok && isTrusted {
				next.ServeHTTP(w, r)
				return
			}

			// Get risk score from context (set by bot detection middleware)
			riskScore := 0
			if score, ok := r.Context().Value(RiskScoreKey).(int); ok {
				riskScore = score
			}

			// Only trap high-confidence bots
			if riskScore < tarpitCfg.RiskThreshold {
				next.ServeHTTP(w, r)
				return
			}

			// === ACTIVATE THE TRAP ===
			clientIP := GetTrustedClientIP(r)
			log.Printf("[TARPIT] 🕳️ Bot trapped! IP: %s, Risk Score: %d, UA: %s",
				clientIP, riskScore, r.UserAgent())

			atomic.AddUint64(&globalTarpitStats.BotsTrapped, 1)
			atomic.AddInt64(&globalTarpitStats.CurrentlyTrapped, 1)
			defer atomic.AddInt64(&globalTarpitStats.CurrentlyTrapped, -1)

			startTime := time.Now()
			defer func() {
				trapDuration := time.Since(startTime)
				atomic.AddUint64(&globalTarpitStats.TotalTrapTime, uint64(trapDuration.Seconds()))
				log.Printf("[TARPIT] Bot released after %v: %s", trapDuration, clientIP)
			}()

			// Choose trap type based on request characteristics
			tm.activateTrap(w, r, riskScore)
		})
	}
}

// activateTrap selects and activates the appropriate trap
func (tm *TarpitMiddleware) activateTrap(w http.ResponseWriter, r *http.Request, riskScore int) {
	// Check Accept header to determine trap type
	accept := r.Header.Get("Accept")

	switch {
	case strings.Contains(accept, "application/json"):
		// API bot - serve infinite JSON
		tm.serveInfiniteJSON(w, r)
	case strings.Contains(accept, "text/html") || accept == "" || accept == "*/*":
		// Browser/scraper bot - serve infinite HTML
		tm.serveInfiniteHTML(w, r)
	default:
		// Generic slow drip
		tm.serveSlowDrip(w, r)
	}
}

// =============================================================================
// TRAP TYPE 1: INFINITE HTML PAGE
// =============================================================================

// serveInfiniteHTML serves a fake HTML page that never finishes loading
func (tm *TarpitMiddleware) serveInfiniteHTML(w http.ResponseWriter, r *http.Request) {
	// Set headers to look like a real response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked") // Allow streaming
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	
	// Fake a large content length to trick bots into waiting
	if tm.tarpitCfg.FakeContentLength > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", tm.tarpitCfg.FakeContentLength))
	}

	w.WriteHeader(http.StatusOK)

	// Get flusher for streaming
	flusher, canFlush := w.(http.Flusher)

	// Send initial HTML that looks legitimate
	initialHTML := tm.generateFakeHTMLStart()
	w.Write([]byte(initialHTML))
	if canFlush {
		flusher.Flush()
	}

	// Create timeout context
	deadline := time.Now().Add(tm.tarpitCfg.MaxTrapDuration)

	// Infinite content loop - keeps sending fake content
	contentIndex := 0
	for {
		// Check if we've exceeded max trap duration
		if time.Now().After(deadline) {
			break
		}

		// Check if client disconnected
		select {
		case <-r.Context().Done():
			atomic.AddUint64(&globalTarpitStats.TrapAborted, 1)
			return
		default:
		}

		// Generate and send fake content
		fakeContent := tm.generateFakeContentChunk(contentIndex)
		_, err := w.Write([]byte(fakeContent))
		if err != nil {
			// Client disconnected
			atomic.AddUint64(&globalTarpitStats.TrapAborted, 1)
			return
		}

		if canFlush {
			flusher.Flush()
		}

		contentIndex++

		// Slow down to waste more time
		time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
	}

	// Send closing HTML (bot probably gave up by now)
	w.Write([]byte(tm.generateFakeHTMLEnd()))
}

// generateFakeHTMLStart creates the beginning of a fake page
func (tm *TarpitMiddleware) generateFakeHTMLStart() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loading Content...</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        .header {
            background: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
            border-radius: 10px;
        }
        .content-card {
            background: white;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            animation: fadeIn 0.5s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .skeleton {
            background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            height: 20px;
            border-radius: 4px;
            margin: 10px 0;
        }
        @keyframes shimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }
        .progress-bar {
            width: 100%;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            animation: progress 3s ease-in-out infinite;
        }
        @keyframes progress {
            0% { width: 0%; }
            50% { width: 70%; }
            100% { width: 0%; }
        }
        /* Hidden infinite scroll trigger */
        .scroll-trigger {
            height: 1px;
            visibility: hidden;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📰 Latest News</h1>
            <div class="progress-bar"><div class="progress-fill"></div></div>
            <p>Loading personalized content for you...</p>
        </div>
        
        <div id="content-area">
            <!-- Dynamic content will appear here -->
            <div class="loading">
                <div class="spinner"></div>
                <span style="margin-left: 1rem;">Fetching articles...</span>
            </div>
`
}

// generateFakeContentChunk creates fake content to keep the bot waiting
func (tm *TarpitMiddleware) generateFakeContentChunk(index int) string {
	// Array of fake article templates
	titles := []string{
		"Breaking: Major Discovery in Technology Sector",
		"Scientists Announce Breakthrough Research Results",
		"Global Markets React to Latest Economic Data",
		"New Study Reveals Surprising Health Benefits",
		"Industry Leaders Gather for Annual Summit",
		"Exclusive Interview with Leading Expert",
		"Analysis: What This Means for the Future",
		"Report: Trends to Watch in Coming Months",
	}

	excerpts := []string{
		"Experts are calling this a significant development that could reshape the industry...",
		"According to new research published today, findings suggest a major shift in...",
		"Analysis from leading institutions indicates that upcoming changes will affect...",
		"Sources close to the matter have confirmed that negotiations are ongoing...",
		"In a statement released earlier today, officials announced that progress has been...",
	}

	title := titles[index%len(titles)]
	excerpt := excerpts[index%len(excerpts)]
	
	// Add some random delay simulation in comments (wastes parser time)
	return fmt.Sprintf(`
            <!-- chunk-%d-start -->
            <div class="content-card" data-index="%d" data-loaded="%d">
                <h2>%s</h2>
                <p class="excerpt">%s</p>
                <div class="skeleton" style="width: %d%%;"></div>
                <div class="skeleton" style="width: %d%%;"></div>
                <div class="skeleton" style="width: %d%%;"></div>
                <small>Loading more details...</small>
            </div>
            <div class="scroll-trigger" data-next="%d"></div>
            <!-- chunk-%d-end -->
`,
		index, index, time.Now().UnixMilli(),
		title, excerpt,
		60+rand.Intn(30), 70+rand.Intn(25), 50+rand.Intn(40),
		index+1, index,
	)
}

// generateFakeHTMLEnd closes the HTML document
func (tm *TarpitMiddleware) generateFakeHTMLEnd() string {
	return `
        </div>
        
        <div class="loading">
            <div class="spinner"></div>
            <span>Preparing more content...</span>
        </div>
    </div>
    
    <script>
        // Infinite scroll simulation (burns CPU)
        let loadCount = 0;
        const maxLoads = 999999;
        
        function loadMore() {
            if (loadCount >= maxLoads) return;
            loadCount++;
            
            // CPU-burning operations disguised as content loading
            const heavy = Array(10000).fill(0).map((_, i) => Math.sqrt(i * Math.random()));
            
            // Simulate scroll trigger
            setTimeout(loadMore, 100 + Math.random() * 200);
        }
        
        // Start the infinite loop
        document.addEventListener('DOMContentLoaded', loadMore);
        
        // Prevent page unload (keeps bot's browser tab active)
        window.onbeforeunload = function() {
            return "Content is still loading...";
        };
        
        // Infinite XHR requests (burns network resources)
        function fakeXHR() {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', '/api/content?page=' + loadCount + '&t=' + Date.now(), true);
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    setTimeout(fakeXHR, 500);
                }
            };
            xhr.send();
        }
        setTimeout(fakeXHR, 1000);
    </script>
</body>
</html>`
}

// =============================================================================
// TRAP TYPE 2: INFINITE JSON API
// =============================================================================

// serveInfiniteJSON serves an infinite JSON response for API bots
func (tm *TarpitMiddleware) serveInfiniteJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	// Start JSON array
	w.Write([]byte(`{"status":"success","data":[`))
	if canFlush {
		flusher.Flush()
	}

	deadline := time.Now().Add(tm.tarpitCfg.MaxTrapDuration)
	itemIndex := 0

	for {
		if time.Now().After(deadline) {
			break
		}

		select {
		case <-r.Context().Done():
			atomic.AddUint64(&globalTarpitStats.TrapAborted, 1)
			return
		default:
		}

		// Generate fake JSON item
		if itemIndex > 0 {
			w.Write([]byte(","))
		}

		fakeItem := fmt.Sprintf(`{"id":%d,"title":"Item %d","content":"Loading detailed content...","timestamp":%d,"status":"pending"}`,
			itemIndex, itemIndex, time.Now().UnixMilli())
		
		_, err := w.Write([]byte(fakeItem))
		if err != nil {
			atomic.AddUint64(&globalTarpitStats.TrapAborted, 1)
			return
		}

		if canFlush {
			flusher.Flush()
		}

		itemIndex++
		time.Sleep(time.Duration(200+rand.Intn(500)) * time.Millisecond)
	}

	// Close JSON (bot probably gone by now)
	w.Write([]byte(`],"total":` + fmt.Sprintf("%d", itemIndex) + `}`))
}

// =============================================================================
// TRAP TYPE 3: SLOW DRIP RESPONSE
// =============================================================================

// serveSlowDrip sends response byte-by-byte extremely slowly
func (tm *TarpitMiddleware) serveSlowDrip(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	// Message to drip out slowly
	message := `Welcome to our service. Your request is being processed. Please wait while we prepare your content. This may take a few moments. Thank you for your patience. Loading resources... Connecting to servers... Fetching data... Processing request... Almost there... `

	// Repeat message to make it longer
	fullMessage := strings.Repeat(message, 100)

	deadline := time.Now().Add(tm.tarpitCfg.MaxTrapDuration)

	for i := 0; i < len(fullMessage); i++ {
		if time.Now().After(deadline) {
			break
		}

		select {
		case <-r.Context().Done():
			atomic.AddUint64(&globalTarpitStats.TrapAborted, 1)
			return
		default:
		}

		// Send one byte at a time
		_, err := w.Write([]byte{fullMessage[i]})
		if err != nil {
			atomic.AddUint64(&globalTarpitStats.TrapAborted, 1)
			return
		}

		if canFlush {
			flusher.Flush()
		}

		// Slow delay between bytes
		time.Sleep(time.Duration(tm.tarpitCfg.SlowDripDelayMs) * time.Millisecond)
	}
}

// =============================================================================
// TRAP TYPE 4: ENDLESSLY REDIRECTING RESPONSE
// =============================================================================

// ServeEndlessRedirect sends the bot on an infinite redirect loop
func ServeEndlessRedirect(w http.ResponseWriter, r *http.Request) {
	// Generate a random path for the next redirect
	nextPath := fmt.Sprintf("/content/%d/%d/page", 
		rand.Intn(1000000), 
		time.Now().UnixNano()%100000)

	// Set a cookie to track redirect count (bot won't notice)
	cookie, _ := r.Cookie("_sx_rd")
	redirectCount := 0
	if cookie != nil {
		fmt.Sscanf(cookie.Value, "%d", &redirectCount)
	}
	redirectCount++

	http.SetCookie(w, &http.Cookie{
		Name:     "_sx_rd",
		Value:    fmt.Sprintf("%d", redirectCount),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	})

	// After many redirects, trap them in slow drip instead
	if redirectCount > 10 {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>Loading...</h1><p>Please wait...</p></body></html>"))
		time.Sleep(30 * time.Second)
		return
	}

	// Send redirect
	w.Header().Set("Location", nextPath)
	w.WriteHeader(http.StatusFound) // 302
}

// =============================================================================
// TARPIT RESPONSE WRITER
// =============================================================================

// TarpitResponseWriter wraps http.ResponseWriter to add slow-drip capability
type TarpitResponseWriter struct {
	http.ResponseWriter
	slowMode    bool
	delayMs     int
	bytesWritten int64
}

// NewTarpitResponseWriter creates a new tarpit response writer
func NewTarpitResponseWriter(w http.ResponseWriter, slowMode bool, delayMs int) *TarpitResponseWriter {
	return &TarpitResponseWriter{
		ResponseWriter: w,
		slowMode:       slowMode,
		delayMs:        delayMs,
	}
}

// Write implements slow-drip writing
func (tw *TarpitResponseWriter) Write(data []byte) (int, error) {
	if !tw.slowMode {
		n, err := tw.ResponseWriter.Write(data)
		tw.bytesWritten += int64(n)
		return n, err
	}

	// Slow drip mode - write byte by byte
	flusher, canFlush := tw.ResponseWriter.(http.Flusher)
	
	for i, b := range data {
		_, err := tw.ResponseWriter.Write([]byte{b})
		if err != nil {
			return i, err
		}
		tw.bytesWritten++
		
		if canFlush {
			flusher.Flush()
		}
		
		time.Sleep(time.Duration(tw.delayMs) * time.Millisecond)
	}
	
	return len(data), nil
}

// Flush implements http.Flusher
func (tw *TarpitResponseWriter) Flush() {
	if flusher, ok := tw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker for WebSocket support
func (tw *TarpitResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := tw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

