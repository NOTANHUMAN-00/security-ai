// =============================================================================
// SENTINEL-X ADVANCED PERSISTENCE & INTEGRITY
// =============================================================================
//
// CUTTING-EDGE FEATURES:
//
// 1. ETAG "SUPERCOOKIE" TRACKING (Undead Cookie)
//    - Bots clear cookies/localStorage to appear as new users
//    - Browser cache is rarely cleared! We use ETag headers to track
//    - Even after clearing cookies, If-None-Match reveals the user
//
// 2. HMAC REQUEST SIGNING (Anti-Replay)
//    - Every request cryptographically signed with session key
//    - Signature includes timestamp - expires in 5 seconds
//    - Captured requests become useless immediately
//
// 3. VM CLOCK SKEW ANALYSIS (The "Matrix" Glitch)
//    - Real devices have stable hardware clocks
//    - VMs on cheap hosts have clock drift/jitter
//    - Measure client vs server time passage - detect VMs
//
// 4. CANARY DOM ELEMENTS (CSS Rendering Check)
//    - Headless browsers don't render CSS perfectly
//    - Check computed styles of hidden elements
//    - Wrong values = fake browser
//
// =============================================================================
package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel-x/internal/storage"
)

// =============================================================================
// FEATURE 1: ETAG "SUPERCOOKIE" TRACKING (The Undead Cookie)
// =============================================================================
//
// HOW IT WORKS:
//   1. Client requests /logo.png (or any static asset)
//   2. We generate a unique ID and return: ETag: "user-uuid-12345"
//   3. Browser caches this in its HTTP cache (NOT cookies!)
//   4. Bot clears cookies & localStorage thinking it's "new"
//   5. Bot requests /logo.png again
//   6. Browser automatically sends: If-None-Match: "user-uuid-12345"
//   7. GOTCHA! We identify the "new" session as the banned user
//
// WHY THIS WORKS:
//   - HTTP cache is designed to persist across sessions
//   - "Clear browsing data" often doesn't clear cache by default
//   - ETags are RFC-compliant and browser-native
//   - Works even without JavaScript enabled!
//
// =============================================================================

// ETagTracker tracks users via ETag headers
type ETagTracker struct {
	store      storage.Store
	secret     []byte
	trackedIPs map[string]string // ETag -> IP mapping for linking sessions
	mu         sync.RWMutex
}

// ETagStats tracks ETag-based tracking statistics
type ETagStats struct {
	TotalTracked     uint64
	ReturningUsers   uint64
	LinkedSessions   uint64
	BannedReturned   uint64
}

var etagStats = &ETagStats{}

// GetETagStats returns current ETag tracking stats
func GetETagStats() ETagStats {
	return ETagStats{
		TotalTracked:   atomic.LoadUint64(&etagStats.TotalTracked),
		ReturningUsers: atomic.LoadUint64(&etagStats.ReturningUsers),
		LinkedSessions: atomic.LoadUint64(&etagStats.LinkedSessions),
		BannedReturned: atomic.LoadUint64(&etagStats.BannedReturned),
	}
}

// NewETagTracker creates a new ETag tracker
func NewETagTracker(store storage.Store) *ETagTracker {
	secret := make([]byte, 32)
	rand.Read(secret)
	
	return &ETagTracker{
		store:      store,
		secret:     secret,
		trackedIPs: make(map[string]string),
	}
}

// generateETag creates a unique, signed ETag for a user
func (et *ETagTracker) generateETag(clientIP string) string {
	// Create unique ID
	idBytes := make([]byte, 12)
	rand.Read(idBytes)
	
	// Include IP hash for verification
	ipHash := sha256.Sum256([]byte(clientIP))
	
	// Combine: random + IP hash prefix
	combined := append(idBytes, ipHash[:4]...)
	
	// Sign with server secret
	mac := hmac.New(sha256.New, et.secret)
	mac.Write(combined)
	signature := mac.Sum(nil)[:8]
	
	// Encode: base64(id + signature)
	final := append(combined, signature...)
	return base64.RawURLEncoding.EncodeToString(final)
}

// verifyETag checks if an ETag is valid and extracts info
func (et *ETagTracker) verifyETag(etag string) (isValid bool, extractedData []byte) {
	// Remove quotes if present
	etag = strings.Trim(etag, "\"")
	
	// Decode
	decoded, err := base64.RawURLEncoding.DecodeString(etag)
	if err != nil || len(decoded) < 24 {
		return false, nil
	}
	
	// Split: data | signature
	data := decoded[:16]
	signature := decoded[16:24]
	
	// Verify signature
	mac := hmac.New(sha256.New, et.secret)
	mac.Write(data)
	expectedSig := mac.Sum(nil)[:8]
	
	if !hmac.Equal(signature, expectedSig) {
		return false, nil
	}
	
	return true, data
}

// ServeTrackedAsset serves a static asset with ETag tracking
func (et *ETagTracker) ServeTrackedAsset(assetPath string, assetContent []byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := GetTrustedClientIP(r)
		ctx := r.Context()
		
		// Check for If-None-Match header (returning user!)
		incomingETag := r.Header.Get("If-None-Match")
		
		if incomingETag != "" {
			// User has been here before!
			isValid, _ := et.verifyETag(incomingETag)
			
			if isValid {
				atomic.AddUint64(&etagStats.ReturningUsers, 1)
				
				// Look up if this ETag is from a banned session
				if et.store != nil {
					key := fmt.Sprintf("etag:banned:%s", incomingETag)
					if exists, _ := et.store.Exists(ctx, key); exists {
						// This is a banned user trying to return!
						atomic.AddUint64(&etagStats.BannedReturned, 1)
						log.Printf("[ETAG] 🧟 Banned user returned via ETag! IP: %s, ETag: %s", 
							clientIP, incomingETag[:16]+"...")
						
						// Link new IP to banned status
						banKey := fmt.Sprintf("sentinel:banned:%s", clientIP)
						et.store.Set(ctx, banKey, "etag_linked", 24*time.Hour)
					}
				}
				
				// Check if we need to link sessions
				et.mu.RLock()
				oldIP, wasTracked := et.trackedIPs[incomingETag]
				et.mu.RUnlock()
				
				if wasTracked && oldIP != clientIP {
					// Same user, different IP!
					atomic.AddUint64(&etagStats.LinkedSessions, 1)
					log.Printf("[ETAG] 🔗 Session linked: %s → %s (same user, new IP)", 
						oldIP, clientIP)
				}
				
				// Update tracking
				et.mu.Lock()
				et.trackedIPs[incomingETag] = clientIP
				et.mu.Unlock()
				
				// Return 304 Not Modified (saves bandwidth, keeps tracking)
				w.Header().Set("ETag", incomingETag)
				w.Header().Set("Cache-Control", "max-age=31536000") // 1 year
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		
		// New user - generate ETag
		newETag := fmt.Sprintf("\"%s\"", et.generateETag(clientIP))
		atomic.AddUint64(&etagStats.TotalTracked, 1)
		
		// Store the mapping
		et.mu.Lock()
		et.trackedIPs[newETag] = clientIP
		et.mu.Unlock()
		
		// Store in Redis for persistence
		if et.store != nil {
			key := fmt.Sprintf("etag:ip:%s", newETag)
			et.store.Set(ctx, key, clientIP, 30*24*time.Hour) // 30 days
		}
		
		log.Printf("[ETAG] 📌 New user tracked: %s, ETag: %s", clientIP, newETag[:16]+"...")
		
		// Serve the asset with tracking headers
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", newETag)
		w.Header().Set("Cache-Control", "max-age=31536000, immutable") // Force caching
		w.Header().Set("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		w.Write(assetContent)
	}
}

// MarkETagAsBanned marks an ETag as belonging to a banned user
func (et *ETagTracker) MarkETagAsBanned(etag string) {
	if et.store != nil {
		key := fmt.Sprintf("etag:banned:%s", strings.Trim(etag, "\""))
		et.store.Set(nil, key, "1", 30*24*time.Hour) // 30 days
	}
}

// =============================================================================
// FEATURE 2: HMAC REQUEST SIGNING (Anti-Replay Protection)
// =============================================================================
//
// THE PROBLEM:
//   Attacker captures a valid request (with solved PoW, valid session)
//   and replays it 1000 times to spam your API.
//
// THE SOLUTION:
//   1. Server sends session_key to client on page load
//   2. Client signs every request: HMAC(body + timestamp, session_key)
//   3. Server verifies:
//      a. Signature is correct
//      b. Timestamp is within 5 seconds
//   4. Result: Captured request becomes stale in 5 seconds!
//
// HEADERS:
//   X-Signature: base64(HMAC-SHA256)
//   X-Timestamp: Unix timestamp in milliseconds
//   X-Nonce: Random value to prevent exact duplicates
//
// =============================================================================

// HMACConfig configures HMAC signing middleware
type HMACConfig struct {
	Enabled        bool
	MaxAge         time.Duration // Max age for valid signatures (default 5s)
	RequiredPaths  []string      // Paths that require signing (e.g., /api/*)
	SessionTTL     time.Duration // How long session keys are valid
}

// HMACSession represents a client's signing session
type HMACSession struct {
	Key       []byte
	CreatedAt time.Time
	ClientIP  string
}

// HMACMiddleware manages request signing
type HMACMiddleware struct {
	config   *HMACConfig
	sessions map[string]*HMACSession // session_id -> session
	mu       sync.RWMutex
	usedNonces map[string]time.Time  // Prevent nonce reuse
	nonceMu  sync.RWMutex
}

// HMACStats tracks HMAC signing statistics
type HMACStats struct {
	TotalVerified   uint64
	ValidSignatures uint64
	InvalidSignature uint64
	ExpiredTimestamp uint64
	ReplayAttempts   uint64
	SessionsCreated  uint64
}

var hmacStats = &HMACStats{}

// GetHMACStats returns current HMAC stats
func GetHMACStats() HMACStats {
	return HMACStats{
		TotalVerified:    atomic.LoadUint64(&hmacStats.TotalVerified),
		ValidSignatures:  atomic.LoadUint64(&hmacStats.ValidSignatures),
		InvalidSignature: atomic.LoadUint64(&hmacStats.InvalidSignature),
		ExpiredTimestamp: atomic.LoadUint64(&hmacStats.ExpiredTimestamp),
		ReplayAttempts:   atomic.LoadUint64(&hmacStats.ReplayAttempts),
		SessionsCreated:  atomic.LoadUint64(&hmacStats.SessionsCreated),
	}
}

// NewHMACMiddleware creates a new HMAC signing middleware
func NewHMACMiddleware(cfg *HMACConfig) *HMACMiddleware {
	if cfg == nil {
		cfg = &HMACConfig{
			Enabled:   true,
			MaxAge:    5 * time.Second,
			SessionTTL: 1 * time.Hour,
		}
	}
	
	hm := &HMACMiddleware{
		config:     cfg,
		sessions:   make(map[string]*HMACSession),
		usedNonces: make(map[string]time.Time),
	}
	
	// Start nonce cleanup goroutine
	go hm.cleanupNonces()
	
	return hm
}

// CreateSession creates a new signing session for a client
func (hm *HMACMiddleware) CreateSession(clientIP string) (sessionID string, sessionKey string) {
	// Generate session ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	sessionID = base64.RawURLEncoding.EncodeToString(idBytes)
	
	// Generate signing key
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	
	session := &HMACSession{
		Key:       keyBytes,
		CreatedAt: time.Now(),
		ClientIP:  clientIP,
	}
	
	hm.mu.Lock()
	hm.sessions[sessionID] = session
	hm.mu.Unlock()
	
	atomic.AddUint64(&hmacStats.SessionsCreated, 1)
	
	return sessionID, base64.StdEncoding.EncodeToString(keyBytes)
}

// VerifyRequest verifies a signed request
func (hm *HMACMiddleware) VerifyRequest(r *http.Request, body []byte) (valid bool, reason string) {
	atomic.AddUint64(&hmacStats.TotalVerified, 1)
	
	// Get required headers
	signature := r.Header.Get("X-Signature")
	timestampStr := r.Header.Get("X-Timestamp")
	nonce := r.Header.Get("X-Nonce")
	sessionID := r.Header.Get("X-Session-ID")
	
	if signature == "" || timestampStr == "" || sessionID == "" {
		return false, "missing_headers"
	}
	
	// Check timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, "invalid_timestamp"
	}
	
	requestTime := time.Unix(timestamp/1000, (timestamp%1000)*1000000)
	age := time.Since(requestTime)
	
	// Allow for slight clock differences
	if age < -30*time.Second || age > hm.config.MaxAge {
		atomic.AddUint64(&hmacStats.ExpiredTimestamp, 1)
		return false, fmt.Sprintf("timestamp_expired: age=%v", age)
	}
	
	// Check nonce (prevent replay)
	if nonce != "" {
		hm.nonceMu.RLock()
		_, used := hm.usedNonces[nonce]
		hm.nonceMu.RUnlock()
		
		if used {
			atomic.AddUint64(&hmacStats.ReplayAttempts, 1)
			return false, "nonce_reused"
		}
		
		// Mark nonce as used
		hm.nonceMu.Lock()
		hm.usedNonces[nonce] = time.Now()
		hm.nonceMu.Unlock()
	}
	
	// Get session
	hm.mu.RLock()
	session, exists := hm.sessions[sessionID]
	hm.mu.RUnlock()
	
	if !exists {
		return false, "invalid_session"
	}
	
	// Check session age
	if time.Since(session.CreatedAt) > hm.config.SessionTTL {
		return false, "session_expired"
	}
	
	// Compute expected signature
	// Signature = HMAC-SHA256(method + path + timestamp + nonce + body, key)
	message := fmt.Sprintf("%s|%s|%s|%s|%s",
		r.Method,
		r.URL.Path,
		timestampStr,
		nonce,
		string(body),
	)
	
	mac := hmac.New(sha256.New, session.Key)
	mac.Write([]byte(message))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	
	// Compare signatures
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		atomic.AddUint64(&hmacStats.InvalidSignature, 1)
		return false, "signature_mismatch"
	}
	
	atomic.AddUint64(&hmacStats.ValidSignatures, 1)
	return true, ""
}

// Middleware creates the HMAC verification middleware
func (hm *HMACMiddleware) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path requires signing
			requiresSigning := false
			for _, path := range hm.config.RequiredPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					requiresSigning = true
					break
				}
			}
			
			if !requiresSigning || r.Method == http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			
			// Read body for verification
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request", http.StatusBadRequest)
				return
			}
			
			// Verify signature
			valid, reason := hm.VerifyRequest(r, body)
			if !valid {
				log.Printf("[HMAC] ❌ Invalid signature from %s: %s", 
					GetTrustedClientIP(r), reason)
				http.Error(w, "Invalid signature", http.StatusForbidden)
				return
			}
			
			// Restore body for downstream handlers
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			
			next.ServeHTTP(w, r)
		})
	}
}

// cleanupNonces periodically removes old nonces
func (hm *HMACMiddleware) cleanupNonces() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		cutoff := time.Now().Add(-hm.config.MaxAge * 2)
		
		hm.nonceMu.Lock()
		for nonce, usedAt := range hm.usedNonces {
			if usedAt.Before(cutoff) {
				delete(hm.usedNonces, nonce)
			}
		}
		hm.nonceMu.Unlock()
	}
}

// GenerateClientSigningScript generates client-side signing JavaScript
func GenerateClientSigningScript(sessionID, sessionKey string) string {
	return fmt.Sprintf(`
<script>
(function() {
    'use strict';
    
    const SESSION_ID = '%s';
    const SESSION_KEY = '%s';
    
    // Convert base64 key to ArrayBuffer
    const keyBytes = Uint8Array.from(atob(SESSION_KEY), c => c.charCodeAt(0));
    let cryptoKey = null;
    
    // Import the key for HMAC
    async function initKey() {
        cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
    }
    initKey();
    
    // Generate random nonce
    function generateNonce() {
        const arr = new Uint8Array(16);
        crypto.getRandomValues(arr);
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // Sign a request
    async function signRequest(method, path, body) {
        if (!cryptoKey) await initKey();
        
        const timestamp = Date.now().toString();
        const nonce = generateNonce();
        
        const message = method + '|' + path + '|' + timestamp + '|' + nonce + '|' + body;
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        
        const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
        
        return {
            'X-Session-ID': SESSION_ID,
            'X-Timestamp': timestamp,
            'X-Nonce': nonce,
            'X-Signature': signatureBase64
        };
    }
    
    // Override fetch to auto-sign requests
    const originalFetch = window.fetch;
    window.fetch = async function(url, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        
        // Only sign POST/PUT/DELETE to /api/*
        if (['POST', 'PUT', 'DELETE'].includes(method) && 
            url.toString().includes('/api/')) {
            
            const body = options.body || '';
            const path = new URL(url, location.origin).pathname;
            const headers = await signRequest(method, path, body);
            
            options.headers = {
                ...(options.headers || {}),
                ...headers
            };
        }
        
        return originalFetch.call(this, url, options);
    };
    
    console.log('[Sentinel] Request signing initialized');
})();
</script>
`, sessionID, sessionKey)
}

// =============================================================================
// FEATURE 3: VM CLOCK SKEW ANALYSIS (The "Matrix" Glitch)
// =============================================================================
//
// THE PROBLEM:
//   Bots run on cheap cloud VMs with inconsistent clocks:
//   - VM clock drift vs host
//   - Container throttling affects time perception
//   - Headless browsers may have different timing behavior
//
// THE DETECTION:
//   1. Server sends ServerTime_Start + a computation task
//   2. Client runs the task (e.g., calculate for exactly 100ms)
//   3. Client reports ClientTime_Elapsed
//   4. Server checks: if ServerTime_Elapsed >> ClientTime_Elapsed
//      → Client is lying or running in a throttled environment
//
// TIMING ANALYSIS:
//   Real Device: Server 100ms ≈ Client 100ms (within RTT)
//   Throttled VM: Server 500ms but Client claims 100ms
//   Overloaded Docker: High variance in timings
//
// =============================================================================

// TimingChallenge represents a timing verification challenge
type TimingChallenge struct {
	ChallengeID       string    `json:"challenge_id"`
	ServerStartTime   int64     `json:"server_start_time"`
	ExpectedDuration  int64     `json:"expected_duration"` // milliseconds
	TaskComplexity    int       `json:"task_complexity"`
	ExpiresAt         int64     `json:"expires_at"`
}

// TimingResponse is the client's timing report
type TimingResponse struct {
	ChallengeID      string  `json:"challenge_id"`
	ClientStartTime  int64   `json:"client_start_time"`
	ClientEndTime    int64   `json:"client_end_time"`
	ClientElapsed    int64   `json:"client_elapsed"`
	TaskResult       string  `json:"task_result"`
}

// TimingAnalysis is the result of timing verification
type TimingAnalysis struct {
	ServerElapsed    int64   `json:"server_elapsed"`
	ClientElapsed    int64   `json:"client_elapsed"`
	Discrepancy      float64 `json:"discrepancy"` // ratio of server/client
	IsAnomaly        bool    `json:"is_anomaly"`
	AnomalyReason    string  `json:"anomaly_reason,omitempty"`
	ConfidenceScore  float64 `json:"confidence_score"` // 0-100
}

// VMDetector detects VMs via timing analysis
type VMDetector struct {
	challenges map[string]*TimingChallenge
	mu         sync.RWMutex
}

// VMStats tracks VM detection statistics
type VMStats struct {
	TotalChallenges   uint64
	Completed         uint64
	VMDetected        uint64
	ThrottledDetected uint64
	HighJitter        uint64
	Passed            uint64
}

var vmStats = &VMStats{}

// GetVMStats returns VM detection stats
func GetVMStats() VMStats {
	return VMStats{
		TotalChallenges:   atomic.LoadUint64(&vmStats.TotalChallenges),
		Completed:         atomic.LoadUint64(&vmStats.Completed),
		VMDetected:        atomic.LoadUint64(&vmStats.VMDetected),
		ThrottledDetected: atomic.LoadUint64(&vmStats.ThrottledDetected),
		HighJitter:        atomic.LoadUint64(&vmStats.HighJitter),
		Passed:            atomic.LoadUint64(&vmStats.Passed),
	}
}

// NewVMDetector creates a new VM detector
func NewVMDetector() *VMDetector {
	vmd := &VMDetector{
		challenges: make(map[string]*TimingChallenge),
	}
	
	// Cleanup goroutine
	go vmd.cleanup()
	
	return vmd
}

// CreateChallenge generates a new timing challenge
func (vmd *VMDetector) CreateChallenge() *TimingChallenge {
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	
	challenge := &TimingChallenge{
		ChallengeID:      hex.EncodeToString(idBytes),
		ServerStartTime:  time.Now().UnixMilli(),
		ExpectedDuration: 100, // 100ms computation
		TaskComplexity:   1000000, // Iterations
		ExpiresAt:        time.Now().Add(30 * time.Second).UnixMilli(),
	}
	
	vmd.mu.Lock()
	vmd.challenges[challenge.ChallengeID] = challenge
	vmd.mu.Unlock()
	
	atomic.AddUint64(&vmStats.TotalChallenges, 1)
	
	return challenge
}

// AnalyzeResponse analyzes a timing response
func (vmd *VMDetector) AnalyzeResponse(response *TimingResponse) *TimingAnalysis {
	vmd.mu.RLock()
	challenge, exists := vmd.challenges[response.ChallengeID]
	vmd.mu.RUnlock()
	
	if !exists {
		return &TimingAnalysis{
			IsAnomaly:     true,
			AnomalyReason: "unknown_challenge",
		}
	}
	
	atomic.AddUint64(&vmStats.Completed, 1)
	
	// Calculate server-side elapsed time
	serverNow := time.Now().UnixMilli()
	serverElapsed := serverNow - challenge.ServerStartTime
	
	// Check for expiry
	if serverNow > challenge.ExpiresAt {
		return &TimingAnalysis{
			IsAnomaly:     true,
			AnomalyReason: "challenge_expired",
		}
	}
	
	analysis := &TimingAnalysis{
		ServerElapsed:   serverElapsed,
		ClientElapsed:   response.ClientElapsed,
		IsAnomaly:       false,
		ConfidenceScore: 100,
	}
	
	// Calculate discrepancy ratio
	if response.ClientElapsed > 0 {
		analysis.Discrepancy = float64(serverElapsed) / float64(response.ClientElapsed)
	} else {
		analysis.IsAnomaly = true
		analysis.AnomalyReason = "zero_client_time"
		return analysis
	}
	
	// Heuristic 1: Server took much longer than client claims
	// Account for ~200ms network RTT
	expectedMin := float64(response.ClientElapsed) + 200 // Allow 200ms RTT
	if float64(serverElapsed) > expectedMin*2 {
		// Server saw 2x the time the client claims
		analysis.IsAnomaly = true
		analysis.AnomalyReason = "timing_discrepancy"
		analysis.ConfidenceScore = math.Min(100, analysis.Discrepancy*30)
		atomic.AddUint64(&vmStats.ThrottledDetected, 1)
	}
	
	// Heuristic 2: Client claims too fast (impossible)
	if response.ClientElapsed < challenge.ExpectedDuration/2 {
		analysis.IsAnomaly = true
		analysis.AnomalyReason = "impossibly_fast"
		analysis.ConfidenceScore = 95
		atomic.AddUint64(&vmStats.VMDetected, 1)
	}
	
	// Heuristic 3: Very slow might indicate heavy throttling
	if response.ClientElapsed > challenge.ExpectedDuration*10 {
		analysis.AnomalyReason = "extremely_slow"
		analysis.ConfidenceScore = 60 // Medium confidence (could be slow device)
		atomic.AddUint64(&vmStats.HighJitter, 1)
	}
	
	if !analysis.IsAnomaly {
		atomic.AddUint64(&vmStats.Passed, 1)
	}
	
	// Cleanup the used challenge
	vmd.mu.Lock()
	delete(vmd.challenges, challenge.ChallengeID)
	vmd.mu.Unlock()
	
	return analysis
}

// cleanup removes expired challenges
func (vmd *VMDetector) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now().UnixMilli()
		
		vmd.mu.Lock()
		for id, challenge := range vmd.challenges {
			if now > challenge.ExpiresAt {
				delete(vmd.challenges, id)
			}
		}
		vmd.mu.Unlock()
	}
}

// GenerateTimingChallengeScript generates client-side timing check
func GenerateTimingChallengeScript(challenge *TimingChallenge) string {
	return fmt.Sprintf(`
<script>
(function() {
    'use strict';
    
    const challenge = {
        id: '%s',
        serverStart: %d,
        expectedDuration: %d,
        complexity: %d
    };
    
    const clientStart = performance.now();
    
    // Perform a measurable computation
    function computeTask() {
        let result = 0;
        for (let i = 0; i < challenge.complexity; i++) {
            result += Math.sin(i) * Math.cos(i);
        }
        return result.toFixed(6);
    }
    
    // Run the computation
    const taskResult = computeTask();
    
    const clientEnd = performance.now();
    const clientElapsed = Math.round(clientEnd - clientStart);
    
    // Report timing
    const response = {
        challenge_id: challenge.id,
        client_start_time: Math.round(performance.timeOrigin + clientStart),
        client_end_time: Math.round(performance.timeOrigin + clientEnd),
        client_elapsed: clientElapsed,
        task_result: taskResult
    };
    
    fetch('/sentinel/timing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(response),
        keepalive: true
    }).catch(() => {});
})();
</script>
`, challenge.ChallengeID, challenge.ServerStartTime, 
		challenge.ExpectedDuration, challenge.TaskComplexity)
}

// =============================================================================
// FEATURE 4: CANARY DOM ELEMENTS (CSS Rendering Check)
// =============================================================================
//
// THE PROBLEM:
//   Headless browsers claim to render CSS but often don't do it correctly.
//
// THE DETECTION:
//   1. Inject hidden DOM elements with complex CSS rules
//   2. Ask client to report computed styles
//   3. Compare against expected values
//
// TRAPS:
//   - calc() expressions: width: calc(100px - 20px) should be 80px
//   - CSS variables: var(--test-val) should resolve
//   - Flexbox: display: flex affects child sizing
//   - Gradients: background should not be "none"
//   - Transforms: getBoundingClientRect() changes with transform
//
// =============================================================================

// CanaryCheck represents a CSS rendering check
type CanaryCheck struct {
	ID               string      `json:"id"`
	CSS              string      `json:"css"`
	ExpectedProperty string      `json:"expected_property"`
	ExpectedValue    interface{} `json:"expected_value"`
	Tolerance        float64     `json:"tolerance,omitempty"` // For numeric values
}

// CanaryResult is the client's reported values
type CanaryResult struct {
	ID       string `json:"id"`
	Property string `json:"property"`
	Value    string `json:"value"`
}

// CanaryAnalysis analyzes canary results
type CanaryAnalysis struct {
	TotalChecks   int      `json:"total_checks"`
	PassedChecks  int      `json:"passed_checks"`
	FailedChecks  int      `json:"failed_checks"`
	FailedIDs     []string `json:"failed_ids"`
	IsHeadless    bool     `json:"is_headless"`
	Confidence    float64  `json:"confidence"`
}

// CanaryStats tracks canary detection stats
type CanaryStats struct {
	TotalChecked    uint64
	HeadlessDetected uint64
	RealBrowser      uint64
	PartialRender    uint64
}

var canaryStats = &CanaryStats{}

// GetCanaryStats returns canary detection stats
func GetCanaryStats() CanaryStats {
	return CanaryStats{
		TotalChecked:     atomic.LoadUint64(&canaryStats.TotalChecked),
		HeadlessDetected: atomic.LoadUint64(&canaryStats.HeadlessDetected),
		RealBrowser:      atomic.LoadUint64(&canaryStats.RealBrowser),
		PartialRender:    atomic.LoadUint64(&canaryStats.PartialRender),
	}
}

// Standard canary checks
var standardCanaryChecks = []CanaryCheck{
	{
		ID:               "calc_width",
		CSS:              "width: calc(100px - 20px); height: 10px;",
		ExpectedProperty: "width",
		ExpectedValue:    "80px",
	},
	{
		ID:               "flex_item",
		CSS:              "display: flex; flex-direction: row;",
		ExpectedProperty: "display",
		ExpectedValue:    "flex",
	},
	{
		ID:               "css_var",
		CSS:              "--test-color: rgb(255, 0, 0); color: var(--test-color);",
		ExpectedProperty: "color",
		ExpectedValue:    "rgb(255, 0, 0)",
	},
	{
		ID:               "transform_scale",
		CSS:              "width: 100px; height: 100px; transform: scale(0.5);",
		ExpectedProperty: "transform",
		ExpectedValue:    "matrix(0.5, 0, 0, 0.5, 0, 0)",
	},
	{
		ID:               "opacity_inherit",
		CSS:              "opacity: 0.5;",
		ExpectedProperty: "opacity",
		ExpectedValue:    "0.5",
	},
}

// AnalyzeCanaryResults analyzes CSS rendering check results
func AnalyzeCanaryResults(results []CanaryResult) *CanaryAnalysis {
	atomic.AddUint64(&canaryStats.TotalChecked, 1)
	
	analysis := &CanaryAnalysis{
		TotalChecks:  len(standardCanaryChecks),
		PassedChecks: 0,
		FailedChecks: 0,
		FailedIDs:    []string{},
		IsHeadless:   false,
	}
	
	// Create lookup map
	resultMap := make(map[string]string)
	for _, r := range results {
		resultMap[r.ID] = r.Value
	}
	
	// Check each canary
	for _, check := range standardCanaryChecks {
		reported, exists := resultMap[check.ID]
		
		if !exists {
			// Missing check = suspicious
			analysis.FailedChecks++
			analysis.FailedIDs = append(analysis.FailedIDs, check.ID+"_missing")
			continue
		}
		
		expected, ok := check.ExpectedValue.(string)
		if !ok {
			continue
		}
		
		// Compare values (case-insensitive, whitespace-normalized)
		reportedNorm := strings.ToLower(strings.TrimSpace(reported))
		expectedNorm := strings.ToLower(strings.TrimSpace(expected))
		
		if reportedNorm == expectedNorm {
			analysis.PassedChecks++
		} else {
			analysis.FailedChecks++
			analysis.FailedIDs = append(analysis.FailedIDs, check.ID)
		}
	}
	
	// Calculate confidence
	if analysis.TotalChecks > 0 {
		passRate := float64(analysis.PassedChecks) / float64(analysis.TotalChecks)
		analysis.Confidence = passRate * 100
	}
	
	// Determine if headless
	if analysis.FailedChecks >= 2 {
		analysis.IsHeadless = true
		atomic.AddUint64(&canaryStats.HeadlessDetected, 1)
	} else if analysis.FailedChecks == 1 {
		atomic.AddUint64(&canaryStats.PartialRender, 1)
	} else {
		atomic.AddUint64(&canaryStats.RealBrowser, 1)
	}
	
	return analysis
}

// GenerateCanaryScript generates client-side canary checking JS
func GenerateCanaryScript() string {
	// Generate randomized IDs to prevent hardcoded bypasses
	idBytes := make([]byte, 4)
	rand.Read(idBytes)
	prefix := hex.EncodeToString(idBytes)
	
	return fmt.Sprintf(`
<script>
(function() {
    'use strict';
    
    const prefix = '%s';
    const results = [];
    
    // Create container
    const container = document.createElement('div');
    container.style.cssText = 'position:absolute;left:-9999px;top:-9999px;pointer-events:none;';
    document.body.appendChild(container);
    
    // Canary checks
    const checks = [
        { id: 'calc_width', css: 'width: calc(100px - 20px); height: 10px;', prop: 'width' },
        { id: 'flex_item', css: 'display: flex; flex-direction: row;', prop: 'display' },
        { id: 'css_var', css: '--test-color: rgb(255, 0, 0); color: var(--test-color);', prop: 'color' },
        { id: 'transform_scale', css: 'width: 100px; height: 100px; transform: scale(0.5);', prop: 'transform' },
        { id: 'opacity_inherit', css: 'opacity: 0.5;', prop: 'opacity' }
    ];
    
    // Run each check
    checks.forEach(check => {
        const el = document.createElement('div');
        el.id = prefix + '_' + check.id;
        el.style.cssText = check.css;
        container.appendChild(el);
        
        // Force layout
        void el.offsetWidth;
        
        // Get computed style
        const computed = getComputedStyle(el);
        const value = computed[check.prop];
        
        results.push({
            id: check.id,
            property: check.prop,
            value: value || ''
        });
    });
    
    // Cleanup
    container.remove();
    
    // Report results
    fetch('/sentinel/canary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results: results }),
        keepalive: true
    }).catch(() => {});
})();
</script>
`, prefix)
}

// =============================================================================
// COMBINED HANDLERS
// =============================================================================

// AdvancedPersistenceConfig configures all advanced features
type AdvancedPersistenceConfig struct {
	EnableETagTracking  bool
	EnableHMACSigning   bool
	EnableVMDetection   bool
	EnableCanaryChecks  bool
	HMACRequiredPaths   []string
}

// AdvancedPersistence creates the combined middleware
func AdvancedPersistence(cfg *AdvancedPersistenceConfig, store storage.Store) (*ETagTracker, *HMACMiddleware, *VMDetector) {
	var etagTracker *ETagTracker
	var hmacMiddleware *HMACMiddleware
	var vmDetector *VMDetector
	
	if cfg.EnableETagTracking {
		etagTracker = NewETagTracker(store)
	}
	
	if cfg.EnableHMACSigning {
		hmacMiddleware = NewHMACMiddleware(&HMACConfig{
			Enabled:       true,
			MaxAge:        5 * time.Second,
			RequiredPaths: cfg.HMACRequiredPaths,
			SessionTTL:    1 * time.Hour,
		})
	}
	
	if cfg.EnableVMDetection {
		vmDetector = NewVMDetector()
	}
	
	return etagTracker, hmacMiddleware, vmDetector
}
