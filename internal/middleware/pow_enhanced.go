// Package middleware - Enhanced Proof of Work with Argon2
// Memory-hard PoW with dynamic difficulty and time-bound tokens
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// =============================================================================
// ENHANCED POW TYPES
// =============================================================================

// EnhancedPoWChallenge represents a time-bound, signed challenge
type EnhancedPoWChallenge struct {
	Salt       string `json:"salt"`       // Random salt
	Timestamp  int64  `json:"timestamp"`  // Unix timestamp (for time-bound validation)
	Difficulty int    `json:"difficulty"` // Dynamic difficulty level
	RiskLevel  string `json:"risk_level"` // low, medium, high, extreme
	Signature  string `json:"signature"`  // HMAC signature to prevent tampering
	Algorithm  string `json:"algorithm"`  // "argon2" or "sha256" (fallback)
	ExpiresAt  int64  `json:"expires_at"` // When the challenge expires
}

// PoWStats tracks PoW statistics for dynamic difficulty
type PoWStats struct {
	TotalChallenges  uint64
	TotalSolved      uint64
	TotalFailed      uint64
	TotalExpired     uint64
	TotalReplayed    uint64
	AvgSolveTimeMS   int64
	UnderAttack      bool
	AttackMultiplier float64
}

var globalPoWStats = &PoWStats{AttackMultiplier: 1.0}
var powStatsMu sync.RWMutex

// =============================================================================
// ARGON2 PARAMETERS
// =============================================================================

// Argon2 parameters tuned for browser compatibility
// These are intentionally lighter than password hashing to allow client-side solving
type Argon2Params struct {
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory in KB
	Threads uint8  // Parallelism
	KeyLen  uint32 // Output length
}

// DifficultyLevels maps risk levels to Argon2 parameters
var DifficultyLevels = map[string]Argon2Params{
	"minimal": {Time: 1, Memory: 4096, Threads: 1, KeyLen: 32},     // ~50ms
	"low":     {Time: 2, Memory: 8192, Threads: 1, KeyLen: 32},     // ~100ms
	"medium":  {Time: 3, Memory: 16384, Threads: 1, KeyLen: 32},    // ~300ms
	"high":    {Time: 4, Memory: 32768, Threads: 1, KeyLen: 32},    // ~1s
	"extreme": {Time: 6, Memory: 65536, Threads: 1, KeyLen: 32},    // ~3s
	"attack":  {Time: 8, Memory: 131072, Threads: 1, KeyLen: 32},   // ~5s+ (under attack)
}

// =============================================================================
// ENHANCED POW MIDDLEWARE
// =============================================================================

// EnhancedPoWMiddleware implements memory-hard PoW with dynamic difficulty
type EnhancedPoWMiddleware struct {
	config     *config.Config
	store      storage.Store
	signingKey []byte // Secret key for HMAC signatures
}

// EnhancedProofOfWork creates the enhanced PoW middleware
func EnhancedProofOfWork(cfg *config.Config, store storage.Store) Middleware {
	// Generate or load signing key
	signingKey := make([]byte, 32)
	if _, err := rand.Read(signingKey); err != nil {
		log.Fatal("[FATAL] Failed to generate PoW signing key")
	}

	pow := &EnhancedPoWMiddleware{
		config:     cfg,
		store:      store,
		signingKey: signingKey,
	}

	// Start attack detection goroutine
	go pow.attackDetector()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if PoW is disabled
			if !cfg.PoW.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for trusted IPs
			if cfg.PoW.BypassTrustedIPs {
				if isTrusted, ok := r.Context().Value(IsTrustedKey).(bool); ok && isTrusted {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Skip for static assets
			if pow.isStaticAsset(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Check for PoW solution
			powHeader := r.Header.Get("X-Sentinel-PoW")
			powQuery := r.URL.Query().Get("pow_token")
			powCookie, _ := r.Cookie("X-Sentinel-PoW")

			solution := powHeader
			if solution == "" && powQuery != "" {
				solution = powQuery
			}
			if solution == "" && powCookie != nil {
				solution = powCookie.Value
			}

			if solution == "" {
				// Calculate risk level for dynamic difficulty
				riskLevel := pow.calculateRiskLevel(r)
				pow.sendEnhancedChallenge(w, r, riskLevel)
				atomic.AddUint64(&globalPoWStats.TotalChallenges, 1)
				return
			}

			// Validate the solution
			valid, reason := pow.validateEnhancedSolution(r.Context(), solution)
			if !valid {
				log.Printf("[POW] Invalid solution from %s: %s", GetTrustedClientIP(r), reason)
				atomic.AddUint64(&globalPoWStats.TotalFailed, 1)
				
				riskLevel := pow.calculateRiskLevel(r)
				pow.sendEnhancedChallenge(w, r, riskLevel)
				return
			}

			atomic.AddUint64(&globalPoWStats.TotalSolved, 1)
			
			// Set a session cookie to avoid re-challenging for a period
			http.SetCookie(w, &http.Cookie{
				Name:     "sx_pow_verified",
				Value:    "1",
				Path:     "/",
				MaxAge:   300, // 5 minutes
				HttpOnly: true,
				Secure:   cfg.Server.TLSEnabled,
				SameSite: http.SameSiteStrictMode,
			})

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// DYNAMIC DIFFICULTY
// =============================================================================

// calculateRiskLevel determines the appropriate difficulty based on request characteristics
func (p *EnhancedPoWMiddleware) calculateRiskLevel(r *http.Request) string {
	riskScore := 0

	// Get risk score from context if available
	if score, ok := r.Context().Value(RiskScoreKey).(int); ok {
		riskScore = score
	} else {
		// Calculate basic risk indicators
		riskScore = p.quickRiskAssessment(r)
	}

	// Apply attack multiplier
	powStatsMu.RLock()
	underAttack := globalPoWStats.UnderAttack
	multiplier := globalPoWStats.AttackMultiplier
	powStatsMu.RUnlock()

	// Under attack - maximum difficulty
	if underAttack {
		return "attack"
	}

	// Adjust score by multiplier
	adjustedScore := int(float64(riskScore) * multiplier)

	// Map score to risk level
	switch {
	case adjustedScore >= 80:
		return "extreme"
	case adjustedScore >= 60:
		return "high"
	case adjustedScore >= 40:
		return "medium"
	case adjustedScore >= 20:
		return "low"
	default:
		return "minimal"
	}
}

// quickRiskAssessment does a fast risk check for PoW difficulty
func (p *EnhancedPoWMiddleware) quickRiskAssessment(r *http.Request) int {
	score := 0
	
	// Check User-Agent
	ua := r.UserAgent()
	if ua == "" {
		score += 40
	} else if len(ua) < 30 {
		score += 20
	}

	// Check for automation indicators
	lowerUA := strings.ToLower(ua)
	automationIndicators := []string{"python", "curl", "wget", "java/", "go-http", "bot", "crawler"}
	for _, indicator := range automationIndicators {
		if strings.Contains(lowerUA, indicator) {
			score += 30
			break
		}
	}

	// Check headers
	if r.Header.Get("Accept-Language") == "" {
		score += 15
	}
	if r.Header.Get("Accept") == "" {
		score += 15
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// attackDetector monitors for attack patterns and adjusts global difficulty
func (p *EnhancedPoWMiddleware) attackDetector() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var prevFailed uint64

	for range ticker.C {
		failed := atomic.LoadUint64(&globalPoWStats.TotalFailed)
		solved := atomic.LoadUint64(&globalPoWStats.TotalSolved)
		expired := atomic.LoadUint64(&globalPoWStats.TotalExpired)
		replayed := atomic.LoadUint64(&globalPoWStats.TotalReplayed)

		// Calculate failure rate in last interval
		newFailures := failed - prevFailed
		prevFailed = failed

		powStatsMu.Lock()

		// Attack detection heuristics
		underAttack := false
		multiplier := 1.0

		// High failure rate indicates attack
		if newFailures > 100 {
			underAttack = true
			multiplier = 2.0
		} else if newFailures > 50 {
			multiplier = 1.5
		} else if newFailures > 20 {
			multiplier = 1.2
		}

		// Many replay attempts indicate attack
		if replayed > 50 {
			underAttack = true
			multiplier = 2.0
		}

		// High expired count (bots giving up) - potential attack
		if expired > 100 {
			multiplier = 1.5
		}

		// Update global stats
		globalPoWStats.UnderAttack = underAttack
		globalPoWStats.AttackMultiplier = multiplier

		powStatsMu.Unlock()

		if underAttack {
			total := atomic.LoadUint64(&globalPoWStats.TotalChallenges)
			log.Printf("[ALERT] Attack detected! Challenges: %d, Failed: %d, Solved: %d, Multiplier: %.1f",
				total, failed, solved, multiplier)
		}
	}
}

// =============================================================================
// TIME-BOUND TOKENS WITH SIGNATURES
// =============================================================================

// sendEnhancedChallenge sends a time-bound, signed challenge
func (p *EnhancedPoWMiddleware) sendEnhancedChallenge(w http.ResponseWriter, r *http.Request, riskLevel string) {
	// Generate random salt
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)

	// Create time-bound challenge
	now := time.Now().Unix()
	expiresAt := now + int64(p.config.PoW.SaltExpiry) // Default 30 seconds

	// Get difficulty parameters
	params, exists := DifficultyLevels[riskLevel]
	if !exists {
		params = DifficultyLevels["medium"]
	}

	// Calculate a numeric difficulty for the SHA256 fallback
	sha256Difficulty := p.config.PoW.Difficulty
	switch riskLevel {
	case "minimal":
		sha256Difficulty = 3
	case "low":
		sha256Difficulty = 4
	case "medium":
		sha256Difficulty = 4
	case "high":
		sha256Difficulty = 5
	case "extreme":
		sha256Difficulty = 5
	case "attack":
		sha256Difficulty = 6
	}

	challenge := EnhancedPoWChallenge{
		Salt:       salt,
		Timestamp:  now,
		Difficulty: sha256Difficulty,
		RiskLevel:  riskLevel,
		Algorithm:  "argon2", // Primary algorithm
		ExpiresAt:  expiresAt,
	}

	// Sign the challenge to prevent tampering
	challenge.Signature = p.signChallenge(challenge)

	// Store in Redis/memory to track valid salts
	ctx := r.Context()
	key := fmt.Sprintf("pow:challenge:%s", salt)
	challengeData, _ := json.Marshal(challenge)
	
	expiry := time.Duration(p.config.PoW.SaltExpiry) * time.Second
	if err := p.store.Set(ctx, key, string(challengeData), expiry); err != nil {
		log.Printf("[ERROR] Failed to store PoW challenge: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Send challenge page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(p.generateEnhancedChallengeHTML(challenge, params)))
}

// signChallenge creates an HMAC signature for the challenge
func (p *EnhancedPoWMiddleware) signChallenge(c EnhancedPoWChallenge) string {
	data := fmt.Sprintf("%s:%d:%d:%s", c.Salt, c.Timestamp, c.ExpiresAt, c.RiskLevel)
	mac := hmac.New(sha256.New, p.signingKey)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifySignature verifies the challenge wasn't tampered with
func (p *EnhancedPoWMiddleware) verifySignature(c EnhancedPoWChallenge) bool {
	expected := p.signChallenge(c)
	return hmac.Equal([]byte(expected), []byte(c.Signature))
}

// =============================================================================
// SOLUTION VALIDATION
// =============================================================================

// validateEnhancedSolution validates a PoW solution with all security checks
func (p *EnhancedPoWMiddleware) validateEnhancedSolution(ctx context.Context, solution string) (bool, string) {
	// Parse solution: format is "salt:nonce:timestamp:signature" for Argon2
	// or "salt:nonce" for SHA256 fallback
	parts := strings.Split(solution, ":")
	if len(parts) < 2 {
		return false, "invalid format"
	}

	salt := parts[0]
	nonce := parts[1]

	// Look up the original challenge
	key := fmt.Sprintf("pow:challenge:%s", salt)
	challengeData, err := p.store.Get(ctx, key)
	if err != nil {
		return false, "challenge not found or expired"
	}

	var challenge EnhancedPoWChallenge
	if err := json.Unmarshal([]byte(challengeData), &challenge); err != nil {
		return false, "invalid challenge data"
	}

	// Check 1: Time-bound validation
	now := time.Now().Unix()
	if now > challenge.ExpiresAt {
		atomic.AddUint64(&globalPoWStats.TotalExpired, 1)
		return false, "challenge expired"
	}

	// Check 2: Verify signature (challenge wasn't tampered)
	if !p.verifySignature(challenge) {
		return false, "invalid signature"
	}

	// Check 3: Check if salt was already used (replay protection)
	usedKey := fmt.Sprintf("pow:used:%s", salt)
	used, _ := p.store.Exists(ctx, usedKey)
	if used {
		atomic.AddUint64(&globalPoWStats.TotalReplayed, 1)
		return false, "token already used (replay attack)"
	}

	// Check 4: Verify the actual PoW solution
	valid := false
	if challenge.Algorithm == "argon2" {
		valid = p.verifyArgon2Solution(challenge, nonce)
	} else {
		// SHA256 fallback
		nonceInt, err := strconv.ParseInt(nonce, 10, 64)
		if err != nil {
			return false, "invalid nonce"
		}
		valid = ValidatePoW(salt, int(nonceInt), challenge.Difficulty)
	}

	if !valid {
		return false, "incorrect solution"
	}

	// Mark salt as used (replay protection)
	// Keep for 1 hour to prevent re-use even after original expiry
	p.store.Set(ctx, usedKey, "1", time.Hour)
	
	// Delete the challenge
	p.store.Delete(ctx, key)

	return true, ""
}

// verifyArgon2Solution verifies an Argon2-based PoW solution
func (p *EnhancedPoWMiddleware) verifyArgon2Solution(challenge EnhancedPoWChallenge, nonce string) bool {
	params, exists := DifficultyLevels[challenge.RiskLevel]
	if !exists {
		params = DifficultyLevels["medium"]
	}

	// Compute Argon2 hash
	input := []byte(challenge.Salt + nonce)
	salt := []byte(challenge.Salt)

	hash := argon2.IDKey(input, salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	hashHex := hex.EncodeToString(hash)

	// Check for required trailing zeros based on difficulty
	requiredZeros := challenge.Difficulty
	if len(hashHex) < requiredZeros {
		return false
	}

	suffix := hashHex[len(hashHex)-requiredZeros:]
	for _, c := range suffix {
		if c != '0' {
			return false
		}
	}

	return true
}

// =============================================================================
// STATIC ASSET CHECK
// =============================================================================

func (p *EnhancedPoWMiddleware) isStaticAsset(path string) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
		".wasm", ".webp", ".avif", ".mp4", ".webm", ".mp3",
	}
	
	lowerPath := strings.ToLower(path)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

// =============================================================================
// ENHANCED CHALLENGE HTML WITH ARGON2 SUPPORT
// =============================================================================

func (p *EnhancedPoWMiddleware) generateEnhancedChallengeHTML(challenge EnhancedPoWChallenge, params Argon2Params) string {
	challengeJSON, _ := json.Marshal(challenge)
	paramsJSON, _ := json.Marshal(map[string]interface{}{
		"time":    params.Time,
		"memory":  params.Memory,
		"threads": params.Threads,
		"keyLen":  params.KeyLen,
	})

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check - Sentinel-X</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%%, #1a1a2e 50%%, #16213e 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 3rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            max-width: 500px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        .shield {
            font-size: 4rem;
            margin-bottom: 1.5rem;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%%, 100%% { transform: scale(1); opacity: 1; }
            50%% { transform: scale(1.1); opacity: 0.8; }
        }
        h1 {
            font-size: 1.75rem;
            margin-bottom: 1rem;
            background: linear-gradient(90deg, #00d2ff, #3a7bd5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        p {
            color: rgba(255, 255, 255, 0.7);
            margin-bottom: 2rem;
            line-height: 1.6;
        }
        .progress-container {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 1.5rem;
        }
        .progress-bar {
            height: 8px;
            background: linear-gradient(90deg, #00d2ff, #3a7bd5);
            width: 0%%;
            transition: width 0.3s ease;
            border-radius: 10px;
        }
        .status { font-size: 0.9rem; color: rgba(255, 255, 255, 0.5); }
        .stats {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1.5rem;
            font-size: 0.85rem;
        }
        .stat { text-align: center; }
        .stat-value { font-size: 1.25rem; font-weight: 600; color: #00d2ff; }
        .stat-label { color: rgba(255, 255, 255, 0.5); margin-top: 0.25rem; }
        .difficulty-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            margin-bottom: 1rem;
        }
        .difficulty-minimal { background: rgba(0, 255, 0, 0.2); color: #0f0; }
        .difficulty-low { background: rgba(0, 200, 255, 0.2); color: #0cf; }
        .difficulty-medium { background: rgba(255, 200, 0, 0.2); color: #fc0; }
        .difficulty-high { background: rgba(255, 100, 0, 0.2); color: #f60; }
        .difficulty-extreme { background: rgba(255, 0, 0, 0.2); color: #f00; }
        .difficulty-attack { background: rgba(255, 0, 0, 0.4); color: #f00; animation: blink 0.5s infinite; }
        @keyframes blink { 50%% { opacity: 0.5; } }
        .error {
            color: #ff6b6b;
            padding: 1rem;
            background: rgba(255, 107, 107, 0.1);
            border-radius: 10px;
            margin-top: 1rem;
            display: none;
        }
        .timer {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.4);
            margin-top: 1rem;
        }
    </style>
    <!-- Argon2 WASM Library -->
    <script src="https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <span class="difficulty-badge difficulty-%s">%s Security Level</span>
        <h1>Security Verification</h1>
        <p>We're verifying you're human using memory-hard cryptography. This is harder for bots to bypass.</p>
        
        <div class="progress-container">
            <div class="progress-bar" id="progress"></div>
        </div>
        
        <p class="status" id="status">Initializing Argon2 engine...</p>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value" id="attempts">0</div>
                <div class="stat-label">Attempts</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="elapsed">0s</div>
                <div class="stat-label">Time</div>
            </div>
        </div>

        <div class="timer" id="timer">Challenge expires in <span id="countdown">30</span>s</div>
        <div class="error" id="error"></div>
    </div>

    <script>
        const challenge = %s;
        const argon2Params = %s;
        
        // Countdown timer
        let timeLeft = challenge.expires_at - Math.floor(Date.now() / 1000);
        const countdownEl = document.getElementById('countdown');
        const timerInterval = setInterval(() => {
            timeLeft--;
            countdownEl.textContent = timeLeft;
            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'Challenge expired. Refreshing...';
                setTimeout(() => window.location.reload(), 2000);
            }
        }, 1000);

        // Check if Argon2 is available
        async function solveWithArgon2(salt, difficulty) {
            const statusEl = document.getElementById('status');
            const progressEl = document.getElementById('progress');
            const attemptsEl = document.getElementById('attempts');
            const elapsedEl = document.getElementById('elapsed');
            
            const startTime = Date.now();
            const targetSuffix = '0'.repeat(difficulty);
            let nonce = 0;

            statusEl.textContent = 'Solving with Argon2 (memory-hard)...';

            while (true) {
                try {
                    const input = salt + nonce;
                    
                    // Use Argon2 browser library
                    const result = await argon2.hash({
                        pass: input,
                        salt: salt,
                        time: argon2Params.time,
                        mem: argon2Params.memory,
                        hashLen: argon2Params.keyLen,
                        parallelism: argon2Params.threads,
                        type: argon2.ArgonType.Argon2id
                    });

                    const hashHex = result.hashHex;
                    
                    // Check if hash ends with required zeros
                    if (hashHex.endsWith(targetSuffix)) {
                        return { nonce: nonce.toString(), method: 'argon2' };
                    }

                    nonce++;
                    
                    // Update UI every iteration (Argon2 is slow enough)
                    const elapsed = (Date.now() - startTime) / 1000;
                    attemptsEl.textContent = nonce.toLocaleString();
                    elapsedEl.textContent = elapsed.toFixed(1) + 's';
                    progressEl.style.width = Math.min(nonce * 10, 95) + '%%';

                    // Safety limit
                    if (nonce > 10000) {
                        throw new Error('Max attempts reached');
                    }

                    // Allow UI updates
                    await new Promise(r => setTimeout(r, 0));

                } catch (e) {
                    console.error('Argon2 error:', e);
                    // Fallback to SHA256
                    return solveWithSHA256(salt, difficulty);
                }
            }
        }

        // Fallback SHA256 solver
        async function solveWithSHA256(salt, difficulty) {
            const statusEl = document.getElementById('status');
            const progressEl = document.getElementById('progress');
            const attemptsEl = document.getElementById('attempts');
            const elapsedEl = document.getElementById('elapsed');
            
            statusEl.textContent = 'Solving with SHA-256 (fallback)...';
            
            const startTime = Date.now();
            const targetSuffix = '0'.repeat(difficulty);
            let nonce = 0;
            const batchSize = 10000;

            async function processBatch() {
                for (let i = 0; i < batchSize; i++) {
                    const data = salt + nonce;
                    const hashBuffer = await crypto.subtle.digest('SHA-256', 
                        new TextEncoder().encode(data));
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    
                    if (hashHex.endsWith(targetSuffix)) {
                        return { nonce: nonce.toString(), method: 'sha256' };
                    }
                    nonce++;
                }

                const elapsed = (Date.now() - startTime) / 1000;
                attemptsEl.textContent = nonce.toLocaleString();
                elapsedEl.textContent = elapsed.toFixed(1) + 's';
                progressEl.style.width = Math.min((nonce / 1000000) * 100, 95) + '%%';

                if (nonce > 50000000) {
                    throw new Error('Max attempts reached');
                }

                return new Promise(resolve => {
                    requestAnimationFrame(() => resolve(processBatch()));
                });
            }

            return processBatch();
        }

        async function main() {
            try {
                const statusEl = document.getElementById('status');
                const progressEl = document.getElementById('progress');
                
                // Try Argon2 first, fall back to SHA256
                let result;
                if (typeof argon2 !== 'undefined') {
                    result = await solveWithArgon2(challenge.salt, challenge.difficulty);
                } else {
                    statusEl.textContent = 'Argon2 not available, using SHA-256...';
                    result = await solveWithSHA256(challenge.salt, challenge.difficulty);
                }
                
                statusEl.textContent = 'Verification complete! Redirecting...';
                progressEl.style.width = '100%%';
                clearInterval(timerInterval);
                
                // Build solution string
                const solution = challenge.salt + ':' + result.nonce;
                
                // Store in cookie
                document.cookie = 'X-Sentinel-PoW=' + solution + '; path=/; max-age=300; SameSite=Strict';
                
                // Redirect with solution
                setTimeout(() => {
                    fetch(window.location.href, {
                        method: 'GET',
                        headers: { 'X-Sentinel-PoW': solution },
                        credentials: 'same-origin'
                    }).then(response => {
                        if (response.ok || response.redirected) {
                            window.location.reload();
                        } else {
                            // Try query parameter fallback
                            const url = new URL(window.location.href);
                            url.searchParams.set('pow_token', solution);
                            window.location.href = url.toString();
                        }
                    }).catch(() => {
                        // Query parameter fallback
                        const url = new URL(window.location.href);
                        url.searchParams.set('pow_token', solution);
                        window.location.href = url.toString();
                    });
                }, 500);
                
            } catch (error) {
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'Error: ' + error.message;
            }
        }
        
        // Start after Argon2 loads
        if (typeof argon2 !== 'undefined') {
            main();
        } else {
            // Wait for script to load
            setTimeout(main, 1000);
        }
    </script>
</body>
</html>`, challenge.RiskLevel, strings.Title(challenge.RiskLevel), string(challengeJSON), string(paramsJSON))
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// GetPoWStats returns current PoW statistics
func GetPoWStats() PoWStats {
	powStatsMu.RLock()
	defer powStatsMu.RUnlock()
	
	return PoWStats{
		TotalChallenges: atomic.LoadUint64(&globalPoWStats.TotalChallenges),
		TotalSolved:     atomic.LoadUint64(&globalPoWStats.TotalSolved),
		TotalFailed:     atomic.LoadUint64(&globalPoWStats.TotalFailed),
		TotalExpired:    atomic.LoadUint64(&globalPoWStats.TotalExpired),
		TotalReplayed:   atomic.LoadUint64(&globalPoWStats.TotalReplayed),
		UnderAttack:     globalPoWStats.UnderAttack,
		AttackMultiplier: globalPoWStats.AttackMultiplier,
	}
}

// encodeBase64 helper
func encodeBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// decodeBase64 helper  
func decodeBase64(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}
