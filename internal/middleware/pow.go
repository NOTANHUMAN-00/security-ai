// Package middleware - Proof of Work implementation
// This is the "Gatekeeper" module that requires clients to solve computational puzzles
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// PoWChallenge represents a Proof of Work challenge
type PoWChallenge struct {
	Salt       string `json:"salt"`
	Difficulty int    `json:"difficulty"`
	Timestamp  int64  `json:"timestamp"`
}

// PoWMiddleware holds the PoW configuration and state
type PoWMiddleware struct {
	config *config.Config
	store  storage.Store
}

// ProofOfWork creates the PoW middleware
func ProofOfWork(cfg *config.Config, store storage.Store) Middleware {
	pow := &PoWMiddleware{
		config: cfg,
		store:  store,
	}

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

			// Skip for static assets (CSS, JS, images)
			if pow.isStaticAsset(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Check for PoW solution in header
			powHeader := r.Header.Get("X-Sentinel-PoW")
			if powHeader == "" {
				// No PoW solution provided - send challenge
				pow.sendChallenge(w, r)
				return
			}

			// Validate the PoW solution
			if !pow.validateSolution(r.Context(), powHeader) {
				log.Printf("[BLOCKED] Invalid PoW solution from %s", r.RemoteAddr)
				pow.sendChallenge(w, r)
				return
			}

			// PoW validated - proceed
			next.ServeHTTP(w, r)
		})
	}
}

// isStaticAsset checks if the request is for a static asset
func (p *PoWMiddleware) isStaticAsset(path string) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
		".wasm", // Allow WASM files through
	}
	
	lowerPath := strings.ToLower(path)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

// sendChallenge sends a PoW challenge to the client
func (p *PoWMiddleware) sendChallenge(w http.ResponseWriter, r *http.Request) {
	// Generate a random salt
	salt := generateSalt(32)

	// Store the salt to prevent replay attacks
	ctx := r.Context()
	key := fmt.Sprintf("pow:salt:%s", salt)
	expiry := time.Duration(p.config.PoW.SaltExpiry) * time.Second
	
	if err := p.store.Set(ctx, key, "1", expiry); err != nil {
		log.Printf("[ERROR] Failed to store PoW salt: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	challenge := PoWChallenge{
		Salt:       salt,
		Difficulty: p.config.PoW.Difficulty,
		Timestamp:  time.Now().Unix(),
	}

	// Return challenge page with embedded WASM solver
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(generateChallengeHTML(challenge)))
}

// validateSolution validates a PoW solution
func (p *PoWMiddleware) validateSolution(ctx context.Context, header string) bool {
	// Parse the header: format is "salt:nonce"
	parts := strings.Split(header, ":")
	if len(parts) != 2 {
		return false
	}

	salt := parts[0]
	nonce, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}

	// Check if salt is valid (exists and not used)
	key := fmt.Sprintf("pow:salt:%s", salt)
	exists, err := p.store.Exists(ctx, key)
	if err != nil || !exists {
		log.Printf("[DEBUG] Salt not found or expired: %s", salt)
		return false
	}

	// Verify the PoW solution
	if !ValidatePoW(salt, int(nonce), p.config.PoW.Difficulty) {
		return false
	}

	// Mark salt as used (delete it)
	usedKey := fmt.Sprintf("pow:used:%s", salt)
	if err := p.store.Set(ctx, usedKey, "1", time.Hour); err != nil {
		log.Printf("[ERROR] Failed to mark salt as used: %v", err)
	}
	p.store.Delete(ctx, key)

	return true
}

// ValidatePoW verifies that SHA256(salt + nonce) has the required leading zeros
// Difficulty is the number of leading zero hex characters required
func ValidatePoW(salt string, nonce int, difficulty int) bool {
	// Compute hash
	data := fmt.Sprintf("%s%d", salt, nonce)
	hash := sha256.Sum256([]byte(data))
	hashHex := hex.EncodeToString(hash[:])

	// Check for leading zeros
	// We check the END of the hash for zeros (as specified in requirements)
	suffix := hashHex[len(hashHex)-difficulty:]
	for _, c := range suffix {
		if c != '0' {
			return false
		}
	}

	return true
}

// generateSalt creates a random hex string of given length
func generateSalt(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// generateChallengeHTML creates the challenge page with embedded solver
func generateChallengeHTML(challenge PoWChallenge) string {
	challengeJSON, _ := json.Marshal(challenge)
	
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check - Sentinel-X</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
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
        
        .status {
            font-size: 0.9rem;
            color: rgba(255, 255, 255, 0.5);
        }
        
        .stats {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1.5rem;
            font-size: 0.85rem;
        }
        
        .stat {
            text-align: center;
        }
        
        .stat-value {
            font-size: 1.25rem;
            font-weight: 600;
            color: #00d2ff;
        }
        
        .stat-label {
            color: rgba(255, 255, 255, 0.5);
            margin-top: 0.25rem;
        }

        .error {
            color: #ff6b6b;
            padding: 1rem;
            background: rgba(255, 107, 107, 0.1);
            border-radius: 10px;
            margin-top: 1rem;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>Security Verification</h1>
        <p>We're verifying that you're not a bot. This process is automatic and should complete in a few seconds.</p>
        
        <div class="progress-container">
            <div class="progress-bar" id="progress"></div>
        </div>
        
        <p class="status" id="status">Initializing security check...</p>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value" id="attempts">0</div>
                <div class="stat-label">Attempts</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="hashrate">0</div>
                <div class="stat-label">Hash/sec</div>
            </div>
        </div>

        <div class="error" id="error"></div>
    </div>

    <script>
        const challenge = %s;
        
        // Solve the PoW challenge using JavaScript (WASM would be faster)
        async function solveChallenge(salt, difficulty) {
            const statusEl = document.getElementById('status');
            const progressEl = document.getElementById('progress');
            const attemptsEl = document.getElementById('attempts');
            const hashrateEl = document.getElementById('hashrate');
            
            let nonce = 0;
            const startTime = Date.now();
            const batchSize = 10000;
            
            // Create the target suffix
            const targetSuffix = '0'.repeat(difficulty);
            
            async function hashBatch() {
                const batchStart = nonce;
                
                for (let i = 0; i < batchSize; i++) {
                    const data = salt + nonce;
                    const hashBuffer = await crypto.subtle.digest('SHA-256', 
                        new TextEncoder().encode(data));
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    
                    // Check if hash ends with required zeros
                    if (hashHex.endsWith(targetSuffix)) {
                        return nonce;
                    }
                    nonce++;
                }
                
                // Update UI
                const elapsed = (Date.now() - startTime) / 1000;
                const hashrate = Math.floor(nonce / elapsed);
                
                attemptsEl.textContent = nonce.toLocaleString();
                hashrateEl.textContent = hashrate.toLocaleString();
                progressEl.style.width = Math.min((nonce / 1000000) * 100, 95) + '%%';
                statusEl.textContent = 'Computing proof of work...';
                
                // Continue in next frame
                return new Promise(resolve => {
                    requestAnimationFrame(() => resolve(hashBatch()));
                });
            }
            
            return hashBatch();
        }
        
        async function main() {
            try {
                const statusEl = document.getElementById('status');
                const progressEl = document.getElementById('progress');
                
                statusEl.textContent = 'Solving challenge...';
                
                // Solve the challenge
                const nonce = await solveChallenge(challenge.salt, challenge.difficulty);
                
                statusEl.textContent = 'Verification complete! Redirecting...';
                progressEl.style.width = '100%%';
                
                // Send the solution and reload
                const solution = challenge.salt + ':' + nonce;
                
                // Store in cookie for subsequent requests
                document.cookie = 'X-Sentinel-PoW=' + solution + '; path=/; max-age=300';
                
                // Reload with the solution header
                setTimeout(() => {
                    fetch(window.location.href, {
                        method: 'GET',
                        headers: {
                            'X-Sentinel-PoW': solution
                        }
                    }).then(response => {
                        if (response.ok) {
                            window.location.reload();
                        }
                    }).catch(() => {
                        // Fallback: submit via form
                        const form = document.createElement('form');
                        form.method = 'GET';
                        form.action = window.location.href;
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'pow_token';
                        input.value = solution;
                        form.appendChild(input);
                        document.body.appendChild(form);
                        form.submit();
                    });
                }, 500);
                
            } catch (error) {
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 
                    'Verification failed: ' + error.message;
            }
        }
        
        // Start solving when page loads
        main();
    </script>
</body>
</html>`, string(challengeJSON))
}
