// Package middleware - Bot Detection implementation
// The "Investigator" module that calculates risk scores for requests
package middleware

import (
	"context"
	"log"
	"net/http"
	"regexp"
	"strings"

	"sentinel-x/internal/config"
)

// BotDetectionMiddleware handles bot detection logic
type BotDetectionMiddleware struct {
	config         *config.Config
	botPatterns    []*regexp.Regexp
	browserPattern *regexp.Regexp
}

// BotDetection creates the bot detection middleware
func BotDetection(cfg *config.Config) Middleware {
	detector := &BotDetectionMiddleware{
		config:         cfg,
		botPatterns:    compileBotPatterns(cfg.BlockedUAs),
		browserPattern: regexp.MustCompile(`(?i)(Chrome|Firefox|Safari|Edge|Opera|MSIE|Trident)`),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if bot detection is disabled
			if !cfg.BotDetection.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for trusted IPs
			if isTrusted, ok := r.Context().Value(IsTrustedKey).(bool); ok && isTrusted {
				next.ServeHTTP(w, r)
				return
			}

			// Calculate risk score
			riskScore := detector.CalculateRiskScore(r)

			// Add risk score to context for logging
			ctx := context.WithValue(r.Context(), RiskScoreKey, riskScore)
			r = r.WithContext(ctx)

			// Block if risk score exceeds threshold
			threshold := int(float64(cfg.BotDetection.RiskThreshold) / cfg.GetProtectionMultiplier())
			if riskScore >= threshold {
				log.Printf("[BLOCKED] High risk score (%d) from %s - UA: %s", 
					riskScore, r.RemoteAddr, r.UserAgent())
				detector.sendBlockedResponse(w, riskScore)
				return
			}

			// Log suspicious requests
			if riskScore >= 30 {
				log.Printf("[SUSPICIOUS] Risk score %d from %s - UA: %s", 
					riskScore, r.RemoteAddr, r.UserAgent())
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CalculateRiskScore computes a risk score (0-100) for a request
// Higher scores indicate more likely bot behavior
func (d *BotDetectionMiddleware) CalculateRiskScore(r *http.Request) int {
	score := 0
	userAgent := r.UserAgent()

	// =========================================
	// User-Agent Analysis (up to 50 points)
	// =========================================

	// Empty User-Agent is highly suspicious
	if userAgent == "" {
		score += 50
	} else {
		// Check against known bot patterns
		for _, pattern := range d.botPatterns {
			if pattern.MatchString(userAgent) {
				score += 40
				break
			}
		}

		// Very short User-Agent
		if len(userAgent) < 20 {
			score += 15
		}

		// Check for common browser indicators
		if !d.browserPattern.MatchString(userAgent) {
			score += 10
		}

		// Check for scripting language indicators
		scriptIndicators := []string{"python", "java/", "ruby", "perl", "php", "go-http"}
		for _, indicator := range scriptIndicators {
			if strings.Contains(strings.ToLower(userAgent), indicator) {
				score += 30
				break
			}
		}
	}

	// =========================================
	// Header Analysis (up to 30 points)
	// =========================================

	// Missing Accept header (browsers always send this)
	if r.Header.Get("Accept") == "" {
		score += 10
	}

	// Missing Accept-Language (browsers send this)
	if r.Header.Get("Accept-Language") == "" {
		score += 10
	}

	// Missing Accept-Encoding
	if r.Header.Get("Accept-Encoding") == "" {
		score += 5
	}

	// Check for suspicious headers
	for _, header := range d.config.SuspiciousHdrs {
		if r.Header.Get(header) != "" {
			score += 10
			break
		}
	}

	// Unusual header order/presence (heuristic)
	// Real browsers have specific header patterns

	// =========================================
	// Request Pattern Analysis (up to 20 points)
	// =========================================

	// Direct IP access without Host header
	if r.Host == "" {
		score += 10
	}

	// Missing or suspicious Referer for non-root paths
	if r.URL.Path != "/" && r.URL.Path != "" {
		referer := r.Header.Get("Referer")
		// If it's a navigation request but missing referer
		if referer == "" && r.Method == http.MethodGet {
			score += 5
		}
	}

	// Connection header analysis
	connection := r.Header.Get("Connection")
	if connection == "close" {
		// Bots often send Connection: close
		score += 5
	}

	// =========================================
	// TLS/Fingerprint Indicators (up to 20 points)
	// Note: Full JA3 fingerprinting requires TLS inspection at connection level
	// =========================================

	// Check for fingerprint header from our WASM client
	fingerprint := r.Header.Get("X-Sentinel-Fingerprint")
	if d.config.BotDetection.BrowserFingerprinting && fingerprint == "" {
		// No browser fingerprint submitted - could be a bot
		// Only penalize on subsequent requests (not first visit)
		if r.Header.Get("Cookie") != "" {
			score += 15
		}
	}

	// Cap the score at 100
	if score > 100 {
		score = 100
	}

	return score
}

// compileBotPatterns compiles the bot user-agent patterns
func compileBotPatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		// Escape special regex characters and make case-insensitive
		re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(pattern))
		if err != nil {
			log.Printf("[WARN] Failed to compile bot pattern '%s': %v", pattern, err)
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// sendBlockedResponse sends a blocked response with appropriate styling
func (d *BotDetectionMiddleware) sendBlockedResponse(w http.ResponseWriter, riskScore int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - Sentinel-X</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #0f0f1a 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 3rem;
            background: rgba(255, 0, 0, 0.05);
            border-radius: 20px;
            border: 1px solid rgba(255, 0, 0, 0.2);
            max-width: 500px;
        }
        .icon { font-size: 4rem; margin-bottom: 1.5rem; }
        h1 {
            color: #ff4444;
            margin-bottom: 1rem;
        }
        p {
            color: rgba(255, 255, 255, 0.7);
            line-height: 1.6;
        }
        .code {
            font-family: monospace;
            background: rgba(255, 255, 255, 0.1);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>Access Denied</h1>
        <p>Your request has been blocked by our security system. If you believe this is an error, please try again with a standard web browser.</p>
        <p style="margin-top: 1rem; font-size: 0.85rem; color: rgba(255,255,255,0.4);">
            Reference: <span class="code">SX-403-BOT</span>
        </p>
    </div>
</body>
</html>`

	w.Write([]byte(html))
}
