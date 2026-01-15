// Package middleware - Rate Limiting implementation
// Uses sliding window algorithm for accurate rate limiting
package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// RateLimiterMiddleware manages request rate limiting
type RateLimiterMiddleware struct {
	config *config.Config
	store  storage.Store
}

// RateLimiter creates the rate limiting middleware
func RateLimiter(cfg *config.Config, store storage.Store) Middleware {
	limiter := &RateLimiterMiddleware{
		config: cfg,
		store:  store,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if rate limiting is disabled
			if !cfg.RateLimit.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for trusted IPs
			if isTrusted, ok := r.Context().Value(IsTrustedKey).(bool); ok && isTrusted {
				next.ServeHTTP(w, r)
				return
			}

			// Get client IP
			clientIP := limiter.getClientIP(r)

			// Check if client is blocked
			if limiter.isBlocked(r.Context(), clientIP) {
				limiter.sendRateLimitResponse(w, 0)
				return
			}

			// Check rate limit
			allowed, remaining := limiter.checkLimit(r.Context(), clientIP)
			if !allowed {
				// Block the IP
				limiter.blockIP(r.Context(), clientIP)
				log.Printf("[RATE_LIMIT] Blocked IP %s for exceeding rate limit", clientIP)
				limiter.sendRateLimitResponse(w, 0)
				return
			}

			// Add rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.RateLimit.RequestsPerSecond))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the real client IP from the request
func (l *RateLimiterMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first (for proxied requests)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the chain
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// checkLimit implements a sliding window rate limit check
func (l *RateLimiterMiddleware) checkLimit(ctx context.Context, ip string) (bool, int) {
	key := fmt.Sprintf("ratelimit:%s", ip)
	window := time.Second

	// Get current count
	count, err := l.store.IncrementWithExpiry(ctx, key, window)
	if err != nil {
		log.Printf("[ERROR] Rate limit check failed: %v", err)
		return true, l.config.RateLimit.RequestsPerSecond // Allow on error
	}

	limit := l.config.RateLimit.RequestsPerSecond
	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	return count <= int64(l.config.RateLimit.Burst), remaining
}

// isBlocked checks if an IP is currently blocked
func (l *RateLimiterMiddleware) isBlocked(ctx context.Context, ip string) bool {
	key := fmt.Sprintf("blocked:%s", ip)
	exists, _ := l.store.Exists(ctx, key)
	return exists
}

// blockIP blocks an IP for the configured duration
func (l *RateLimiterMiddleware) blockIP(ctx context.Context, ip string) {
	key := fmt.Sprintf("blocked:%s", ip)
	duration := time.Duration(l.config.RateLimit.BlockDuration) * time.Second
	l.store.Set(ctx, key, "1", duration)
}

// sendRateLimitResponse sends a rate limit exceeded response
func (l *RateLimiterMiddleware) sendRateLimitResponse(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", fmt.Sprintf("%d", l.config.RateLimit.BlockDuration))
	w.WriteHeader(http.StatusTooManyRequests)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rate Limited - Sentinel-X</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #0f0f1a 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 3rem;
            background: rgba(255, 107, 107, 0.05);
            border-radius: 20px;
            border: 1px solid rgba(255, 107, 107, 0.2);
            max-width: 500px;
        }
        .icon { font-size: 4rem; margin-bottom: 1.5rem; }
        h1 {
            color: #ff6b6b;
            margin-bottom: 1rem;
        }
        p {
            color: rgba(255, 255, 255, 0.7);
            line-height: 1.6;
        }
        .countdown {
            font-size: 2rem;
            color: #ff6b6b;
            margin-top: 1.5rem;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>Rate Limit Exceeded</h1>
        <p>You've made too many requests. Please wait before trying again.</p>
        <div class="countdown" id="countdown">%d seconds</div>
    </div>
    <script>
        let seconds = %d;
        const countdown = document.getElementById('countdown');
        const timer = setInterval(() => {
            seconds--;
            countdown.textContent = seconds + ' seconds';
            if (seconds <= 0) {
                clearInterval(timer);
                window.location.reload();
            }
        }, 1000);
    </script>
</body>
</html>`, l.config.RateLimit.BlockDuration, l.config.RateLimit.BlockDuration)

	w.Write([]byte(html))
}
