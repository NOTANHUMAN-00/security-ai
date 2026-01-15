// Package middleware - Common middleware utilities
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"sentinel-x/internal/config"
)

// Logger creates a logging middleware that records request details
func Logger(cfg *config.Config) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Generate request ID
			requestID := generateRequestID()
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			r = r.WithContext(ctx)

			// Wrap response writer to capture status code
			wrapped := &statusRecorder{ResponseWriter: w, statusCode: 200}

			// Process request
			next.ServeHTTP(wrapped, r)

			// Log the request
			duration := time.Since(start)
			riskScore := 0
			if score, ok := r.Context().Value(RiskScoreKey).(int); ok {
				riskScore = score
			}

			log.Printf("[%s] %s %s %s - %d - %v - Risk:%d - %s",
				requestID[:8],
				getClientIP(r),
				r.Method,
				r.URL.Path,
				wrapped.statusCode,
				duration,
				riskScore,
				r.UserAgent(),
			)
		})
	}
}

// Recovery creates a panic recovery middleware
func Recovery() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("[PANIC] Recovered from panic: %v\n%s", err, debug.Stack())
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// TrustedIP creates a middleware that marks requests from trusted IPs
func TrustedIP(cfg *config.Config) Middleware {
	// Parse trusted IPs into net.IP for efficient comparison
	trustedNets := make([]*net.IPNet, 0)
	trustedIPs := make([]net.IP, 0)

	for _, ip := range cfg.TrustedIPs {
		// Check if it's a CIDR range
		if strings.Contains(ip, "/") {
			_, network, err := net.ParseCIDR(ip)
			if err == nil {
				trustedNets = append(trustedNets, network)
				continue
			}
		}
		// Parse as single IP
		parsed := net.ParseIP(ip)
		if parsed != nil {
			trustedIPs = append(trustedIPs, parsed)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			ip := net.ParseIP(clientIP)

			isTrusted := false
			if ip != nil {
				// Check against single IPs
				for _, trusted := range trustedIPs {
					if trusted.Equal(ip) {
						isTrusted = true
						break
					}
				}
				// Check against CIDR ranges
				if !isTrusted {
					for _, network := range trustedNets {
						if network.Contains(ip) {
							isTrusted = true
							break
						}
					}
				}
			}

			// Add to context
			ctx := context.WithValue(r.Context(), IsTrustedKey, isTrusted)
			ctx = context.WithValue(ctx, ClientIPKey, clientIP)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			
			// Add Sentinel-X identifier
			w.Header().Set("X-Protected-By", "Sentinel-X/1.0")

			next.ServeHTTP(w, r)
		})
	}
}

// Honeypot creates the honeypot middleware
// Note: Main honeypot logic is in the challenges package
// This middleware primarily checks for honeypot triggers
func Honeypot(cfg *config.Config) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Honeypot checking is handled in the proxy handler
			// This middleware is a placeholder for additional honeypot logic
			next.ServeHTTP(w, r)
		})
	}
}

// Helper types and functions

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func generateRequestID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
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
