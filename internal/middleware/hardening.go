// Package middleware - Production Hardening
// Security hardening middleware for enterprise-grade deployment
package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"sentinel-x/internal/config"
)

// =============================================================================
// FAIL-SAFE ARCHITECTURE - Enhanced Panic Recovery
// =============================================================================

// PanicStats tracks panic recovery statistics
type PanicStats struct {
	TotalPanics    uint64
	LastPanicTime  time.Time
	LastPanicError string
}

var globalPanicStats = &PanicStats{}

// EnhancedRecovery creates an enterprise-grade panic recovery middleware
// Features:
// - Captures full stack traces
// - Tracks panic statistics for monitoring
// - Prevents information leakage to clients
// - Ensures request isolation (one bad request doesn't crash server)
func EnhancedRecovery() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Increment panic counter atomically
					atomic.AddUint64(&globalPanicStats.TotalPanics, 1)
					globalPanicStats.LastPanicTime = time.Now()
					globalPanicStats.LastPanicError = fmt.Sprintf("%v", err)

					// Get request ID if available
					requestID := "unknown"
					if id, ok := r.Context().Value(RequestIDKey).(string); ok {
						requestID = id[:8]
					}

					// Get client info (safely)
					clientIP := "unknown"
					if ip, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
						clientIP = ip
					}

					// Log full details for debugging (server-side only)
					stack := debug.Stack()
					log.Printf("[CRITICAL PANIC] Request %s from %s\n"+
						"  Method: %s\n"+
						"  Path: %s\n"+
						"  User-Agent: %s\n"+
						"  Error: %v\n"+
						"  Stack Trace:\n%s",
						requestID,
						clientIP,
						r.Method,
						r.URL.Path,
						r.UserAgent(),
						err,
						string(stack),
					)

					// Send generic error to client (no information leakage)
					// Check if headers already sent
					if !headersSent(w) {
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						w.Header().Set("X-Sentinel-Error", "internal")
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte(panicErrorPage(requestID)))
					}
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// GetPanicStats returns current panic statistics
func GetPanicStats() PanicStats {
	return PanicStats{
		TotalPanics:    atomic.LoadUint64(&globalPanicStats.TotalPanics),
		LastPanicTime:  globalPanicStats.LastPanicTime,
		LastPanicError: globalPanicStats.LastPanicError,
	}
}

// panicErrorPage generates a user-friendly error page without exposing internals
func panicErrorPage(requestID string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Sentinel-X</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 2rem;
        }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #ff6b6b; margin-bottom: 0.5rem; }
        p { color: #888; margin-bottom: 1rem; }
        .ref { font-family: monospace; color: #444; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>Something went wrong</h1>
        <p>We encountered an unexpected error processing your request.</p>
        <p>Please try again in a moment.</p>
        <p class="ref">Reference: %s</p>
    </div>
</body>
</html>`, requestID)
}

// headersSent checks if response headers have already been written
func headersSent(w http.ResponseWriter) bool {
	// Check if we can cast to a recorder that tracks this
	if recorder, ok := w.(*statusRecorder); ok {
		return recorder.statusCode != 200
	}
	return false
}

// =============================================================================
// HEADER SANITIZATION - "Trust No One" Rule
// =============================================================================

// SpoofableHeaders lists headers that clients can spoof and must be sanitized
var SpoofableHeaders = []string{
	// IP-related headers that can be spoofed
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Client-IP",
	"X-Originating-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
	"X-Cluster-Client-IP",
	"Forwarded-For",
	"Forwarded",

	// Sentinel-X internal headers (prevent client spoofing)
	"X-Sentinel-Score",
	"X-Sentinel-Verified",
	"X-Sentinel-Fingerprint",
	"X-Sentinel-PoW-Validated",
	"X-Sentinel-Timestamp",
	"X-Sentinel-Request-ID",

	// Other security-sensitive headers
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Host",
	"X-Original-Host",
}

// HeaderSanitizer creates a middleware that strips spoofable headers
// This MUST run early in the chain (right after Recovery)
func HeaderSanitizer(cfg *config.Config) Middleware {
	// Build lookup map for O(1) header checking
	spoofableMap := make(map[string]bool)
	for _, header := range SpoofableHeaders {
		spoofableMap[strings.ToLower(header)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Store the REAL client IP from the TCP connection BEFORE sanitization
			realIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				realIP = r.RemoteAddr
			}

			// Count stripped headers for logging
			strippedCount := 0

			// Strip all spoofable headers from incoming request
			for header := range r.Header {
				if spoofableMap[strings.ToLower(header)] {
					strippedCount++
					r.Header.Del(header)
				}
			}

			// Log if headers were stripped (potential attack)
			if strippedCount > 0 {
				log.Printf("[SECURITY] Stripped %d spoofable headers from %s",
					strippedCount, realIP)
			}

			// Set our TRUSTED headers based on actual connection info
			r.Header.Set("X-Sentinel-Real-IP", realIP)
			r.Header.Set("X-Sentinel-Request-ID", generateRequestID())
			r.Header.Set("X-Sentinel-Timestamp", time.Now().UTC().Format(time.RFC3339))

			// Store real IP in context for downstream middleware
			ctx := context.WithValue(r.Context(), ClientIPKey, realIP)
			ctx = context.WithValue(ctx, "sentinel_sanitized", true)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// GetTrustedClientIP returns the sanitized, trusted client IP
// This should be used instead of getClientIP after sanitization
func GetTrustedClientIP(r *http.Request) string {
	// First check if we've already sanitized and stored the IP
	if ip, ok := r.Context().Value(ClientIPKey).(string); ok {
		return ip
	}

	// Check our trusted header
	if ip := r.Header.Get("X-Sentinel-Real-IP"); ip != "" {
		return ip
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// =============================================================================
// REQUEST SIZE LIMITING - Prevent Memory Exhaustion
// =============================================================================

// RequestSizeLimiter limits the size of incoming requests
func RequestSizeLimiter(maxBodySize int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Limit request body size
			if r.ContentLength > maxBodySize {
				log.Printf("[BLOCKED] Request body too large: %d bytes from %s",
					r.ContentLength, GetTrustedClientIP(r))
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}

			// Wrap body with a limiting reader as a safety measure
			// (ContentLength can be spoofed)
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// CONNECTION TRACKING - For Slowloris Detection
// =============================================================================

// ConnectionStats tracks active connections
type ConnectionStats struct {
	Active       int64
	Total        uint64
	Rejected     uint64
	SlowRequests uint64
}

var connStats = &ConnectionStats{}

// GetConnectionStats returns current connection statistics
func GetConnectionStats() ConnectionStats {
	return ConnectionStats{
		Active:       atomic.LoadInt64(&connStats.Active),
		Total:        atomic.LoadUint64(&connStats.Total),
		Rejected:     atomic.LoadUint64(&connStats.Rejected),
		SlowRequests: atomic.LoadUint64(&connStats.SlowRequests),
	}
}

// ConnectionTracker tracks active connections for monitoring
func ConnectionTracker(maxConnections int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Increment active connections
			current := atomic.AddInt64(&connStats.Active, 1)
			atomic.AddUint64(&connStats.Total, 1)

			// Decrement when done
			defer atomic.AddInt64(&connStats.Active, -1)

			// Reject if too many connections
			if maxConnections > 0 && current > maxConnections {
				atomic.AddUint64(&connStats.Rejected, 1)
				log.Printf("[REJECTED] Too many connections: %d (max: %d)",
					current, maxConnections)
				http.Error(w, "Service Busy", http.StatusServiceUnavailable)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// REQUEST TIMEOUT WRAPPER - Per-Request Timeouts
// =============================================================================

// RequestTimeout adds a per-request timeout context
// This ensures individual slow requests don't hang forever
func RequestTimeout(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create timeout context
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Create channel for completion
			done := make(chan struct{})

			// Run handler in goroutine
			go func() {
				next.ServeHTTP(w, r.WithContext(ctx))
				close(done)
			}()

			// Wait for completion or timeout
			select {
			case <-done:
				// Request completed normally
			case <-ctx.Done():
				// Request timed out
				atomic.AddUint64(&connStats.SlowRequests, 1)
				log.Printf("[TIMEOUT] Request timeout for %s %s from %s",
					r.Method, r.URL.Path, GetTrustedClientIP(r))
				// Note: Response may already be partially sent
			}
		})
	}
}

// =============================================================================
// METHOD VALIDATION - Reject Invalid HTTP Methods
// =============================================================================

// AllowedMethods validates that request method is allowed
func AllowedMethods(methods ...string) Middleware {
	allowed := make(map[string]bool)
	for _, m := range methods {
		allowed[strings.ToUpper(m)] = true
	}

	// Default allowed methods if none specified
	if len(methods) == 0 {
		allowed = map[string]bool{
			"GET":     true,
			"POST":    true,
			"PUT":     true,
			"DELETE":  true,
			"PATCH":   true,
			"HEAD":    true,
			"OPTIONS": true,
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowed[r.Method] {
				log.Printf("[BLOCKED] Invalid method %s from %s",
					r.Method, GetTrustedClientIP(r))
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// HOST HEADER VALIDATION - Prevent Host Header Attacks
// =============================================================================

// ValidateHost ensures the Host header matches allowed hosts
func ValidateHost(allowedHosts []string) Middleware {
	hostMap := make(map[string]bool)
	for _, h := range allowedHosts {
		hostMap[strings.ToLower(h)] = true
	}

	// If no hosts specified, allow all (backward compatibility)
	skipValidation := len(allowedHosts) == 0

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skipValidation {
				next.ServeHTTP(w, r)
				return
			}

			host := strings.ToLower(r.Host)
			// Remove port if present
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}

			if !hostMap[host] {
				log.Printf("[BLOCKED] Invalid Host header '%s' from %s",
					r.Host, GetTrustedClientIP(r))
				http.Error(w, "Invalid Host", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
