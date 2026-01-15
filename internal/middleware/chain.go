// Package middleware provides the security middleware chain for Sentinel-X
// Each middleware inspects and optionally blocks requests before they reach the proxy
package middleware

import (
	"net/http"
)

// Middleware is a function that wraps an http.Handler
type Middleware func(http.Handler) http.Handler

// Chain builds the middleware chain
// Middlewares are applied in reverse order (last added = first executed)
func Chain(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// RequestIDKey is the context key for request IDs
	RequestIDKey contextKey = "request_id"
	// RiskScoreKey is the context key for bot risk scores
	RiskScoreKey contextKey = "risk_score"
	// IsTrustedKey is the context key for trusted IP flag
	IsTrustedKey contextKey = "is_trusted"
	// ClientIPKey is the context key for the real client IP
	ClientIPKey contextKey = "client_ip"
)
