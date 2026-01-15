// Package proxy implements the reverse proxy functionality
// This is the core component that forwards legitimate traffic to the target server
package proxy

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"sentinel-x/internal/challenges"
	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// Handler wraps the reverse proxy with Sentinel-X functionality
type Handler struct {
	proxy       *httputil.ReverseProxy
	config      *config.Config
	store       storage.Store
	honeypot    *challenges.Honeypot
}

// NewHandler creates a new reverse proxy handler
func NewHandler(cfg *config.Config, store storage.Store) (*Handler, error) {
	targetURL, err := url.Parse(cfg.Server.TargetURL)
	if err != nil {
		return nil, err
	}

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Customize the Director to modify requests before forwarding
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		
		// Add Sentinel-X headers to track that request passed through WAF
		req.Header.Set("X-Sentinel-Verified", "true")
		req.Header.Set("X-Sentinel-Timestamp", time.Now().UTC().Format(time.RFC3339))
		
		// Remove our internal headers before forwarding
		req.Header.Del("X-Sentinel-PoW")
		req.Header.Del("X-Sentinel-Fingerprint")
	}

	// Customize error handling
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[ERROR] Proxy error for %s %s: %v", r.Method, r.URL.Path, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	handler := &Handler{
		proxy:  proxy,
		config: cfg,
		store:  store,
	}

	// Initialize honeypot if enabled
	if cfg.Honeypot.Enabled {
		handler.honeypot = challenges.NewHoneypot(cfg)
	}

	// Modify response to inject honeypot fields
	proxy.ModifyResponse = handler.modifyResponse

	return handler, nil
}

// ServeHTTP implements the http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check for honeypot field in form submissions
	if h.config.Honeypot.Enabled && r.Method == http.MethodPost {
		if h.checkHoneypot(r) {
			log.Printf("[BLOCKED] Honeypot triggered from %s", r.RemoteAddr)
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}
	}

	// Forward the request
	h.proxy.ServeHTTP(w, r)
}

// checkHoneypot validates that honeypot fields are empty
func (h *Handler) checkHoneypot(r *http.Request) bool {
	// Parse the form
	if err := r.ParseForm(); err != nil {
		return false
	}

	// Check each honeypot field
	for _, fieldName := range h.config.Honeypot.FieldNames {
		if value := r.FormValue(fieldName); value != "" {
			// Honeypot field was filled - it's a bot!
			return true
		}
	}

	return false
}

// modifyResponse modifies the response from the target server
// Used primarily to inject honeypot fields into HTML forms
func (h *Handler) modifyResponse(resp *http.Response) error {
	// Only modify HTML responses
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return nil
	}

	// Only inject honeypot if enabled
	if !h.config.Honeypot.Enabled || h.honeypot == nil {
		return nil
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Inject honeypot fields into forms
	modifiedBody := h.honeypot.InjectFields(body)

	// Update the response
	resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
	resp.Header.Set("Content-Length", string(rune(len(modifiedBody))))
	resp.ContentLength = int64(len(modifiedBody))

	return nil
}

// responseRecorder wraps http.ResponseWriter to capture the response
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}
