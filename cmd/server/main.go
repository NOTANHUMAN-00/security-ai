// Package main - Entry point for Sentinel-X WAF Server
// This is a high-performance Web Application Firewall and Anti-Bot Defense System
// Production-hardened with Slowloris protection, header sanitization, and fail-safe architecture
// Enterprise features: Distributed rate limiting, GeoIP blocking, Prometheus metrics, hot-reload
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-x/internal/config"
	"sentinel-x/internal/middleware"
	"sentinel-x/internal/observability"
	"sentinel-x/internal/proxy"
	"sentinel-x/internal/storage"
)

// Version information
const (
	Version   = "2.0.0"
	BuildType = "enterprise"
)

// ASCII art banner for startup
const banner = `
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ██╗  ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║      ╚██╗██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║█████╗ ╚███╔╝ 
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║╚════╝ ██╔██╗ 
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═╝  ╚═╝
                Web Application Firewall & Anti-Bot Defense
                         v%s [%s]
`

// Production security constants
const (
	// Slowloris Protection: Maximum time to read request headers
	ReadHeaderTimeout = 2 * time.Second

	// Maximum time for entire request read
	DefaultReadTimeout = 10 * time.Second

	// Maximum time for response write
	DefaultWriteTimeout = 30 * time.Second

	// Idle connection timeout
	DefaultIdleTimeout = 120 * time.Second

	// Maximum request body size (10MB default)
	MaxRequestBodySize = 10 * 1024 * 1024

	// Maximum concurrent connections (0 = unlimited)
	MaxConnections = 10000

	// Per-request timeout
	RequestTimeout = 60 * time.Second
)

func main() {
	fmt.Printf(banner, Version, BuildType)

	configPath := "configs/config.yaml"

	// === HOT-RELOAD CONFIGURATION ===
	// Use ConfigManager for hot-reload support
	configManager, err := config.NewConfigManager(configPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration: %v", err)
	}
	defer configManager.Stop()

	cfg := configManager.Get()

	log.Printf("[INFO] Protection Level: %s", cfg.ProtectionLevel)
	log.Printf("[INFO] Hardening: Slowloris Protection (ReadHeaderTimeout: %v)", ReadHeaderTimeout)
	log.Printf("[INFO] Hardening: Max Request Body: %d bytes", MaxRequestBodySize)
	log.Printf("[INFO] Hardening: Max Connections: %d", MaxConnections)

	// === INITIALIZE STORAGE (Redis or In-Memory) ===
	store, err := storage.New(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize storage: %v", err)
	}
	defer store.Close()

	log.Printf("[INFO] Storage backend initialized: %s", store.Type())

	// === INITIALIZE GEO-BLOCKER ===
	var geoBlocker *middleware.GeoBlocker
	if cfg.GeoIP.Enabled {
		geoBlocker, err = middleware.NewGeoBlocker(cfg)
		if err != nil {
			log.Printf("[WARN] GeoIP initialization failed: %v", err)
		} else {
			log.Printf("[INFO] GeoIP blocking enabled")
			if cfg.GeoIP.BlockDataCenters {
				log.Printf("[INFO] GeoIP: Blocking data centers (AWS, Azure, GCP, etc.)")
			}
			if len(cfg.GeoIP.BlockedCountries) > 0 {
				log.Printf("[INFO] GeoIP: Blocked countries: %v", cfg.GeoIP.BlockedCountries)
			}
		}
		defer func() {
			if geoBlocker != nil {
				geoBlocker.Close()
			}
		}()
	}

	// === REGISTER HOT-RELOAD CALLBACKS ===
	configManager.OnChange(func(newCfg *config.Config) {
		// Update GeoIP blocked countries
		if geoBlocker != nil {
			geoBlocker.UpdateBlockedCountries(newCfg.GeoIP.BlockedCountries)
			geoBlocker.UpdateAllowedCountries(newCfg.GeoIP.AllowedCountries)
		}
		log.Printf("[CONFIG] Configuration reloaded, new settings active")
	})

	// === CREATE REVERSE PROXY HANDLER ===
	proxyHandler, err := proxy.NewHandler(cfg, store)
	if err != nil {
		log.Fatalf("[FATAL] Failed to create proxy handler: %v", err)
	}

	// === BUILD HARDENED MIDDLEWARE CHAIN ===
	// Order is CRITICAL - outermost middleware executes first
	//
	// Security Layer Order:
	//  1. Connection Tracking - Monitor active connections
	//  2. Enhanced Recovery - Catch panics, prevent crashes
	//  3. Header Sanitization - Strip spoofable headers FIRST
	//  4. Request Size Limit - Prevent memory exhaustion
	//  5. Request Timeout - Kill slow requests
	//  6. Logger - Log all requests (with sanitized IP)
	//  7. Trusted IP - Mark trusted sources
	//  8. Geo-Fencing - Block by country/ASN (NEW)
	//  9. Distributed Rate Limiting - Redis-backed (NEW)
	// 10. Enhanced PoW - Argon2 + Dynamic Difficulty
	// 11. Bot Detection - Score and block bots
	// 12. Honeypot - Form protection
	// 13. Security Headers - Response hardening
	//
	handler := middleware.Chain(
		proxyHandler,
		// === HARDENING LAYER (outer - runs first) ===
		middleware.ConnectionTracker(MaxConnections),              // Track connections, reject overflow
		middleware.EnhancedRecovery(),                             // Fail-safe panic recovery with logging
		middleware.HeaderSanitizer(cfg),                           // CRITICAL: Strip spoofable headers
		middleware.RequestSizeLimiter(MaxRequestBodySize),         // Prevent memory exhaustion
		middleware.RequestTimeout(RequestTimeout),                 // Per-request timeout

		// === LOGGING & TRUST LAYER ===
		middleware.Logger(cfg),                                    // Request logging (uses sanitized IP)
		middleware.TrustedIP(cfg),                                 // Trusted IP bypass

		// === GEO-FENCING LAYER (NEW) ===
		middleware.GeoFencing(cfg, geoBlocker),                    // Block by country/ASN/datacenter

		// === RATE LIMITING LAYER ===
		middleware.DistributedRateLimiterMiddleware(cfg, store),   // Redis Lua script distributed rate limiting

		// === PROTECTION LAYER ===
		middleware.EnhancedProofOfWork(cfg, store),                // ENHANCED PoW: Argon2 + Dynamic Difficulty
		middleware.BotDetection(cfg),                              // Bot scoring (feeds into PoW difficulty)
		middleware.Tarpit(cfg),                                    // 🕳️ INFINITE VOID: Trap high-confidence bots
		middleware.Honeypot(cfg),                                  // Honeypot injection

		// === RESPONSE LAYER (inner - runs last before proxy) ===
		middleware.SecurityHeaders(),                              // Security response headers
	)

	// === CREATE MAIN HTTP SERVER ===
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.ListenPort),
		Handler: handler,

		// === SLOWLORIS PROTECTION ===
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       getTimeout(cfg.Server.ReadTimeout, DefaultReadTimeout),
		WriteTimeout:      getTimeout(cfg.Server.WriteTimeout, DefaultWriteTimeout),
		IdleTimeout:       DefaultIdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1MB max headers
	}

	// === CREATE METRICS SERVER (Prometheus) ===
	metricsServer := &http.Server{
		Addr:         ":9090",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Set up metrics endpoints
	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("/metrics", observability.Metrics().Handler())
	metricsMux.HandleFunc("/stats", observability.Metrics().StatsHandler())
	metricsMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","version":"` + Version + `"}`))
	})
	metricsServer.Handler = metricsMux

	// === SHUTDOWN SIGNAL HANDLING ===
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// === START METRICS SERVER ===
	go func() {
		log.Printf("[INFO] Prometheus metrics available at http://localhost:9090/metrics")
		log.Printf("[INFO] JSON stats available at http://localhost:9090/stats")
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[WARN] Metrics server error: %v", err)
		}
	}()

	// === START MAIN SERVER ===
	go func() {
		log.Printf("[INFO] Sentinel-X listening on port %d", cfg.Server.ListenPort)
		log.Printf("[INFO] Proxying requests to: %s", cfg.Server.TargetURL)
		log.Printf("[INFO] Server timeouts - ReadHeader: %v, Read: %v, Write: %v, Idle: %v",
			ReadHeaderTimeout,
			server.ReadTimeout,
			server.WriteTimeout,
			server.IdleTimeout,
		)

		var serverErr error
		if cfg.Server.TLSEnabled {
			log.Printf("[INFO] TLS enabled, using certificate: %s", cfg.Server.TLSCertPath)
			serverErr = server.ListenAndServeTLS(cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath)
		} else {
			serverErr = server.ListenAndServe()
		}

		if serverErr != nil && serverErr != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server error: %v", serverErr)
		}
	}()

	// === START BACKGROUND STATS LOGGER ===
	go logStats()

	// === WAIT FOR SHUTDOWN ===
	<-shutdown
	log.Println("[INFO] Shutdown signal received, gracefully stopping...")

	// Log final stats
	logFinalStats()

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown both servers
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[ERROR] Main server shutdown error: %v", err)
	}
	if err := metricsServer.Shutdown(ctx); err != nil {
		log.Printf("[ERROR] Metrics server shutdown error: %v", err)
	}

	log.Println("[INFO] Sentinel-X stopped successfully")
}

// getTimeout returns configured timeout or default
func getTimeout(configured int, defaultTimeout time.Duration) time.Duration {
	if configured > 0 {
		return time.Duration(configured) * time.Second
	}
	return defaultTimeout
}

// logStats periodically logs server statistics
func logStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		panicStats := middleware.GetPanicStats()
		connStats := middleware.GetConnectionStats()
		geoStats := middleware.GetGeoIPStats()
		rlStats := middleware.GetDistributedRateLimitStats()

		log.Printf("[STATS] Connections: active=%d total=%d rejected=%d | "+
			"RateLimit: requests=%d blocked=%d | "+
			"Geo: lookups=%d blocked=%d | "+
			"Panics: %d",
			connStats.Active,
			connStats.Total,
			connStats.Rejected,
			rlStats.TotalRequests,
			rlStats.TotalBlocked,
			geoStats.TotalLookups,
			geoStats.CountryBlocked+geoStats.ASNBlocked+geoStats.DataCenterBlocked,
			panicStats.TotalPanics,
		)
	}
}

// logFinalStats logs final statistics on shutdown
func logFinalStats() {
	panicStats := middleware.GetPanicStats()
	connStats := middleware.GetConnectionStats()
	geoStats := middleware.GetGeoIPStats()
	rlStats := middleware.GetDistributedRateLimitStats()
	powStats := middleware.GetPoWStats()
	tarpitStats := middleware.GetTarpitStats()

	log.Printf("[FINAL STATS]")
	log.Printf("  Connections: Total=%d, Rejected=%d, Slow=%d",
		connStats.Total, connStats.Rejected, connStats.SlowRequests)
	log.Printf("  Rate Limiting: Requests=%d, Blocked=%d, RedisErrors=%d",
		rlStats.TotalRequests, rlStats.TotalBlocked, rlStats.RedisErrors)
	log.Printf("  GeoIP: Lookups=%d, CountryBlocked=%d, ASNBlocked=%d, DataCenterBlocked=%d",
		geoStats.TotalLookups, geoStats.CountryBlocked, geoStats.ASNBlocked, geoStats.DataCenterBlocked)
	log.Printf("  PoW: Challenges=%d, Solved=%d, Failed=%d, Expired=%d, Replayed=%d",
		powStats.TotalChallenges, powStats.TotalSolved, powStats.TotalFailed,
		powStats.TotalExpired, powStats.TotalReplayed)
	log.Printf("  🕳️ Tarpit: BotsTrapped=%d, TotalTrapTime=%ds, Aborted=%d",
		tarpitStats.BotsTrapped, tarpitStats.TotalTrapTime, tarpitStats.TrapAborted)
	log.Printf("  Panics Recovered: %d", panicStats.TotalPanics)
}

