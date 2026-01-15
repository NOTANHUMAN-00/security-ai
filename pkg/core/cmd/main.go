// =============================================================================
// SENTINEL-X WAF - Main Entry Point
// =============================================================================
// This is the standalone main file for the Sentinel-X WAF.
// It demonstrates how to use the core WAF engine.
// =============================================================================

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sentinel-x/pkg/core"
)

func main() {
	// Parse command-line flags
	listenAddr := flag.String("listen", ":8080", "Address to listen on")
	targetURL := flag.String("target", "http://localhost:3000", "Target URL to proxy to")
	redisAddr := flag.String("redis", "localhost:6379", "Redis address")
	difficulty := flag.Int("difficulty", 4, "Base PoW difficulty (trailing zeros)")
	flag.Parse()

	// Banner
	log.Println("╔═══════════════════════════════════════════════════════════════╗")
	log.Println("║           SENTINEL-X Web Application Firewall v2.0            ║")
	log.Println("║              Production-Grade Security Engine                 ║")
	log.Println("╚═══════════════════════════════════════════════════════════════╝")

	// Create configuration
	cfg := core.DefaultConfig()
	cfg.ListenAddr = *listenAddr
	cfg.TargetURL = *targetURL
	cfg.RedisAddr = *redisAddr
	cfg.PoWBaseDifficulty = *difficulty

	// Create WAF proxy
	waf, err := core.NewSentinelProxy(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Failed to create WAF: %v", err)
	}

	// Handle shutdown signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := waf.Start(); err != nil {
			log.Fatalf("[FATAL] Server error: %v", err)
		}
	}()

	log.Printf("[INFO] WAF is running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	<-shutdown
	log.Println("[INFO] Shutting down...")

	// Print final stats
	stats := waf.GetStats()
	log.Printf("[STATS] Final Statistics:")
	log.Printf("  Total Requests:    %d", stats.TotalRequests)
	log.Printf("  Blocked Requests:  %d", stats.BlockedRequests)
	log.Printf("  PoW Challenges:    %d", stats.PoWChallenges)
	log.Printf("  PoW Solved:        %d", stats.PoWSolved)
	log.Printf("  Rate Limited:      %d", stats.RateLimited)
	log.Printf("  Geo Blocked:       %d", stats.GeoBlocked)
	log.Printf("  Panics Recovered:  %d", stats.PanicsRecovered)

	log.Println("[INFO] Goodbye!")
}
