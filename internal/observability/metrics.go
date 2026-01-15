// Package observability - Prometheus Metrics Exporter
// Exposes /metrics endpoint for enterprise monitoring
package observability

import (
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// PROMETHEUS METRICS
// =============================================================================

// MetricsCollector collects and exposes Prometheus-format metrics
type MetricsCollector struct {
	startTime time.Time
	
	// Request metrics
	RequestsTotal     uint64
	RequestsBlocked   uint64
	RequestsAllowed   uint64
	
	// PoW metrics
	PoWChallengesIssued uint64
	PoWChallengesSolved uint64
	PoWChallengesFailed uint64
	PoWChallengesExpired uint64
	PoWSolveDurationSum  uint64 // Sum of solve times in ms
	PoWSolveDurationCount uint64
	
	// Rate limiting metrics
	RateLimitHits     uint64
	RateLimitBlocks   uint64
	
	// Bot detection metrics
	BotDetectionChecks uint64
	BotsBlocked        uint64
	
	// GeoIP metrics
	GeoLookups        uint64
	GeoBlocked        uint64
	
	// Honeypot metrics
	HoneypotTriggered uint64
	
	// Error metrics
	PanicsRecovered   uint64
	
	// Current state
	ActiveConnections int64
	
	mu sync.RWMutex
}

var globalMetrics = &MetricsCollector{
	startTime: time.Now(),
}

// Metrics singleton
func Metrics() *MetricsCollector {
	return globalMetrics
}

// =============================================================================
// METRIC RECORDING FUNCTIONS
// =============================================================================

// RecordRequest records a request (blocked or allowed)
func (m *MetricsCollector) RecordRequest(blocked bool) {
	atomic.AddUint64(&m.RequestsTotal, 1)
	if blocked {
		atomic.AddUint64(&m.RequestsBlocked, 1)
	} else {
		atomic.AddUint64(&m.RequestsAllowed, 1)
	}
}

// RecordPoWChallenge records a PoW challenge event
func (m *MetricsCollector) RecordPoWChallenge(event string, solveDurationMs ...int64) {
	switch event {
	case "issued":
		atomic.AddUint64(&m.PoWChallengesIssued, 1)
	case "solved":
		atomic.AddUint64(&m.PoWChallengesSolved, 1)
		if len(solveDurationMs) > 0 {
			atomic.AddUint64(&m.PoWSolveDurationSum, uint64(solveDurationMs[0]))
			atomic.AddUint64(&m.PoWSolveDurationCount, 1)
		}
	case "failed":
		atomic.AddUint64(&m.PoWChallengesFailed, 1)
	case "expired":
		atomic.AddUint64(&m.PoWChallengesExpired, 1)
	}
}

// RecordRateLimit records a rate limit event
func (m *MetricsCollector) RecordRateLimit(blocked bool) {
	atomic.AddUint64(&m.RateLimitHits, 1)
	if blocked {
		atomic.AddUint64(&m.RateLimitBlocks, 1)
	}
}

// RecordBotDetection records a bot detection event
func (m *MetricsCollector) RecordBotDetection(blocked bool) {
	atomic.AddUint64(&m.BotDetectionChecks, 1)
	if blocked {
		atomic.AddUint64(&m.BotsBlocked, 1)
	}
}

// RecordGeoLookup records a GeoIP lookup
func (m *MetricsCollector) RecordGeoLookup(blocked bool) {
	atomic.AddUint64(&m.GeoLookups, 1)
	if blocked {
		atomic.AddUint64(&m.GeoBlocked, 1)
	}
}

// RecordHoneypot records a honeypot trigger
func (m *MetricsCollector) RecordHoneypot() {
	atomic.AddUint64(&m.HoneypotTriggered, 1)
}

// RecordPanic records a recovered panic
func (m *MetricsCollector) RecordPanic() {
	atomic.AddUint64(&m.PanicsRecovered, 1)
}

// SetActiveConnections sets the current active connection count
func (m *MetricsCollector) SetActiveConnections(count int64) {
	atomic.StoreInt64(&m.ActiveConnections, count)
}

// =============================================================================
// PROMETHEUS METRICS HANDLER
// =============================================================================

// Handler returns an HTTP handler for /metrics endpoint
func (m *MetricsCollector) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		
		// Collect current values
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		
		uptime := time.Since(m.startTime).Seconds()
		
		// Build metrics output
		output := ""
		
		// Runtime metrics
		output += "# HELP sentinel_uptime_seconds Time since server started\n"
		output += "# TYPE sentinel_uptime_seconds counter\n"
		output += fmt.Sprintf("sentinel_uptime_seconds %.2f\n\n", uptime)
		
		output += "# HELP sentinel_goroutines Current number of goroutines\n"
		output += "# TYPE sentinel_goroutines gauge\n"
		output += fmt.Sprintf("sentinel_goroutines %d\n\n", runtime.NumGoroutine())
		
		output += "# HELP sentinel_memory_alloc_bytes Current memory allocation\n"
		output += "# TYPE sentinel_memory_alloc_bytes gauge\n"
		output += fmt.Sprintf("sentinel_memory_alloc_bytes %d\n\n", memStats.Alloc)
		
		output += "# HELP sentinel_active_connections Current active connections\n"
		output += "# TYPE sentinel_active_connections gauge\n"
		output += fmt.Sprintf("sentinel_active_connections %d\n\n", atomic.LoadInt64(&m.ActiveConnections))
		
		// Request metrics
		output += "# HELP sentinel_requests_total Total number of requests processed\n"
		output += "# TYPE sentinel_requests_total counter\n"
		output += fmt.Sprintf("sentinel_requests_total %d\n\n", atomic.LoadUint64(&m.RequestsTotal))
		
		output += "# HELP sentinel_requests_blocked_total Total number of blocked requests\n"
		output += "# TYPE sentinel_requests_blocked_total counter\n"
		output += fmt.Sprintf("sentinel_requests_blocked_total %d\n\n", atomic.LoadUint64(&m.RequestsBlocked))
		
		output += "# HELP sentinel_requests_allowed_total Total number of allowed requests\n"
		output += "# TYPE sentinel_requests_allowed_total counter\n"
		output += fmt.Sprintf("sentinel_requests_allowed_total %d\n\n", atomic.LoadUint64(&m.RequestsAllowed))
		
		// PoW metrics
		output += "# HELP sentinel_pow_challenges_total Total PoW challenges by status\n"
		output += "# TYPE sentinel_pow_challenges_total counter\n"
		output += fmt.Sprintf("sentinel_pow_challenges_total{status=\"issued\"} %d\n", atomic.LoadUint64(&m.PoWChallengesIssued))
		output += fmt.Sprintf("sentinel_pow_challenges_total{status=\"solved\"} %d\n", atomic.LoadUint64(&m.PoWChallengesSolved))
		output += fmt.Sprintf("sentinel_pow_challenges_total{status=\"failed\"} %d\n", atomic.LoadUint64(&m.PoWChallengesFailed))
		output += fmt.Sprintf("sentinel_pow_challenges_total{status=\"expired\"} %d\n\n", atomic.LoadUint64(&m.PoWChallengesExpired))
		
		// PoW solve duration
		solveCount := atomic.LoadUint64(&m.PoWSolveDurationCount)
		if solveCount > 0 {
			avgSolveMs := float64(atomic.LoadUint64(&m.PoWSolveDurationSum)) / float64(solveCount)
			output += "# HELP sentinel_pow_solve_duration_ms Average PoW solve time in milliseconds\n"
			output += "# TYPE sentinel_pow_solve_duration_ms gauge\n"
			output += fmt.Sprintf("sentinel_pow_solve_duration_ms %.2f\n\n", avgSolveMs)
		}
		
		// Rate limiting metrics
		output += "# HELP sentinel_ratelimit_hits_total Total rate limit checks\n"
		output += "# TYPE sentinel_ratelimit_hits_total counter\n"
		output += fmt.Sprintf("sentinel_ratelimit_hits_total %d\n\n", atomic.LoadUint64(&m.RateLimitHits))
		
		output += "# HELP sentinel_ratelimit_blocked_total Total rate limit blocks\n"
		output += "# TYPE sentinel_ratelimit_blocked_total counter\n"
		output += fmt.Sprintf("sentinel_ratelimit_blocked_total %d\n\n", atomic.LoadUint64(&m.RateLimitBlocks))
		
		// Bot detection metrics
		output += "# HELP sentinel_bot_checks_total Total bot detection checks\n"
		output += "# TYPE sentinel_bot_checks_total counter\n"
		output += fmt.Sprintf("sentinel_bot_checks_total %d\n\n", atomic.LoadUint64(&m.BotDetectionChecks))
		
		output += "# HELP sentinel_bots_blocked_total Total bots blocked\n"
		output += "# TYPE sentinel_bots_blocked_total counter\n"
		output += fmt.Sprintf("sentinel_bots_blocked_total %d\n\n", atomic.LoadUint64(&m.BotsBlocked))
		
		// GeoIP metrics
		output += "# HELP sentinel_geo_lookups_total Total GeoIP lookups\n"
		output += "# TYPE sentinel_geo_lookups_total counter\n"
		output += fmt.Sprintf("sentinel_geo_lookups_total %d\n\n", atomic.LoadUint64(&m.GeoLookups))
		
		output += "# HELP sentinel_geo_blocked_total Total geo-blocked requests\n"
		output += "# TYPE sentinel_geo_blocked_total counter\n"
		output += fmt.Sprintf("sentinel_geo_blocked_total %d\n\n", atomic.LoadUint64(&m.GeoBlocked))
		
		// Honeypot metrics
		output += "# HELP sentinel_honeypot_triggered_total Total honeypot triggers (bots caught)\n"
		output += "# TYPE sentinel_honeypot_triggered_total counter\n"
		output += fmt.Sprintf("sentinel_honeypot_triggered_total %d\n\n", atomic.LoadUint64(&m.HoneypotTriggered))
		
		// Error metrics
		output += "# HELP sentinel_panics_recovered_total Total panics recovered\n"
		output += "# TYPE sentinel_panics_recovered_total counter\n"
		output += fmt.Sprintf("sentinel_panics_recovered_total %d\n\n", atomic.LoadUint64(&m.PanicsRecovered))
		
		// Block rate (derived)
		total := atomic.LoadUint64(&m.RequestsTotal)
		blocked := atomic.LoadUint64(&m.RequestsBlocked)
		blockRate := float64(0)
		if total > 0 {
			blockRate = float64(blocked) / float64(total) * 100
		}
		output += "# HELP sentinel_block_rate_percent Percentage of requests blocked\n"
		output += "# TYPE sentinel_block_rate_percent gauge\n"
		output += fmt.Sprintf("sentinel_block_rate_percent %.2f\n", blockRate)
		
		w.Write([]byte(output))
	}
}

// =============================================================================
// STATS ENDPOINT (JSON)
// =============================================================================

// StatsHandler returns a JSON stats endpoint
func (m *MetricsCollector) StatsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		
		json := fmt.Sprintf(`{
  "uptime_seconds": %.2f,
  "goroutines": %d,
  "memory_mb": %.2f,
  "active_connections": %d,
  "requests": {
    "total": %d,
    "blocked": %d,
    "allowed": %d,
    "block_rate_percent": %.2f
  },
  "pow": {
    "issued": %d,
    "solved": %d,
    "failed": %d,
    "expired": %d
  },
  "rate_limit": {
    "hits": %d,
    "blocks": %d
  },
  "bot_detection": {
    "checks": %d,
    "blocked": %d
  },
  "geoip": {
    "lookups": %d,
    "blocked": %d
  },
  "honeypot_triggered": %d,
  "panics_recovered": %d
}`,
			time.Since(m.startTime).Seconds(),
			runtime.NumGoroutine(),
			float64(memStats.Alloc)/1024/1024,
			atomic.LoadInt64(&m.ActiveConnections),
			atomic.LoadUint64(&m.RequestsTotal),
			atomic.LoadUint64(&m.RequestsBlocked),
			atomic.LoadUint64(&m.RequestsAllowed),
			func() float64 {
				t := atomic.LoadUint64(&m.RequestsTotal)
				if t == 0 { return 0 }
				return float64(atomic.LoadUint64(&m.RequestsBlocked)) / float64(t) * 100
			}(),
			atomic.LoadUint64(&m.PoWChallengesIssued),
			atomic.LoadUint64(&m.PoWChallengesSolved),
			atomic.LoadUint64(&m.PoWChallengesFailed),
			atomic.LoadUint64(&m.PoWChallengesExpired),
			atomic.LoadUint64(&m.RateLimitHits),
			atomic.LoadUint64(&m.RateLimitBlocks),
			atomic.LoadUint64(&m.BotDetectionChecks),
			atomic.LoadUint64(&m.BotsBlocked),
			atomic.LoadUint64(&m.GeoLookups),
			atomic.LoadUint64(&m.GeoBlocked),
			atomic.LoadUint64(&m.HoneypotTriggered),
			atomic.LoadUint64(&m.PanicsRecovered),
		)
		
		w.Write([]byte(json))
	}
}
