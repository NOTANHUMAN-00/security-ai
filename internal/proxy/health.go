// Package proxy - Health check endpoint
package proxy

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

// HealthStatus represents the health check response
type HealthStatus struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Uptime    string    `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
	GoVersion string    `json:"go_version"`
	NumCPU    int       `json:"num_cpu"`
	MemAlloc  uint64    `json:"memory_alloc_mb"`
}

var startTime = time.Now()

// HealthHandler returns a health check endpoint
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		status := HealthStatus{
			Status:    "healthy",
			Version:   "1.0.0",
			Uptime:    time.Since(startTime).String(),
			Timestamp: time.Now().UTC(),
			GoVersion: runtime.Version(),
			NumCPU:    runtime.NumCPU(),
			MemAlloc:  m.Alloc / 1024 / 1024,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status)
	}
}

// MetricsHandler returns Prometheus-compatible metrics
func MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		
		metrics := `# HELP sentinel_x_uptime_seconds Time since server started
# TYPE sentinel_x_uptime_seconds counter
sentinel_x_uptime_seconds %.2f

# HELP sentinel_x_memory_alloc_bytes Current memory allocation
# TYPE sentinel_x_memory_alloc_bytes gauge
sentinel_x_memory_alloc_bytes %d

# HELP sentinel_x_goroutines Number of goroutines
# TYPE sentinel_x_goroutines gauge
sentinel_x_goroutines %d
`
		
		uptime := time.Since(startTime).Seconds()
		w.Write([]byte(
			formatMetrics(metrics, uptime, m.Alloc, runtime.NumGoroutine()),
		))
	}
}

func formatMetrics(template string, args ...interface{}) string {
	// Simple format without using fmt to avoid import
	result := template
	for i, arg := range args {
		placeholder := "%d"
		if i == 0 {
			placeholder = "%.2f"
		}
		switch v := arg.(type) {
		case float64:
			result = replaceFirst(result, placeholder, formatFloat(v))
		case uint64:
			result = replaceFirst(result, placeholder, formatUint(v))
		case int:
			result = replaceFirst(result, placeholder, formatInt(v))
		}
	}
	return result
}

func replaceFirst(s, old, new string) string {
	for i := 0; i <= len(s)-len(old); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

func formatFloat(f float64) string {
	// Simple float formatting
	intPart := int64(f)
	fracPart := int64((f - float64(intPart)) * 100)
	if fracPart < 0 {
		fracPart = -fracPart
	}
	return formatInt64(intPart) + "." + padLeft(formatInt64(fracPart), 2, '0')
}

func formatUint(u uint64) string {
	if u == 0 {
		return "0"
	}
	var result []byte
	for u > 0 {
		result = append([]byte{byte('0' + u%10)}, result...)
		u /= 10
	}
	return string(result)
}

func formatInt(i int) string {
	if i < 0 {
		return "-" + formatUint(uint64(-i))
	}
	return formatUint(uint64(i))
}

func formatInt64(i int64) string {
	if i < 0 {
		return "-" + formatUint(uint64(-i))
	}
	return formatUint(uint64(i))
}

func padLeft(s string, n int, c byte) string {
	for len(s) < n {
		s = string(c) + s
	}
	return s
}
