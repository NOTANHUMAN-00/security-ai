// Package middleware - Distributed Rate Limiting with Redis Lua Scripts
// Enables consistent rate limiting across multiple server instances
package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// =============================================================================
// DISTRIBUTED RATE LIMITER (Redis Lua Scripts)
// =============================================================================

// Lua script for atomic sliding window rate limiting
// This script runs atomically on Redis, ensuring consistency across all servers
const luaRateLimitScript = `
-- KEYS[1] = rate limit key (e.g., "ratelimit:ip:192.168.1.1")
-- ARGV[1] = current timestamp in milliseconds
-- ARGV[2] = window size in milliseconds
-- ARGV[3] = max requests allowed
-- ARGV[4] = block duration in milliseconds (if limit exceeded)

local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local block_duration = tonumber(ARGV[4])

-- Check if IP is blocked
local block_key = key .. ":blocked"
local blocked_until = redis.call('GET', block_key)
if blocked_until then
    local blocked_until_num = tonumber(blocked_until)
    if now < blocked_until_num then
        -- Still blocked, return remaining block time
        return {0, blocked_until_num - now, 0}
    else
        -- Block expired, remove it
        redis.call('DEL', block_key)
    end
end

-- Remove old entries outside the window
local window_start = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current requests in window
local current_count = redis.call('ZCARD', key)

if current_count >= limit then
    -- Rate limit exceeded, block the IP
    local block_until = now + block_duration
    redis.call('SET', block_key, block_until, 'PX', block_duration)
    return {0, block_duration, current_count}
end

-- Add current request with timestamp as score
redis.call('ZADD', key, now, now .. '-' .. math.random(1000000))

-- Set expiry on the key
redis.call('PEXPIRE', key, window)

-- Return: {allowed (1/0), remaining requests, current count}
local remaining = limit - current_count - 1
return {1, remaining, current_count + 1}
`

// Lua script for distributed counter with expiry
const luaIncrementWithExpiry = `
local key = KEYS[1]
local increment = tonumber(ARGV[1])
local expiry_ms = tonumber(ARGV[2])

local current = redis.call('INCRBY', key, increment)
if current == increment then
    redis.call('PEXPIRE', key, expiry_ms)
end
return current
`

// DistributedRateLimiter implements Redis-backed distributed rate limiting
type DistributedRateLimiter struct {
	config *config.Config
	client *redis.Client
	script *redis.Script
	
	// Fallback to local limiter if Redis is unavailable
	localLimiter *RateLimiterMiddleware
	
	// Stats
	totalRequests  uint64
	totalBlocked   uint64
	redisErrors    uint64
}

// DistributedRateLimiterStats contains rate limiter statistics
type DistributedRateLimiterStats struct {
	TotalRequests uint64
	TotalBlocked  uint64
	RedisErrors   uint64
}

var globalDistributedRLStats = &DistributedRateLimiterStats{}

// NewDistributedRateLimiter creates a new distributed rate limiter
func NewDistributedRateLimiter(cfg *config.Config, redisClient *redis.Client) *DistributedRateLimiter {
	return &DistributedRateLimiter{
		config: cfg,
		client: redisClient,
		script: redis.NewScript(luaRateLimitScript),
	}
}

// DistributedRateLimiterMiddleware creates the distributed rate limiting middleware
func DistributedRateLimiterMiddleware(cfg *config.Config, store storage.Store) Middleware {
	// Try to get Redis client from store
	var redisClient *redis.Client
	if cfg.Redis.Enabled {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Address,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
		
		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			log.Printf("[WARN] Redis not available for distributed rate limiting, using local: %v", err)
			redisClient = nil
		} else {
			log.Printf("[INFO] Distributed rate limiting enabled via Redis")
		}
	}

	limiter := &DistributedRateLimiter{
		config: cfg,
		client: redisClient,
		script: redis.NewScript(luaRateLimitScript),
		localLimiter: &RateLimiterMiddleware{
			config: cfg,
			store:  store,
		},
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

			clientIP := GetTrustedClientIP(r)
			atomic.AddUint64(&globalDistributedRLStats.TotalRequests, 1)

			var allowed bool
			var remaining int64
			var err error

			if limiter.client != nil {
				// Use distributed (Redis) rate limiting
				allowed, remaining, err = limiter.checkDistributed(r.Context(), clientIP)
				if err != nil {
					atomic.AddUint64(&globalDistributedRLStats.RedisErrors, 1)
					log.Printf("[WARN] Redis rate limit error, falling back to local: %v", err)
					// Fallback to local
					allowed, remaining = limiter.checkLocal(r.Context(), clientIP)
				}
			} else {
				// Use local rate limiting
				allowed, remaining = limiter.checkLocal(r.Context(), clientIP)
			}

			if !allowed {
				atomic.AddUint64(&globalDistributedRLStats.TotalBlocked, 1)
				log.Printf("[RATE_LIMIT] Blocked %s (distributed)", clientIP)
				limiter.sendRateLimitResponse(w)
				return
			}

			// Add rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.RateLimit.RequestsPerSecond))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

			next.ServeHTTP(w, r)
		})
	}
}

// checkDistributed performs distributed rate limiting via Redis Lua script
func (d *DistributedRateLimiter) checkDistributed(ctx context.Context, ip string) (bool, int64, error) {
	key := fmt.Sprintf("sentinel:ratelimit:%s", ip)
	
	now := time.Now().UnixMilli()
	windowMs := int64(1000) // 1 second window
	limit := int64(d.config.RateLimit.RequestsPerSecond)
	blockDurationMs := int64(d.config.RateLimit.BlockDuration) * 1000

	// Execute Lua script atomically
	result, err := d.script.Run(ctx, d.client, []string{key},
		now, windowMs, limit, blockDurationMs).Slice()
	
	if err != nil {
		return false, 0, err
	}

	allowed := result[0].(int64) == 1
	remaining := result[1].(int64)
	
	return allowed, remaining, nil
}

// checkLocal performs local (non-distributed) rate limiting
func (d *DistributedRateLimiter) checkLocal(ctx context.Context, ip string) (bool, int64) {
	// Simple token bucket implementation
	key := fmt.Sprintf("ratelimit:%s", ip)
	
	limit := int64(d.config.RateLimit.Burst)
	
	// Use the store's increment functionality
	count, _ := d.localLimiter.store.IncrementWithExpiry(ctx, key, time.Second)
	
	if count > limit {
		return false, 0
	}
	
	return true, limit - count
}

// sendRateLimitResponse sends a rate limit exceeded response
func (d *DistributedRateLimiter) sendRateLimitResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", fmt.Sprintf("%d", d.config.RateLimit.BlockDuration))
	w.WriteHeader(http.StatusTooManyRequests)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rate Limited - Sentinel-X</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0a0a0a; color: #fff;
               display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .container { text-align: center; padding: 2rem; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #ff6b6b; margin-bottom: 0.5rem; }
        p { color: #888; }
        .countdown { font-size: 2rem; color: #ff6b6b; margin-top: 1rem; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>Rate Limit Exceeded</h1>
        <p>Too many requests. Please wait before trying again.</p>
        <div class="countdown" id="countdown">%d seconds</div>
    </div>
    <script>
        let s = %d;
        const el = document.getElementById('countdown');
        setInterval(() => { s--; el.textContent = s + ' seconds'; if(s<=0) location.reload(); }, 1000);
    </script>
</body>
</html>`, d.config.RateLimit.BlockDuration, d.config.RateLimit.BlockDuration)

	w.Write([]byte(html))
}

// GetDistributedRateLimitStats returns current statistics
func GetDistributedRateLimitStats() DistributedRateLimiterStats {
	return DistributedRateLimiterStats{
		TotalRequests: atomic.LoadUint64(&globalDistributedRLStats.TotalRequests),
		TotalBlocked:  atomic.LoadUint64(&globalDistributedRLStats.TotalBlocked),
		RedisErrors:   atomic.LoadUint64(&globalDistributedRLStats.RedisErrors),
	}
}
