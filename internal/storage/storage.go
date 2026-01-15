// Package storage provides an abstraction layer for data persistence
// Supports both Redis and in-memory storage backends
package storage

import (
	"context"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"sentinel-x/internal/config"
)

// Store interface defines the storage operations
type Store interface {
	// Set stores a value with optional expiration
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	// Get retrieves a value by key
	Get(ctx context.Context, key string) (string, error)
	// Delete removes a key
	Delete(ctx context.Context, key string) error
	// Exists checks if a key exists
	Exists(ctx context.Context, key string) (bool, error)
	// Increment atomically increments a counter
	Increment(ctx context.Context, key string) (int64, error)
	// IncrementWithExpiry increments and sets expiry on first increment
	IncrementWithExpiry(ctx context.Context, key string, expiration time.Duration) (int64, error)
	// Type returns the storage backend type
	Type() string
	// Close cleans up resources
	Close() error
}

// New creates a new storage instance based on configuration
func New(cfg *config.Config) (Store, error) {
	if cfg.Redis.Enabled {
		return NewRedisStore(cfg)
	}
	return NewMemoryStore(), nil
}

// ============================================================================
// Redis Store Implementation
// ============================================================================

// RedisStore implements Store using Redis
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a new Redis-backed store
func NewRedisStore(cfg *config.Config) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Address,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisStore{client: client}, nil
}

func (r *RedisStore) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

func (r *RedisStore) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *RedisStore) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *RedisStore) Exists(ctx context.Context, key string) (bool, error) {
	result, err := r.client.Exists(ctx, key).Result()
	return result > 0, err
}

func (r *RedisStore) Increment(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

func (r *RedisStore) IncrementWithExpiry(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, expiration)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (r *RedisStore) Type() string {
	return "redis"
}

func (r *RedisStore) Close() error {
	return r.client.Close()
}

// ============================================================================
// In-Memory Store Implementation
// ============================================================================

// memoryItem represents an item in memory with expiration
type memoryItem struct {
	value      string
	expiration time.Time
}

// MemoryStore implements Store using in-memory sync.Map
type MemoryStore struct {
	data     sync.Map
	counters sync.Map
	mu       sync.RWMutex
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{}
	
	// Start cleanup goroutine for expired items
	go store.cleanup()
	
	return store
}

// cleanup periodically removes expired items
func (m *MemoryStore) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		now := time.Now()
		m.data.Range(func(key, value interface{}) bool {
			item := value.(memoryItem)
			if !item.expiration.IsZero() && now.After(item.expiration) {
				m.data.Delete(key)
			}
			return true
		})
	}
}

func (m *MemoryStore) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	}
	
	m.data.Store(key, memoryItem{
		value:      value.(string),
		expiration: exp,
	})
	return nil
}

func (m *MemoryStore) Get(ctx context.Context, key string) (string, error) {
	val, ok := m.data.Load(key)
	if !ok {
		return "", redis.Nil // Use redis.Nil for consistency
	}
	
	item := val.(memoryItem)
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		m.data.Delete(key)
		return "", redis.Nil
	}
	
	return item.value, nil
}

func (m *MemoryStore) Delete(ctx context.Context, key string) error {
	m.data.Delete(key)
	return nil
}

func (m *MemoryStore) Exists(ctx context.Context, key string) (bool, error) {
	_, err := m.Get(ctx, key)
	if err == redis.Nil {
		return false, nil
	}
	return err == nil, err
}

func (m *MemoryStore) Increment(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	val, _ := m.counters.LoadOrStore(key, int64(0))
	newVal := val.(int64) + 1
	m.counters.Store(key, newVal)
	return newVal, nil
}

func (m *MemoryStore) IncrementWithExpiry(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	val, loaded := m.counters.LoadOrStore(key, int64(0))
	newVal := val.(int64) + 1
	m.counters.Store(key, newVal)
	
	// Set expiry tracking
	if !loaded && expiration > 0 {
		go func() {
			time.Sleep(expiration)
			m.counters.Delete(key)
		}()
	}
	
	return newVal, nil
}

func (m *MemoryStore) Type() string {
	return "memory"
}

func (m *MemoryStore) Close() error {
	return nil
}
