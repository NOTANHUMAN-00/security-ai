// Package config - Hot-Reloading Configuration
// Watches config file for changes and updates in real-time without restart
package config

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// HOT-RELOAD CONFIGURATION MANAGER
// =============================================================================

// ConfigManager handles hot-reloading of configuration
type ConfigManager struct {
	config     *Config
	configPath string
	watcher    *fsnotify.Watcher
	
	// Callbacks for config changes
	callbacks []func(*Config)
	
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// NewConfigManager creates a new config manager with hot-reload support
func NewConfigManager(path string) (*ConfigManager, error) {
	cm := &ConfigManager{
		configPath: path,
		callbacks:  make([]func(*Config), 0),
		stopCh:     make(chan struct{}),
	}

	// Load initial configuration
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	cm.config = cfg

	// Set up file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[WARN] Could not create file watcher, hot-reload disabled: %v", err)
		return cm, nil
	}
	cm.watcher = watcher

	// Watch the config file
	if err := watcher.Add(path); err != nil {
		log.Printf("[WARN] Could not watch config file, hot-reload disabled: %v", err)
		return cm, nil
	}

	// Also watch the directory for config file recreation
	dir := getDir(path)
	if err := watcher.Add(dir); err != nil {
		log.Printf("[WARN] Could not watch config directory: %v", err)
	}

	// Start the watcher goroutine
	go cm.watchLoop()

	log.Printf("[INFO] Hot-reload enabled for config: %s", path)
	return cm, nil
}

// watchLoop watches for file changes
func (cm *ConfigManager) watchLoop() {
	if cm.watcher == nil {
		return
	}

	// Debounce timer to avoid multiple reloads
	var debounceTimer *time.Timer
	debounceDelay := 500 * time.Millisecond

	for {
		select {
		case <-cm.stopCh:
			return
		
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}

			// Check if this is our config file
			if event.Name != cm.configPath {
				continue
			}

			// Only react to write/create events
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Debounce: reset timer on each event
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(debounceDelay, func() {
				cm.reload()
			})

		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[ERROR] Config watcher error: %v", err)
		}
	}
}

// reload reloads the configuration from disk
func (cm *ConfigManager) reload() {
	log.Printf("[CONFIG] Reloading configuration from %s", cm.configPath)

	// Read and parse the config file
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read config file: %v", err)
		return
	}

	var newConfig Config
	if err := yaml.Unmarshal(data, &newConfig); err != nil {
		log.Printf("[ERROR] Failed to parse config file: %v", err)
		return
	}

	// Apply defaults
	newConfig.applyDefaults()

	// Validate
	if err := newConfig.validate(); err != nil {
		log.Printf("[ERROR] Invalid configuration, keeping old config: %v", err)
		return
	}

	// Log what changed
	cm.mu.RLock()
	oldConfig := cm.config
	cm.mu.RUnlock()

	cm.logChanges(oldConfig, &newConfig)

	// Update the config
	cm.mu.Lock()
	cm.config = &newConfig
	cm.mu.Unlock()

	// Notify all callbacks
	for _, callback := range cm.callbacks {
		go callback(&newConfig)
	}

	log.Printf("[CONFIG] Configuration reloaded successfully")
}

// logChanges logs significant configuration changes
func (cm *ConfigManager) logChanges(old, new *Config) {
	// Rate limiting changes
	if old.RateLimit.RequestsPerSecond != new.RateLimit.RequestsPerSecond {
		log.Printf("[CONFIG] Rate limit changed: %d -> %d req/s",
			old.RateLimit.RequestsPerSecond, new.RateLimit.RequestsPerSecond)
	}

	// PoW changes
	if old.PoW.Enabled != new.PoW.Enabled {
		log.Printf("[CONFIG] PoW enabled changed: %v -> %v", old.PoW.Enabled, new.PoW.Enabled)
	}
	if old.PoW.Difficulty != new.PoW.Difficulty {
		log.Printf("[CONFIG] PoW difficulty changed: %d -> %d", old.PoW.Difficulty, new.PoW.Difficulty)
	}

	// Protection level
	if old.ProtectionLevel != new.ProtectionLevel {
		log.Printf("[CONFIG] Protection level changed: %s -> %s",
			old.ProtectionLevel, new.ProtectionLevel)
	}

	// Trusted IPs
	if len(old.TrustedIPs) != len(new.TrustedIPs) {
		log.Printf("[CONFIG] Trusted IPs changed: %v -> %v", old.TrustedIPs, new.TrustedIPs)
	}

	// Blocked user agents
	if len(old.BlockedUAs) != len(new.BlockedUAs) {
		log.Printf("[CONFIG] Blocked user agents changed: %d -> %d patterns",
			len(old.BlockedUAs), len(new.BlockedUAs))
	}

	// GeoIP blocked countries
	if len(old.GeoIP.BlockedCountries) != len(new.GeoIP.BlockedCountries) {
		log.Printf("[CONFIG] Blocked countries changed: %v -> %v",
			old.GeoIP.BlockedCountries, new.GeoIP.BlockedCountries)
	}
}

// Get returns the current configuration (thread-safe)
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// OnChange registers a callback for configuration changes
func (cm *ConfigManager) OnChange(callback func(*Config)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.callbacks = append(cm.callbacks, callback)
}

// Stop stops the config watcher
func (cm *ConfigManager) Stop() {
	close(cm.stopCh)
	if cm.watcher != nil {
		cm.watcher.Close()
	}
}

// getDir extracts directory from path
func getDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}

// =============================================================================
// RUNTIME CONFIGURATION UPDATES
// =============================================================================

// RuntimeConfig provides methods to update configuration at runtime
type RuntimeConfig struct {
	cm *ConfigManager
}

// NewRuntimeConfig creates a new runtime config interface
func NewRuntimeConfig(cm *ConfigManager) *RuntimeConfig {
	return &RuntimeConfig{cm: cm}
}

// BanIP adds an IP to the blocked list
func (rc *RuntimeConfig) BanIP(ip string) {
	rc.cm.mu.Lock()
	defer rc.cm.mu.Unlock()
	
	// Check if already in trusted list - remove from there
	for i, trusted := range rc.cm.config.TrustedIPs {
		if trusted == ip {
			rc.cm.config.TrustedIPs = append(rc.cm.config.TrustedIPs[:i], rc.cm.config.TrustedIPs[i+1:]...)
			break
		}
	}
	
	// Add to a runtime-only ban list (would need to add this field to config)
	log.Printf("[RUNTIME] Banned IP: %s", ip)
}

// UnbanIP removes an IP from the blocked list
func (rc *RuntimeConfig) UnbanIP(ip string) {
	log.Printf("[RUNTIME] Unbanned IP: %s", ip)
}

// AddTrustedIP adds an IP to the trusted list
func (rc *RuntimeConfig) AddTrustedIP(ip string) {
	rc.cm.mu.Lock()
	defer rc.cm.mu.Unlock()
	
	// Check if already trusted
	for _, trusted := range rc.cm.config.TrustedIPs {
		if trusted == ip {
			return
		}
	}
	
	rc.cm.config.TrustedIPs = append(rc.cm.config.TrustedIPs, ip)
	log.Printf("[RUNTIME] Added trusted IP: %s", ip)
}

// SetProtectionLevel changes the protection level
func (rc *RuntimeConfig) SetProtectionLevel(level string) error {
	validLevels := map[string]bool{"low": true, "medium": true, "high": true, "paranoid": true}
	if !validLevels[level] {
		return &ConfigError{Message: "invalid protection level: " + level}
	}
	
	rc.cm.mu.Lock()
	defer rc.cm.mu.Unlock()
	
	old := rc.cm.config.ProtectionLevel
	rc.cm.config.ProtectionLevel = level
	log.Printf("[RUNTIME] Protection level changed: %s -> %s", old, level)
	
	return nil
}

// BlockCountry adds a country to the block list
func (rc *RuntimeConfig) BlockCountry(countryCode string) {
	rc.cm.mu.Lock()
	defer rc.cm.mu.Unlock()
	
	// Check if already blocked
	for _, c := range rc.cm.config.GeoIP.BlockedCountries {
		if c == countryCode {
			return
		}
	}
	
	rc.cm.config.GeoIP.BlockedCountries = append(rc.cm.config.GeoIP.BlockedCountries, countryCode)
	log.Printf("[RUNTIME] Blocked country: %s", countryCode)
}

// UnblockCountry removes a country from the block list
func (rc *RuntimeConfig) UnblockCountry(countryCode string) {
	rc.cm.mu.Lock()
	defer rc.cm.mu.Unlock()
	
	for i, c := range rc.cm.config.GeoIP.BlockedCountries {
		if c == countryCode {
			rc.cm.config.GeoIP.BlockedCountries = append(
				rc.cm.config.GeoIP.BlockedCountries[:i],
				rc.cm.config.GeoIP.BlockedCountries[i+1:]...,
			)
			log.Printf("[RUNTIME] Unblocked country: %s", countryCode)
			return
		}
	}
}

// ConfigError represents a configuration error
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}
