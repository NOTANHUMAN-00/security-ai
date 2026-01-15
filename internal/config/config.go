// Package config handles loading and parsing of Sentinel-X configuration
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the complete Sentinel-X configuration
type Config struct {
	Server          ServerConfig        `yaml:"server"`
	ProtectionLevel string              `yaml:"protection_level"`
	PoW             PoWConfig           `yaml:"pow"`
	RateLimit       RateLimitConfig     `yaml:"rate_limit"`
	BotDetection    BotDetectionConfig  `yaml:"bot_detection"`
	Honeypot        HoneypotConfig      `yaml:"honeypot"`
	GeoIP           GeoIPConfig         `yaml:"geoip"`
	Redis           RedisConfig         `yaml:"redis"`
	Logging         LoggingConfig       `yaml:"logging"`
	TrustedIPs      []string            `yaml:"trusted_ips"`
	BlockedUAs      []string            `yaml:"blocked_user_agents"`
	SuspiciousHdrs  []string            `yaml:"suspicious_headers"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	ListenPort   int    `yaml:"listen_port"`
	TargetURL    string `yaml:"target_url"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
	TLSEnabled   bool   `yaml:"tls_enabled"`
	TLSCertPath  string `yaml:"tls_cert_path"`
	TLSKeyPath   string `yaml:"tls_key_path"`
}

// PoWConfig contains Proof of Work settings
type PoWConfig struct {
	Enabled          bool `yaml:"enabled"`
	Difficulty       int  `yaml:"difficulty"`
	SaltExpiry       int  `yaml:"salt_expiry"`
	BypassTrustedIPs bool `yaml:"bypass_trusted_ips"`
}

// RateLimitConfig contains rate limiting settings
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	Burst             int  `yaml:"burst"`
	BlockDuration     int  `yaml:"block_duration"`
}

// BotDetectionConfig contains bot detection settings
type BotDetectionConfig struct {
	Enabled              bool `yaml:"enabled"`
	RiskThreshold        int  `yaml:"risk_threshold"`
	JA3Fingerprinting    bool `yaml:"ja3_fingerprinting"`
	BrowserFingerprinting bool `yaml:"browser_fingerprinting"`
}

// HoneypotConfig contains honeypot settings
type HoneypotConfig struct {
	Enabled    bool     `yaml:"enabled"`
	FieldNames []string `yaml:"field_names"`
}

// GeoIPConfig contains GeoIP and geo-fencing settings
type GeoIPConfig struct {
	Enabled          bool     `yaml:"enabled"`
	DatabasePath     string   `yaml:"database_path"` // Path to MaxMind GeoLite2 City database
	ASNDatabasePath  string   `yaml:"asn_database_path"` // Path to MaxMind GeoLite2 ASN database
	BlockedCountries []string `yaml:"blocked_countries"` // ISO country codes to block
	AllowedCountries []string `yaml:"allowed_countries"` // If set, ONLY these countries allowed
	BlockDataCenters bool     `yaml:"block_data_centers"` // Block AWS, Azure, GCP, etc.
	BlockTor         bool     `yaml:"block_tor"` // Block Tor exit nodes
	BlockProxies     bool     `yaml:"block_proxies"` // Block known proxies
	BlockedASNs      []uint   `yaml:"blocked_asns"` // Specific ASNs to block
}

// RedisConfig contains Redis connection settings
type RedisConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults
	cfg.applyDefaults()

	// Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// applyDefaults sets default values for missing configuration
func (c *Config) applyDefaults() {
	if c.Server.ListenPort == 0 {
		c.Server.ListenPort = 8080
	}
	if c.Server.TargetURL == "" {
		c.Server.TargetURL = "http://localhost:3000"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 30
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 30
	}
	if c.ProtectionLevel == "" {
		c.ProtectionLevel = "medium"
	}
	if c.PoW.Difficulty == 0 {
		c.PoW.Difficulty = 4
	}
	if c.PoW.SaltExpiry == 0 {
		c.PoW.SaltExpiry = 300
	}
	if c.RateLimit.RequestsPerSecond == 0 {
		c.RateLimit.RequestsPerSecond = 10
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 50
	}
	if c.RateLimit.BlockDuration == 0 {
		c.RateLimit.BlockDuration = 300
	}
	if c.BotDetection.RiskThreshold == 0 {
		c.BotDetection.RiskThreshold = 70
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
}

// validate checks the configuration for errors
func (c *Config) validate() error {
	if c.Server.ListenPort < 1 || c.Server.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", c.Server.ListenPort)
	}
	
	validLevels := map[string]bool{
		"low": true, "medium": true, "high": true, "paranoid": true,
	}
	if !validLevels[c.ProtectionLevel] {
		return fmt.Errorf("invalid protection level: %s", c.ProtectionLevel)
	}

	if c.PoW.Difficulty < 1 || c.PoW.Difficulty > 8 {
		return fmt.Errorf("PoW difficulty must be between 1 and 8")
	}

	if c.BotDetection.RiskThreshold < 0 || c.BotDetection.RiskThreshold > 100 {
		return fmt.Errorf("risk threshold must be between 0 and 100")
	}

	return nil
}

// GetProtectionMultiplier returns a multiplier based on protection level
// Used to adjust sensitivity of various checks
func (c *Config) GetProtectionMultiplier() float64 {
	switch c.ProtectionLevel {
	case "low":
		return 0.5
	case "medium":
		return 1.0
	case "high":
		return 1.5
	case "paranoid":
		return 2.0
	default:
		return 1.0
	}
}
