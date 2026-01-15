// Package middleware - Geo-Fencing and ASN Blocking
// Block traffic by country, continent, or cloud provider (AWS, Azure, GCP, etc.)
package middleware

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
	"sentinel-x/internal/config"
)

// =============================================================================
// GEO-FENCING & ASN BLOCKING
// =============================================================================

// GeoIPResult contains the result of a GeoIP lookup
type GeoIPResult struct {
	IP          string
	Country     string // ISO 3166-1 alpha-2 (e.g., "US", "CN")
	CountryName string
	Continent   string // e.g., "NA", "EU", "AS"
	City        string
	ASN         uint   // Autonomous System Number
	ASNOrg      string // Organization name (e.g., "Amazon.com, Inc.")
	IsProxy     bool
	IsHosting   bool // Data center / cloud provider
	IsTor       bool
}

// GeoIPStats contains statistics about geo-blocking
type GeoIPStats struct {
	TotalLookups      uint64
	CountryBlocked    uint64
	ASNBlocked        uint64
	DataCenterBlocked uint64
	TorBlocked        uint64
	LookupErrors      uint64
}

var globalGeoStats = &GeoIPStats{}

// GeoBlocker handles geo-fencing and ASN blocking
type GeoBlocker struct {
	config        *config.Config
	cityDB        *maxminddb.Reader
	asnDB         *maxminddb.Reader
	
	// Fast lookup maps
	blockedCountries map[string]bool
	allowedCountries map[string]bool
	blockedASNs      map[uint]bool
	blockedASNOrgs   []string // Partial match (e.g., "Amazon", "Microsoft", "Google")
	
	mu sync.RWMutex
}

// Known cloud provider ASN patterns
var cloudProviderPatterns = []string{
	"Amazon",
	"Microsoft",
	"Google",
	"DigitalOcean",
	"Linode",
	"Vultr",
	"OVH",
	"Hetzner",
	"Cloudflare",
	"Akamai",
	"Fastly",
	"Alibaba",
	"Tencent",
	"Oracle",
}

// Known hosting/datacenter ASNs
var knownDataCenterASNs = map[uint]string{
	16509:  "Amazon (AWS)",
	14618:  "Amazon (AWS)",
	8075:   "Microsoft (Azure)",
	15169:  "Google Cloud",
	396982: "Google Cloud",
	14061:  "DigitalOcean",
	63949:  "Linode",
	20473:  "Vultr",
	16276:  "OVH",
	24940:  "Hetzner",
	13335:  "Cloudflare",
	20940:  "Akamai",
	54113:  "Fastly",
	45102:  "Alibaba Cloud",
	132203: "Tencent Cloud",
	31898:  "Oracle Cloud",
}

// NewGeoBlocker creates a new geo-blocker
func NewGeoBlocker(cfg *config.Config) (*GeoBlocker, error) {
	gb := &GeoBlocker{
		config:           cfg,
		blockedCountries: make(map[string]bool),
		allowedCountries: make(map[string]bool),
		blockedASNs:      make(map[uint]bool),
	}

	// Load blocked/allowed countries
	for _, c := range cfg.GeoIP.BlockedCountries {
		gb.blockedCountries[strings.ToUpper(c)] = true
	}
	for _, c := range cfg.GeoIP.AllowedCountries {
		gb.allowedCountries[strings.ToUpper(c)] = true
	}

	// Load blocked ASN organizations
	gb.blockedASNOrgs = cloudProviderPatterns

	// Load MaxMind databases if enabled
	if cfg.GeoIP.Enabled && cfg.GeoIP.DatabasePath != "" {
		var err error
		
		// Try to load city database
		gb.cityDB, err = maxminddb.Open(cfg.GeoIP.DatabasePath)
		if err != nil {
			log.Printf("[WARN] Failed to load GeoIP City database: %v", err)
		} else {
			log.Printf("[INFO] GeoIP City database loaded: %s", cfg.GeoIP.DatabasePath)
		}

		// Try to load ASN database (usually separate file)
		asnPath := strings.Replace(cfg.GeoIP.DatabasePath, "City", "ASN", 1)
		asnPath = strings.Replace(asnPath, "Country", "ASN", 1)
		gb.asnDB, err = maxminddb.Open(asnPath)
		if err != nil {
			log.Printf("[WARN] Failed to load GeoIP ASN database: %v", err)
		} else {
			log.Printf("[INFO] GeoIP ASN database loaded: %s", asnPath)
		}
	}

	return gb, nil
}

// Close closes the database readers
func (g *GeoBlocker) Close() {
	if g.cityDB != nil {
		g.cityDB.Close()
	}
	if g.asnDB != nil {
		g.asnDB.Close()
	}
}

// Lookup performs a GeoIP lookup for an IP address
func (g *GeoBlocker) Lookup(ipStr string) (*GeoIPResult, error) {
	atomic.AddUint64(&globalGeoStats.TotalLookups, 1)

	ip := net.ParseIP(ipStr)
	if ip == nil {
		atomic.AddUint64(&globalGeoStats.LookupErrors, 1)
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	result := &GeoIPResult{IP: ipStr}

	// Lookup city/country data
	if g.cityDB != nil {
		var record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
				Names   map[string]string `maxminddb:"names"`
			} `maxminddb:"country"`
			Continent struct {
				Code string `maxminddb:"code"`
			} `maxminddb:"continent"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
			Traits struct {
				IsAnonymousProxy bool `maxminddb:"is_anonymous_proxy"`
			} `maxminddb:"traits"`
		}

		if err := g.cityDB.Lookup(ip, &record); err == nil {
			result.Country = record.Country.ISOCode
			result.CountryName = record.Country.Names["en"]
			result.Continent = record.Continent.Code
			result.City = record.City.Names["en"]
			result.IsProxy = record.Traits.IsAnonymousProxy
		}
	}

	// Lookup ASN data
	if g.asnDB != nil {
		var record struct {
			ASN uint   `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}

		if err := g.asnDB.Lookup(ip, &record); err == nil {
			result.ASN = record.ASN
			result.ASNOrg = record.Org

			// Check if it's a known data center
			if _, known := knownDataCenterASNs[record.ASN]; known {
				result.IsHosting = true
			}

			// Check organization name for cloud providers
			lowerOrg := strings.ToLower(record.Org)
			for _, pattern := range cloudProviderPatterns {
				if strings.Contains(lowerOrg, strings.ToLower(pattern)) {
					result.IsHosting = true
					break
				}
			}
		}
	}

	return result, nil
}

// ShouldBlock checks if an IP should be blocked based on geo-rules
func (g *GeoBlocker) ShouldBlock(result *GeoIPResult) (bool, string) {
	if result == nil {
		return false, ""
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Check if country is in allowed list (whitelist mode)
	if len(g.allowedCountries) > 0 {
		if !g.allowedCountries[result.Country] {
			atomic.AddUint64(&globalGeoStats.CountryBlocked, 1)
			return true, fmt.Sprintf("country not in allow list: %s", result.Country)
		}
	}

	// Check if country is blocked
	if g.blockedCountries[result.Country] {
		atomic.AddUint64(&globalGeoStats.CountryBlocked, 1)
		return true, fmt.Sprintf("blocked country: %s (%s)", result.Country, result.CountryName)
	}

	// Check if ASN is blocked
	if g.blockedASNs[result.ASN] {
		atomic.AddUint64(&globalGeoStats.ASNBlocked, 1)
		return true, fmt.Sprintf("blocked ASN: %d (%s)", result.ASN, result.ASNOrg)
	}

	// Check for data center / cloud provider (if blocking enabled)
	if g.config.GeoIP.BlockDataCenters && result.IsHosting {
		atomic.AddUint64(&globalGeoStats.DataCenterBlocked, 1)
		return true, fmt.Sprintf("blocked data center: %s (ASN %d)", result.ASNOrg, result.ASN)
	}

	// Check for Tor exit nodes (if blocking enabled)
	if g.config.GeoIP.BlockTor && result.IsTor {
		atomic.AddUint64(&globalGeoStats.TorBlocked, 1)
		return true, "blocked Tor exit node"
	}

	// Check for anonymous proxies
	if g.config.GeoIP.BlockProxies && result.IsProxy {
		return true, "blocked anonymous proxy"
	}

	return false, ""
}

// UpdateBlockedCountries updates the blocked countries list (for hot-reload)
func (g *GeoBlocker) UpdateBlockedCountries(countries []string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.blockedCountries = make(map[string]bool)
	for _, c := range countries {
		g.blockedCountries[strings.ToUpper(c)] = true
	}
	log.Printf("[CONFIG] Updated blocked countries: %v", countries)
}

// UpdateAllowedCountries updates the allowed countries list (for hot-reload)
func (g *GeoBlocker) UpdateAllowedCountries(countries []string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.allowedCountries = make(map[string]bool)
	for _, c := range countries {
		g.allowedCountries[strings.ToUpper(c)] = true
	}
	log.Printf("[CONFIG] Updated allowed countries: %v", countries)
}

// AddBlockedASN adds an ASN to the block list
func (g *GeoBlocker) AddBlockedASN(asn uint) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockedASNs[asn] = true
}

// GeoFencing creates the geo-fencing middleware
func GeoFencing(cfg *config.Config, blocker *GeoBlocker) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if GeoIP is disabled
			if !cfg.GeoIP.Enabled || blocker == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for trusted IPs
			if isTrusted, ok := r.Context().Value(IsTrustedKey).(bool); ok && isTrusted {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := GetTrustedClientIP(r)
			
			// Perform GeoIP lookup
			result, err := blocker.Lookup(clientIP)
			if err != nil {
				// Allow on lookup error (fail-open)
				log.Printf("[GEOIP] Lookup error for %s: %v", clientIP, err)
				next.ServeHTTP(w, r)
				return
			}

			// Check if should be blocked
			blocked, reason := blocker.ShouldBlock(result)
			if blocked {
				log.Printf("[BLOCKED] GeoIP block for %s: %s", clientIP, reason)
				sendGeoBlockResponse(w, result, reason)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// sendGeoBlockResponse sends a geo-blocked response
func sendGeoBlockResponse(w http.ResponseWriter, result *GeoIPResult, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	countryDisplay := result.Country
	if result.CountryName != "" {
		countryDisplay = result.CountryName
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - Sentinel-X</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%%, #0f0f1a 100%%);
               color: #fff; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .container { text-align: center; padding: 2rem; background: rgba(255,0,0,0.05); 
                     border-radius: 20px; border: 1px solid rgba(255,0,0,0.2); max-width: 500px; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #ff4444; margin-bottom: 0.5rem; }
        p { color: rgba(255,255,255,0.7); line-height: 1.6; }
        .details { font-size: 0.8rem; color: rgba(255,255,255,0.4); margin-top: 1.5rem; 
                   padding: 1rem; background: rgba(0,0,0,0.2); border-radius: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🌍</div>
        <h1>Access Denied</h1>
        <p>Access from your region is not permitted.</p>
        <div class="details">
            Location: %s<br>
            Ref: SX-GEO-403
        </div>
    </div>
</body>
</html>`, countryDisplay)

	w.Write([]byte(html))
}

// GetGeoIPStats returns current GeoIP statistics
func GetGeoIPStats() GeoIPStats {
	return GeoIPStats{
		TotalLookups:      atomic.LoadUint64(&globalGeoStats.TotalLookups),
		CountryBlocked:    atomic.LoadUint64(&globalGeoStats.CountryBlocked),
		ASNBlocked:        atomic.LoadUint64(&globalGeoStats.ASNBlocked),
		DataCenterBlocked: atomic.LoadUint64(&globalGeoStats.DataCenterBlocked),
		TorBlocked:        atomic.LoadUint64(&globalGeoStats.TorBlocked),
		LookupErrors:      atomic.LoadUint64(&globalGeoStats.LookupErrors),
	}
}
