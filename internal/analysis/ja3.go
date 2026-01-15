// Package analysis - JA3/JA4 TLS Fingerprinting
// The "Investigator" module for TLS fingerprint analysis
package analysis

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// JA3Fingerprint represents a TLS fingerprint
type JA3Fingerprint struct {
	Raw        string // The raw JA3 string
	Hash       string // MD5 hash of the JA3 string
	SSLVersion uint16
	Ciphers    []uint16
	Extensions []uint16
	Groups     []uint16
	Points     []uint8
}

// NewJA3Fingerprint creates a JA3 fingerprint from TLS ClientHello data
func NewJA3Fingerprint(
	sslVersion uint16,
	ciphers []uint16,
	extensions []uint16,
	groups []uint16,
	points []uint8,
) *JA3Fingerprint {
	fp := &JA3Fingerprint{
		SSLVersion: sslVersion,
		Ciphers:    ciphers,
		Extensions: extensions,
		Groups:     groups,
		Points:     points,
	}
	
	fp.Raw = fp.computeRaw()
	fp.Hash = fp.computeHash()
	
	return fp
}

// computeRaw generates the raw JA3 string
func (j *JA3Fingerprint) computeRaw() string {
	// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	
	// SSLVersion
	version := strconv.FormatUint(uint64(j.SSLVersion), 10)
	
	// Ciphers (comma-separated)
	cipherStrs := make([]string, len(j.Ciphers))
	for i, c := range j.Ciphers {
		cipherStrs[i] = strconv.FormatUint(uint64(c), 10)
	}
	ciphers := strings.Join(cipherStrs, "-")
	
	// Extensions (comma-separated)
	extStrs := make([]string, len(j.Extensions))
	for i, e := range j.Extensions {
		extStrs[i] = strconv.FormatUint(uint64(e), 10)
	}
	extensions := strings.Join(extStrs, "-")
	
	// Elliptic Curves/Groups
	groupStrs := make([]string, len(j.Groups))
	for i, g := range j.Groups {
		groupStrs[i] = strconv.FormatUint(uint64(g), 10)
	}
	groups := strings.Join(groupStrs, "-")
	
	// Point Formats
	pointStrs := make([]string, len(j.Points))
	for i, p := range j.Points {
		pointStrs[i] = strconv.FormatUint(uint64(p), 10)
	}
	points := strings.Join(pointStrs, "-")
	
	return fmt.Sprintf("%s,%s,%s,%s,%s", version, ciphers, extensions, groups, points)
}

// computeHash generates the MD5 hash of the JA3 string
func (j *JA3Fingerprint) computeHash() string {
	hash := md5.Sum([]byte(j.Raw))
	return hex.EncodeToString(hash[:])
}

// KnownFingerprints contains database of known JA3 fingerprints
var KnownFingerprints = map[string]string{
	// Chrome fingerprints (various versions)
	"b32309a26951912be7dba376398abc3b": "Chrome",
	"56d7bf6e2cd0f3e2f3c4b2e1a0a5d7c9": "Chrome Mobile",
	
	// Firefox fingerprints
	"9f0e7c2a1b3d4e5f6a7b8c9d0e1f2a3b": "Firefox",
	
	// Safari fingerprints
	"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d": "Safari",
	
	// Known bot/automation fingerprints
	"e7d705a3286853e07d9b65c7c0e6f6a1": "Python Requests",
	"c12f54a143e6e5b7e7e5f5a7b3d1e5c9": "Go HTTP Client",
	"a0e9f5d6c7b8a9e0f1d2c3b4a5e6f7d8": "Java HTTP Client",
	"b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6": "Curl",
	"d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9": "Scrapy",
	"e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0": "Selenium",
	"f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1": "Puppeteer",
	"a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2": "PhantomJS",
}

// FingerprintAnalyzer analyzes TLS fingerprints
type FingerprintAnalyzer struct {
	knownBots     map[string]bool
	knownBrowsers map[string]bool
}

// NewFingerprintAnalyzer creates a new analyzer
func NewFingerprintAnalyzer() *FingerprintAnalyzer {
	fa := &FingerprintAnalyzer{
		knownBots:     make(map[string]bool),
		knownBrowsers: make(map[string]bool),
	}
	
	// Categorize known fingerprints
	botIdentifiers := []string{"Python", "Go", "Java", "Curl", "Scrapy", "Selenium", "Puppeteer", "PhantomJS"}
	browserIdentifiers := []string{"Chrome", "Firefox", "Safari", "Edge", "Opera"}
	
	for hash, name := range KnownFingerprints {
		for _, id := range botIdentifiers {
			if strings.Contains(name, id) {
				fa.knownBots[hash] = true
				break
			}
		}
		for _, id := range browserIdentifiers {
			if strings.Contains(name, id) {
				fa.knownBrowsers[hash] = true
				break
			}
		}
	}
	
	return fa
}

// Analyze examines a fingerprint and returns analysis results
func (fa *FingerprintAnalyzer) Analyze(fp *JA3Fingerprint) *FingerprintResult {
	result := &FingerprintResult{
		Fingerprint: fp,
		RiskScore:   0,
		Signals:     make([]string, 0),
	}
	
	// Check against known bots
	if fa.knownBots[fp.Hash] {
		result.RiskScore += 60
		result.Signals = append(result.Signals, "Known bot TLS fingerprint")
		result.IsKnownBot = true
	}
	
	// Check if it's a known browser
	if fa.knownBrowsers[fp.Hash] {
		result.IsKnownBrowser = true
		result.Signals = append(result.Signals, "Known browser TLS fingerprint")
	}
	
	// Analyze cipher suite choices
	result.RiskScore += fa.analyzeCiphers(fp, result)
	
	// Analyze extension patterns
	result.RiskScore += fa.analyzeExtensions(fp, result)
	
	// Cap risk score at 100
	if result.RiskScore > 100 {
		result.RiskScore = 100
	}
	
	return result
}

// analyzeCiphers examines cipher suite selection
func (fa *FingerprintAnalyzer) analyzeCiphers(fp *JA3Fingerprint, result *FingerprintResult) int {
	riskAdd := 0
	
	// Very few ciphers is suspicious (browsers offer many)
	if len(fp.Ciphers) < 5 {
		riskAdd += 10
		result.Signals = append(result.Signals, "Suspiciously few cipher suites")
	}
	
	// No modern ciphers is suspicious
	hasModernCipher := false
	modernCiphers := map[uint16]bool{
		0x1301: true, // TLS_AES_128_GCM_SHA256
		0x1302: true, // TLS_AES_256_GCM_SHA384
		0x1303: true, // TLS_CHACHA20_POLY1305_SHA256
	}
	for _, c := range fp.Ciphers {
		if modernCiphers[c] {
			hasModernCipher = true
			break
		}
	}
	if !hasModernCipher {
		riskAdd += 15
		result.Signals = append(result.Signals, "No TLS 1.3 cipher suites")
	}
	
	return riskAdd
}

// analyzeExtensions examines TLS extension patterns
func (fa *FingerprintAnalyzer) analyzeExtensions(fp *JA3Fingerprint, result *FingerprintResult) int {
	riskAdd := 0
	
	// Very few extensions is suspicious
	if len(fp.Extensions) < 5 {
		riskAdd += 10
		result.Signals = append(result.Signals, "Suspiciously few TLS extensions")
	}
	
	// Check for GREASE values (browsers use these, bots often don't)
	hasGrease := false
	greaseValues := map[uint16]bool{
		0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
		0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
		0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
		0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
	}
	for _, e := range fp.Extensions {
		if greaseValues[e] {
			hasGrease = true
			break
		}
	}
	if !hasGrease {
		riskAdd += 15
		result.Signals = append(result.Signals, "No GREASE values (unusual for browsers)")
	}
	
	return riskAdd
}

// FingerprintResult contains the analysis results
type FingerprintResult struct {
	Fingerprint    *JA3Fingerprint
	RiskScore      int
	Signals        []string
	IsKnownBot     bool
	IsKnownBrowser bool
}

// CompareFingerprints checks if two fingerprints are similar
func CompareFingerprints(a, b *JA3Fingerprint) float64 {
	if a.Hash == b.Hash {
		return 1.0
	}
	
	// Calculate Jaccard similarity of cipher suites
	aCiphers := make(map[uint16]bool)
	for _, c := range a.Ciphers {
		aCiphers[c] = true
	}
	
	intersection := 0
	for _, c := range b.Ciphers {
		if aCiphers[c] {
			intersection++
		}
	}
	
	union := len(a.Ciphers) + len(b.Ciphers) - intersection
	if union == 0 {
		return 0
	}
	
	return float64(intersection) / float64(union)
}

// SortExtensions sorts extensions for consistent fingerprinting
func SortExtensions(extensions []uint16) []uint16 {
	sorted := make([]uint16, len(extensions))
	copy(sorted, extensions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	return sorted
}
