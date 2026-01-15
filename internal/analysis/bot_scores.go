// Package analysis - Bot Scoring Engine
// Combines multiple signals to calculate a unified risk score
package analysis

import (
	"net/http"
	"strings"
	"time"
)

// BotScorer calculates risk scores based on multiple signals
type BotScorer struct {
	weights          ScoreWeights
	suspiciousAgents []string
}

// ScoreWeights defines the weight of each signal type
type ScoreWeights struct {
	UserAgent      float64
	Headers        float64
	TLSFingerprint float64
	Behavior       float64
	GeoIP          float64
	Reputation     float64
}

// DefaultWeights returns balanced default weights
func DefaultWeights() ScoreWeights {
	return ScoreWeights{
		UserAgent:      0.25,
		Headers:        0.20,
		TLSFingerprint: 0.25,
		Behavior:       0.15,
		GeoIP:          0.10,
		Reputation:     0.05,
	}
}

// NewBotScorer creates a new scoring engine
func NewBotScorer() *BotScorer {
	return &BotScorer{
		weights: DefaultWeights(),
		suspiciousAgents: []string{
			"python", "java/", "ruby", "perl", "php", "go-http",
			"curl", "wget", "scrapy", "httpclient", "libwww",
			"bot", "crawler", "spider", "scraper", "headless",
		},
	}
}

// ScoreRequest calculates a comprehensive risk score for a request
func (bs *BotScorer) ScoreRequest(r *http.Request, ja3Result *FingerprintResult) *ScoringResult {
	result := &ScoringResult{
		Timestamp: time.Now(),
		ClientIP:  extractIP(r),
		Signals:   make([]Signal, 0),
	}

	// Score User-Agent
	uaScore := bs.scoreUserAgent(r, result)
	
	// Score Headers
	headerScore := bs.scoreHeaders(r, result)
	
	// Score TLS Fingerprint
	tlsScore := bs.scoreTLS(ja3Result, result)
	
	// Score Behavioral patterns
	behaviorScore := bs.scoreBehavior(r, result)
	
	// Calculate weighted total
	totalScore := 0.0
	totalScore += float64(uaScore) * bs.weights.UserAgent
	totalScore += float64(headerScore) * bs.weights.Headers
	totalScore += float64(tlsScore) * bs.weights.TLSFingerprint
	totalScore += float64(behaviorScore) * bs.weights.Behavior
	
	// Normalize to 0-100
	result.FinalScore = int(totalScore)
	if result.FinalScore > 100 {
		result.FinalScore = 100
	}
	
	// Determine verdict
	result.Verdict = bs.determineVerdict(result.FinalScore)
	
	return result
}

// scoreUserAgent analyzes the User-Agent string
func (bs *BotScorer) scoreUserAgent(r *http.Request, result *ScoringResult) int {
	ua := r.UserAgent()
	score := 0
	
	// Empty User-Agent
	if ua == "" {
		score = 80
		result.addSignal("user_agent", "empty", 80, "No User-Agent header")
		return score
	}
	
	// Very short User-Agent
	if len(ua) < 20 {
		score += 30
		result.addSignal("user_agent", "short", 30, "Unusually short User-Agent")
	}
	
	// Check for suspicious patterns
	lowerUA := strings.ToLower(ua)
	for _, suspicious := range bs.suspiciousAgents {
		if strings.Contains(lowerUA, suspicious) {
			score += 50
			result.addSignal("user_agent", "suspicious_pattern", 50, 
				"Contains suspicious identifier: "+suspicious)
			break
		}
	}
	
	// Check for browser indicators
	browsers := []string{"chrome", "firefox", "safari", "edge", "opera"}
	hasBrowser := false
	for _, browser := range browsers {
		if strings.Contains(lowerUA, browser) {
			hasBrowser = true
			break
		}
	}
	if !hasBrowser && score < 30 {
		score += 20
		result.addSignal("user_agent", "no_browser", 20, "No browser identifier found")
	}
	
	return score
}

// scoreHeaders analyzes HTTP headers
func (bs *BotScorer) scoreHeaders(r *http.Request, result *ScoringResult) int {
	score := 0
	
	// Missing Accept header
	if r.Header.Get("Accept") == "" {
		score += 25
		result.addSignal("headers", "missing_accept", 25, "Missing Accept header")
	}
	
	// Missing Accept-Language
	if r.Header.Get("Accept-Language") == "" {
		score += 20
		result.addSignal("headers", "missing_language", 20, "Missing Accept-Language header")
	}
	
	// Missing Accept-Encoding
	if r.Header.Get("Accept-Encoding") == "" {
		score += 15
		result.addSignal("headers", "missing_encoding", 15, "Missing Accept-Encoding header")
	}
	
	// Connection: close (bots often use this)
	if r.Header.Get("Connection") == "close" {
		score += 10
		result.addSignal("headers", "connection_close", 10, "Connection: close header")
	}
	
	// Check for automation-specific headers
	automationHeaders := []string{
		"X-Requested-With", "X-Automation", "Headless-Chrome",
	}
	for _, header := range automationHeaders {
		if r.Header.Get(header) != "" {
			score += 30
			result.addSignal("headers", "automation_header", 30, 
				"Automation header present: "+header)
			break
		}
	}
	
	return score
}

// scoreTLS analyzes TLS fingerprint results
func (bs *BotScorer) scoreTLS(ja3Result *FingerprintResult, result *ScoringResult) int {
	if ja3Result == nil {
		// No TLS analysis available (might be HTTP)
		return 0
	}
	
	score := ja3Result.RiskScore
	
	// Add signals from JA3 analysis
	for _, signal := range ja3Result.Signals {
		result.addSignal("tls", "ja3_signal", 0, signal)
	}
	
	if ja3Result.IsKnownBot {
		result.addSignal("tls", "known_bot", 60, "Known bot TLS fingerprint")
	}
	
	if ja3Result.IsKnownBrowser {
		score -= 20 // Reduce score for known browsers
		if score < 0 {
			score = 0
		}
		result.addSignal("tls", "known_browser", -20, "Known browser TLS fingerprint")
	}
	
	return score
}

// scoreBehavior analyzes request behavior patterns
func (bs *BotScorer) scoreBehavior(r *http.Request, result *ScoringResult) int {
	score := 0
	
	// Direct IP access
	if r.Host == "" {
		score += 15
		result.addSignal("behavior", "no_host", 15, "Direct IP access without Host header")
	}
	
	// Unusual request method for path
	if r.Method == http.MethodPost && r.URL.Path == "/" {
		score += 10
		result.addSignal("behavior", "root_post", 10, "POST request to root path")
	}
	
	// Check for rapid automated patterns in query string
	query := r.URL.RawQuery
	if len(query) > 500 {
		score += 15
		result.addSignal("behavior", "long_query", 15, "Unusually long query string")
	}
	
	return score
}

// determineVerdict returns the final verdict based on score
func (bs *BotScorer) determineVerdict(score int) Verdict {
	switch {
	case score >= 80:
		return VerdictBot
	case score >= 50:
		return VerdictSuspicious
	case score >= 30:
		return VerdictUncertain
	default:
		return VerdictHuman
	}
}

// Verdict represents the final classification
type Verdict string

const (
	VerdictHuman      Verdict = "human"
	VerdictBot        Verdict = "bot"
	VerdictSuspicious Verdict = "suspicious"
	VerdictUncertain  Verdict = "uncertain"
)

// Signal represents a single scoring signal
type Signal struct {
	Category    string
	Type        string
	Score       int
	Description string
}

// ScoringResult contains the complete scoring results
type ScoringResult struct {
	Timestamp   time.Time
	ClientIP    string
	FinalScore  int
	Verdict     Verdict
	Signals     []Signal
}

// AddSignal adds a signal to the result
func (sr *ScoringResult) addSignal(category, signalType string, score int, description string) {
	sr.Signals = append(sr.Signals, Signal{
		Category:    category,
		Type:        signalType,
		Score:       score,
		Description: description,
	})
}

// IsBot returns true if the verdict is bot
func (sr *ScoringResult) IsBot() bool {
	return sr.Verdict == VerdictBot
}

// IsSuspicious returns true if the verdict is suspicious or bot
func (sr *ScoringResult) IsSuspicious() bool {
	return sr.Verdict == VerdictBot || sr.Verdict == VerdictSuspicious
}

// Helper function to extract IP
func extractIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	// Remove port from RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
