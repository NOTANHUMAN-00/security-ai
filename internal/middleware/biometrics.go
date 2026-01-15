// Package middleware - Behavioral Biometric Telemetry
// =============================================================================
// BEHAVIORAL ANALYSIS: Track HOW users interact, not just WHAT they request
//
// Humans vs Bots exhibit fundamentally different behavioral patterns:
//
// MOUSE MOVEMENT:
//   - Humans: Move in curves/arcs, accelerate/decelerate, micro-corrections
//   - Bots: Straight lines, instant teleportation (0ms travel), robotic precision
//
// ACCELEROMETER (Mobile):
//   - Real Phone: Natural variance from hand tremor (even "still" phones move)
//   - Emulator: Perfect 0.0000 variance - server rack doesn't shake
//
// KEYBOARD DYNAMICS:
//   - Humans: Variable timing between keystrokes, natural rhythm
//   - Bots: Perfectly consistent timing or instant paste
//
// SCROLL PATTERNS:
//   - Humans: Variable speed, pauses to read, irregular patterns
//   - Bots: Consistent speed, no pauses, mechanical scrolling
//
// =============================================================================
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// =============================================================================
// BIOMETRIC DATA STRUCTURES
// =============================================================================

// MousePoint represents a single mouse position with timestamp
type MousePoint struct {
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Timestamp int64   `json:"t"` // Milliseconds since page load
}

// AccelerometerReading represents a single accelerometer reading
type AccelerometerReading struct {
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Z         float64 `json:"z"`
	Timestamp int64   `json:"t"`
}

// KeystrokeEvent represents a single keystroke timing
type KeystrokeEvent struct {
	KeyCode   int   `json:"k"`
	DownTime  int64 `json:"d"` // Key down timestamp
	UpTime    int64 `json:"u"` // Key up timestamp
	Interval  int64 `json:"i"` // Time since last key
}

// ScrollEvent represents scroll behavior
type ScrollEvent struct {
	DeltaY    float64 `json:"dy"`
	Timestamp int64   `json:"t"`
	Direction int     `json:"dir"` // 1 = down, -1 = up
}

// BiometricTelemetry holds all collected behavioral data
type BiometricTelemetry struct {
	SessionID     string `json:"session_id"`
	
	// Mouse data
	MousePoints   []MousePoint `json:"mouse_points"`
	MouseEntropy  float64      `json:"mouse_entropy"`
	StraightLines int          `json:"straight_lines"`
	Teleports     int          `json:"teleports"`
	
	// Accelerometer data (mobile)
	AccelReadings []AccelerometerReading `json:"accel_readings"`
	AccelVariance float64                `json:"accel_variance"`
	HasAccel      bool                   `json:"has_accel"`
	
	// Keyboard data
	Keystrokes    []KeystrokeEvent `json:"keystrokes"`
	TypingSpeed   float64          `json:"typing_speed"` // WPM
	KeyVariance   float64          `json:"key_variance"`
	
	// Scroll data
	ScrollEvents  []ScrollEvent `json:"scroll_events"`
	ScrollVariance float64      `json:"scroll_variance"`
	
	// Touch data (mobile)
	TouchCount    int     `json:"touch_count"`
	TouchPressure float64 `json:"touch_pressure"`
	
	// Time metrics
	TimeOnPage    int64 `json:"time_on_page"`
	InteractionStart int64 `json:"interaction_start"`
	
	// Device claimed
	ClaimedUA     string `json:"claimed_ua"`
	ScreenWidth   int    `json:"screen_width"`
	ScreenHeight  int    `json:"screen_height"`
}

// BiometricScore represents the analysis result
type BiometricScore struct {
	IsHuman          bool    `json:"is_human"`
	Confidence       float64 `json:"confidence"` // 0-100
	MouseScore       float64 `json:"mouse_score"`
	AccelScore       float64 `json:"accel_score"`
	KeyboardScore    float64 `json:"keyboard_score"`
	ScrollScore      float64 `json:"scroll_score"`
	ConsistencyScore float64 `json:"consistency_score"`
	Flags            []string `json:"flags"`
}

// BiometricStats tracks biometric analysis statistics
type BiometricStats struct {
	TotalSessions    uint64
	HumanDetected    uint64
	BotDetected      uint64
	MobileEmulators  uint64
	MouseBots        uint64
	KeyboardBots     uint64
}

var globalBiometricStats = &BiometricStats{}
var biometricScoreCache = make(map[string]*BiometricScore)
var biometricCacheMu sync.RWMutex

// GetBiometricStats returns current stats
func GetBiometricStats() BiometricStats {
	return BiometricStats{
		TotalSessions:   atomic.LoadUint64(&globalBiometricStats.TotalSessions),
		HumanDetected:   atomic.LoadUint64(&globalBiometricStats.HumanDetected),
		BotDetected:     atomic.LoadUint64(&globalBiometricStats.BotDetected),
		MobileEmulators: atomic.LoadUint64(&globalBiometricStats.MobileEmulators),
		MouseBots:       atomic.LoadUint64(&globalBiometricStats.MouseBots),
		KeyboardBots:    atomic.LoadUint64(&globalBiometricStats.KeyboardBots),
	}
}

// =============================================================================
// BIOMETRIC MIDDLEWARE
// =============================================================================

// BiometricMiddleware analyzes behavioral patterns
type BiometricMiddleware struct {
	config *config.Config
	store  storage.Store
}

// BehavioralBiometrics creates the biometric analysis middleware
func BehavioralBiometrics(cfg *config.Config, store storage.Store) Middleware {
	bm := &BiometricMiddleware{
		config: cfg,
		store:  store,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for biometric telemetry submission
			if r.URL.Path == "/sentinel/biometrics" && r.Method == "POST" {
				bm.handleBiometricSubmission(w, r)
				return
			}

			// Check for existing biometric session
			sessionCookie, err := r.Cookie("sx_bio_session")
			if err == nil && sessionCookie.Value != "" {
				// Check if we have a score for this session
				biometricCacheMu.RLock()
				score, exists := biometricScoreCache[sessionCookie.Value]
				biometricCacheMu.RUnlock()

				if exists && !score.IsHuman && score.Confidence > 80 {
					// High confidence bot - block or challenge
					log.Printf("[BIOMETRIC] Bot detected via behavior: session=%s, confidence=%.1f%%",
						sessionCookie.Value, score.Confidence)
					
					// Add to context for other middleware
					ctx := context.WithValue(r.Context(), RiskScoreKey, int(score.Confidence))
					r = r.WithContext(ctx)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// handleBiometricSubmission processes submitted telemetry
func (bm *BiometricMiddleware) handleBiometricSubmission(w http.ResponseWriter, r *http.Request) {
	var telemetry BiometricTelemetry
	if err := json.NewDecoder(r.Body).Decode(&telemetry); err != nil {
		http.Error(w, "Invalid telemetry data", http.StatusBadRequest)
		return
	}

	atomic.AddUint64(&globalBiometricStats.TotalSessions, 1)

	// Analyze the telemetry
	score := bm.analyzeTelemetry(&telemetry, r)

	// Cache the score
	if telemetry.SessionID != "" {
		biometricCacheMu.Lock()
		biometricScoreCache[telemetry.SessionID] = score
		biometricCacheMu.Unlock()
	}

	// Store in Redis for persistence
	if bm.store != nil {
		key := fmt.Sprintf("bio:score:%s", telemetry.SessionID)
		scoreData, _ := json.Marshal(score)
		bm.store.Set(r.Context(), key, string(scoreData), 30*time.Minute)
	}

	// Log suspicious behavior
	if !score.IsHuman {
		clientIP := GetTrustedClientIP(r)
		log.Printf("[BIOMETRIC] 🤖 Bot behavior detected: IP=%s, confidence=%.1f%%, flags=%v",
			clientIP, score.Confidence, score.Flags)
		atomic.AddUint64(&globalBiometricStats.BotDetected, 1)
	} else {
		atomic.AddUint64(&globalBiometricStats.HumanDetected, 1)
	}

	// Return score (optional - for debugging)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"human":  score.IsHuman,
	})
}

// =============================================================================
// BEHAVIORAL ANALYSIS ENGINE
// =============================================================================

// analyzeTelemetry performs comprehensive behavioral analysis
func (bm *BiometricMiddleware) analyzeTelemetry(t *BiometricTelemetry, r *http.Request) *BiometricScore {
	score := &BiometricScore{
		IsHuman:    true,
		Confidence: 0,
		Flags:      []string{},
	}

	// Analyze each behavioral dimension
	score.MouseScore = bm.analyzeMouseMovement(t, score)
	score.AccelScore = bm.analyzeAccelerometer(t, r, score)
	score.KeyboardScore = bm.analyzeKeyboard(t, score)
	score.ScrollScore = bm.analyzeScroll(t, score)
	score.ConsistencyScore = bm.analyzeConsistency(t, r, score)

	// Calculate overall score
	weights := map[string]float64{
		"mouse":       0.25,
		"accel":       0.20,
		"keyboard":    0.20,
		"scroll":      0.15,
		"consistency": 0.20,
	}

	totalScore := score.MouseScore*weights["mouse"] +
		score.AccelScore*weights["accel"] +
		score.KeyboardScore*weights["keyboard"] +
		score.ScrollScore*weights["scroll"] +
		score.ConsistencyScore*weights["consistency"]

	// Determine human/bot classification
	if totalScore < 40 {
		score.IsHuman = true
		score.Confidence = 100 - totalScore
	} else if totalScore > 60 {
		score.IsHuman = false
		score.Confidence = totalScore
	} else {
		// Ambiguous - lean towards human
		score.IsHuman = true
		score.Confidence = 50
	}

	return score
}

// =============================================================================
// MOUSE MOVEMENT ANALYSIS
// =============================================================================

// analyzeMouseMovement calculates mouse behavior score (0 = human, 100 = bot)
func (bm *BiometricMiddleware) analyzeMouseMovement(t *BiometricTelemetry, score *BiometricScore) float64 {
	if len(t.MousePoints) < 10 {
		// Not enough data - neutral score
		return 50
	}

	botScore := 0.0
	points := t.MousePoints

	// Check 1: Calculate path curvature (humans move in curves)
	totalCurvature := 0.0
	straightSegments := 0
	teleportCount := 0

	for i := 2; i < len(points); i++ {
		p0 := points[i-2]
		p1 := points[i-1]
		p2 := points[i]

		// Calculate curvature using cross product
		dx1 := p1.X - p0.X
		dy1 := p1.Y - p0.Y
		dx2 := p2.X - p1.X
		dy2 := p2.Y - p1.Y

		cross := dx1*dy2 - dy1*dx2
		len1 := math.Sqrt(dx1*dx1 + dy1*dy1)
		len2 := math.Sqrt(dx2*dx2 + dy2*dy2)

		if len1 > 0 && len2 > 0 {
			curvature := math.Abs(cross) / (len1 * len2)
			totalCurvature += curvature

			// Nearly straight line (low curvature)
			if curvature < 0.01 {
				straightSegments++
			}
		}

		// Check for teleportation (instant position change)
		timeDiff := p2.Timestamp - p1.Timestamp
		distance := math.Sqrt(dx2*dx2 + dy2*dy2)

		if timeDiff <= 1 && distance > 50 {
			teleportCount++
		}

		// Check for impossible speed (bots move instantly)
		if timeDiff > 0 {
			speed := distance / float64(timeDiff) // pixels per ms
			if speed > 10 { // > 10 px/ms is superhuman
				teleportCount++
			}
		}
	}

	// Average curvature
	avgCurvature := totalCurvature / float64(len(points)-2)
	
	// Humans typically have curvature > 0.05
	if avgCurvature < 0.02 {
		botScore += 30
		score.Flags = append(score.Flags, "straight_mouse_movement")
		atomic.AddUint64(&globalBiometricStats.MouseBots, 1)
	} else if avgCurvature < 0.05 {
		botScore += 15
	}

	// Too many straight segments
	straightRatio := float64(straightSegments) / float64(len(points)-2)
	if straightRatio > 0.8 {
		botScore += 25
		score.Flags = append(score.Flags, "robotic_path")
	}

	// Teleportation detection
	if teleportCount > 5 {
		botScore += 30
		score.Flags = append(score.Flags, "mouse_teleportation")
	}

	// Check 2: Movement entropy (randomness)
	entropy := calculateMouseEntropy(points)
	if entropy < 2.0 { // Low entropy = predictable/robotic
		botScore += 20
		score.Flags = append(score.Flags, "low_mouse_entropy")
	}

	// Check 3: Timestamp regularity (bots often have regular intervals)
	intervalVariance := calculateTimestampVariance(points)
	if intervalVariance < 5 { // Very regular = suspicious
		botScore += 15
		score.Flags = append(score.Flags, "regular_mouse_intervals")
	}

	return math.Min(botScore, 100)
}

// calculateMouseEntropy calculates Shannon entropy of mouse movement
func calculateMouseEntropy(points []MousePoint) float64 {
	if len(points) < 2 {
		return 0
	}

	// Discretize angles into buckets
	buckets := make(map[int]int)
	for i := 1; i < len(points); i++ {
		dx := points[i].X - points[i-1].X
		dy := points[i].Y - points[i-1].Y
		
		if dx == 0 && dy == 0 {
			continue
		}

		angle := math.Atan2(dy, dx)
		bucket := int((angle + math.Pi) / (math.Pi / 8)) // 16 direction buckets
		buckets[bucket]++
	}

	// Calculate entropy
	total := 0
	for _, count := range buckets {
		total += count
	}

	entropy := 0.0
	for _, count := range buckets {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// calculateTimestampVariance calculates variance in time intervals
func calculateTimestampVariance(points []MousePoint) float64 {
	if len(points) < 3 {
		return 0
	}

	intervals := make([]float64, 0, len(points)-1)
	for i := 1; i < len(points); i++ {
		intervals = append(intervals, float64(points[i].Timestamp-points[i-1].Timestamp))
	}

	// Calculate variance
	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))

	variance := 0.0
	for _, v := range intervals {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	return variance
}

// =============================================================================
// ACCELEROMETER ANALYSIS (Mobile)
// =============================================================================

// analyzeAccelerometer checks if mobile accelerometer data is realistic
func (bm *BiometricMiddleware) analyzeAccelerometer(t *BiometricTelemetry, r *http.Request, score *BiometricScore) float64 {
	ua := strings.ToLower(r.UserAgent())
	isMobile := strings.Contains(ua, "iphone") || strings.Contains(ua, "android") ||
		strings.Contains(ua, "mobile") || strings.Contains(ua, "tablet")

	// If not claiming to be mobile, skip
	if !isMobile {
		return 50 // Neutral
	}

	// Mobile claims to be a phone - check accelerometer
	if !t.HasAccel || len(t.AccelReadings) < 10 {
		// Claims to be mobile but no accelerometer data
		score.Flags = append(score.Flags, "missing_accelerometer")
		atomic.AddUint64(&globalBiometricStats.MobileEmulators, 1)
		return 80 // Very suspicious
	}

	// Calculate variance in accelerometer readings
	var sumX, sumY, sumZ float64
	readings := t.AccelReadings

	for _, r := range readings {
		sumX += r.X
		sumY += r.Y
		sumZ += r.Z
	}

	meanX := sumX / float64(len(readings))
	meanY := sumY / float64(len(readings))
	meanZ := sumZ / float64(len(readings))

	var varX, varY, varZ float64
	for _, r := range readings {
		varX += (r.X - meanX) * (r.X - meanX)
		varY += (r.Y - meanY) * (r.Y - meanY)
		varZ += (r.Z - meanZ) * (r.Z - meanZ)
	}

	varX /= float64(len(readings))
	varY /= float64(len(readings))
	varZ /= float64(len(readings))

	totalVariance := varX + varY + varZ

	// Real phones have natural micro-tremors (variance > 0.001)
	// Emulators sitting on servers have nearly zero variance
	if totalVariance < 0.0001 {
		score.Flags = append(score.Flags, "flat_accelerometer_emulator")
		atomic.AddUint64(&globalBiometricStats.MobileEmulators, 1)
		return 95 // Almost certainly emulator
	}

	if totalVariance < 0.001 {
		score.Flags = append(score.Flags, "suspicious_accelerometer")
		return 70
	}

	// Check for perfectly periodic readings (fake data)
	if hasPeriodicPattern(readings) {
		score.Flags = append(score.Flags, "periodic_accelerometer")
		return 75
	}

	return 20 // Looks human
}

// hasPeriodicPattern checks if accelerometer data has artificial periodicity
func hasPeriodicPattern(readings []AccelerometerReading) bool {
	if len(readings) < 20 {
		return false
	}

	// Check for perfect repetition
	for period := 2; period < len(readings)/4; period++ {
		matches := 0
		for i := period; i < len(readings); i++ {
			if math.Abs(readings[i].X-readings[i-period].X) < 0.0001 &&
				math.Abs(readings[i].Y-readings[i-period].Y) < 0.0001 &&
				math.Abs(readings[i].Z-readings[i-period].Z) < 0.0001 {
				matches++
			}
		}
		if float64(matches)/float64(len(readings)-period) > 0.9 {
			return true
		}
	}
	return false
}

// =============================================================================
// KEYBOARD ANALYSIS
// =============================================================================

// analyzeKeyboard analyzes typing patterns
func (bm *BiometricMiddleware) analyzeKeyboard(t *BiometricTelemetry, score *BiometricScore) float64 {
	if len(t.Keystrokes) < 5 {
		return 50 // Not enough data
	}

	botScore := 0.0
	keystrokes := t.Keystrokes

	// Check 1: Key hold duration (time between keydown and keyup)
	var holdTimes []float64
	for _, k := range keystrokes {
		if k.UpTime > k.DownTime {
			holdTimes = append(holdTimes, float64(k.UpTime-k.DownTime))
		}
	}

	if len(holdTimes) > 0 {
		holdVariance := calculateVariance(holdTimes)
		avgHold := calculateMean(holdTimes)

		// Humans have variable hold times (50-200ms typically)
		if holdVariance < 5 {
			botScore += 25
			score.Flags = append(score.Flags, "robotic_key_holds")
			atomic.AddUint64(&globalBiometricStats.KeyboardBots, 1)
		}

		// Superhuman typing speed
		if avgHold < 30 {
			botScore += 20
			score.Flags = append(score.Flags, "superhuman_typing")
		}
	}

	// Check 2: Inter-key intervals
	var intervals []float64
	for i := 1; i < len(keystrokes); i++ {
		interval := float64(keystrokes[i].DownTime - keystrokes[i-1].UpTime)
		if interval > 0 {
			intervals = append(intervals, interval)
		}
	}

	if len(intervals) > 0 {
		intervalVariance := calculateVariance(intervals)

		// Humans have variable typing rhythm
		if intervalVariance < 10 {
			botScore += 25
			score.Flags = append(score.Flags, "robotic_typing_rhythm")
		}
	}

	// Check 3: Impossible overlap (multiple keys down at impossible speed)
	simultaneousKeys := 0
	for i := 1; i < len(keystrokes); i++ {
		if keystrokes[i].DownTime < keystrokes[i-1].UpTime &&
			keystrokes[i].DownTime-keystrokes[i-1].DownTime < 10 {
			simultaneousKeys++
		}
	}
	if float64(simultaneousKeys)/float64(len(keystrokes)) > 0.5 {
		botScore += 30
		score.Flags = append(score.Flags, "paste_detected")
	}

	return math.Min(botScore, 100)
}

// =============================================================================
// SCROLL ANALYSIS
// =============================================================================

// analyzeScroll analyzes scroll behavior
func (bm *BiometricMiddleware) analyzeScroll(t *BiometricTelemetry, score *BiometricScore) float64 {
	if len(t.ScrollEvents) < 5 {
		return 50
	}

	botScore := 0.0
	scrolls := t.ScrollEvents

	// Check 1: Scroll speed variance
	var speeds []float64
	for i := 1; i < len(scrolls); i++ {
		timeDiff := scrolls[i].Timestamp - scrolls[i-1].Timestamp
		if timeDiff > 0 {
			speed := math.Abs(scrolls[i].DeltaY) / float64(timeDiff)
			speeds = append(speeds, speed)
		}
	}

	if len(speeds) > 0 {
		variance := calculateVariance(speeds)
		if variance < 0.01 {
			botScore += 25
			score.Flags = append(score.Flags, "robotic_scroll")
		}
	}

	// Check 2: Direction changes (humans change direction, bots often scroll one way)
	directionChanges := 0
	for i := 1; i < len(scrolls); i++ {
		if scrolls[i].Direction != scrolls[i-1].Direction {
			directionChanges++
		}
	}

	changeRatio := float64(directionChanges) / float64(len(scrolls)-1)
	if changeRatio < 0.1 && len(scrolls) > 20 {
		botScore += 15
		score.Flags = append(score.Flags, "unidirectional_scroll")
	}

	// Check 3: Perfect scroll amounts (bots often scroll exact pixels)
	exactAmounts := 0
	for _, s := range scrolls {
		if math.Mod(s.DeltaY, 100) == 0 { // Perfectly divisible by 100
			exactAmounts++
		}
	}
	if float64(exactAmounts)/float64(len(scrolls)) > 0.8 {
		botScore += 20
		score.Flags = append(score.Flags, "programmatic_scroll")
	}

	return math.Min(botScore, 100)
}

// =============================================================================
// CONSISTENCY ANALYSIS
// =============================================================================

// analyzeConsistency checks if behavior matches claimed device
func (bm *BiometricMiddleware) analyzeConsistency(t *BiometricTelemetry, r *http.Request, score *BiometricScore) float64 {
	botScore := 0.0
	ua := r.UserAgent()

	// Check 1: Mobile claims with desktop behavior
	if strings.Contains(strings.ToLower(ua), "mobile") ||
		strings.Contains(strings.ToLower(ua), "iphone") ||
		strings.Contains(strings.ToLower(ua), "android") {

		// Mobile should have touch events, not mouse events
		if len(t.MousePoints) > 50 && t.TouchCount == 0 {
			botScore += 30
			score.Flags = append(score.Flags, "mobile_with_mouse")
		}

		// Mobile with no accelerometer
		if !t.HasAccel {
			botScore += 25
			score.Flags = append(score.Flags, "mobile_no_sensors")
		}
	}

	// Check 2: Screen size vs UA
	if strings.Contains(strings.ToLower(ua), "iphone") {
		// iPhone screens are specific sizes
		if t.ScreenWidth > 500 || t.ScreenHeight > 1000 {
			botScore += 20
			score.Flags = append(score.Flags, "wrong_iphone_resolution")
		}
	}

	// Check 3: Time on page vs interaction
	if t.TimeOnPage > 60000 { // More than 1 minute
		totalEvents := len(t.MousePoints) + len(t.Keystrokes) + len(t.ScrollEvents)
		eventsPerMinute := float64(totalEvents) / (float64(t.TimeOnPage) / 60000)

		if eventsPerMinute < 1 {
			// Very little interaction for time spent
			botScore += 15
			score.Flags = append(score.Flags, "low_interaction_rate")
		}
	}

	// Check 4: Interaction start time
	if t.InteractionStart > 0 && t.InteractionStart < 100 {
		// Interaction started within 100ms of page load - suspicious
		botScore += 20
		score.Flags = append(score.Flags, "instant_interaction")
	}

	return math.Min(botScore, 100)
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

func calculateVariance(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := calculateMean(values)
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	return variance / float64(len(values))
}

func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// =============================================================================
// CLIENT-SIDE COLLECTOR SCRIPT
// =============================================================================

// GenerateBiometricCollector generates the client-side JavaScript collector
func GenerateBiometricCollector() string {
	// Generate session ID
	sessionBytes := make([]byte, 16)
	rand.Read(sessionBytes)
	sessionID := hex.EncodeToString(sessionBytes)

	return fmt.Sprintf(`
<script>
(function() {
    'use strict';
    
    const SESSION_ID = '%s';
    let startTime = Date.now();
    let interactionStart = 0;
    
    // Data collectors
    const mousePoints = [];
    const accelReadings = [];
    const keystrokes = [];
    const scrollEvents = [];
    let touchCount = 0;
    let hasAccel = false;
    
    // Mouse tracking
    let lastMouseTime = 0;
    document.addEventListener('mousemove', (e) => {
        const now = Date.now() - startTime;
        if (now - lastMouseTime < 50) return; // Throttle to 20Hz
        lastMouseTime = now;
        
        if (interactionStart === 0) interactionStart = now;
        
        mousePoints.push({
            x: e.clientX,
            y: e.clientY,
            t: now
        });
        
        // Keep last 200 points
        if (mousePoints.length > 200) mousePoints.shift();
    });
    
    // Accelerometer tracking (mobile)
    if (window.DeviceMotionEvent) {
        window.addEventListener('devicemotion', (e) => {
            const acc = e.accelerationIncludingGravity;
            if (!acc) return;
            
            hasAccel = true;
            const now = Date.now() - startTime;
            
            accelReadings.push({
                x: acc.x || 0,
                y: acc.y || 0,
                z: acc.z || 0,
                t: now
            });
            
            if (accelReadings.length > 100) accelReadings.shift();
        });
    }
    
    // Keyboard tracking
    let lastKeyUp = 0;
    document.addEventListener('keydown', (e) => {
        const now = Date.now() - startTime;
        if (interactionStart === 0) interactionStart = now;
        
        keystrokes.push({
            k: e.keyCode,
            d: now,
            u: 0,
            i: now - lastKeyUp
        });
    });
    
    document.addEventListener('keyup', (e) => {
        const now = Date.now() - startTime;
        lastKeyUp = now;
        
        // Find matching keydown
        for (let i = keystrokes.length - 1; i >= 0; i--) {
            if (keystrokes[i].k === e.keyCode && keystrokes[i].u === 0) {
                keystrokes[i].u = now;
                break;
            }
        }
        
        if (keystrokes.length > 100) keystrokes.shift();
    });
    
    // Scroll tracking
    let lastScrollTime = 0;
    document.addEventListener('scroll', () => {
        const now = Date.now() - startTime;
        if (now - lastScrollTime < 100) return;
        lastScrollTime = now;
        
        scrollEvents.push({
            dy: window.scrollY,
            t: now,
            dir: window.scrollY > (scrollEvents[scrollEvents.length - 1]?.dy || 0) ? 1 : -1
        });
        
        if (scrollEvents.length > 50) scrollEvents.shift();
    });
    
    // Touch tracking (mobile)
    document.addEventListener('touchstart', () => {
        touchCount++;
        if (interactionStart === 0) interactionStart = Date.now() - startTime;
    });
    
    // Submit telemetry periodically
    function submitTelemetry() {
        const telemetry = {
            session_id: SESSION_ID,
            mouse_points: mousePoints.slice(-100),
            accel_readings: accelReadings.slice(-50),
            keystrokes: keystrokes.slice(-50),
            scroll_events: scrollEvents.slice(-30),
            touch_count: touchCount,
            has_accel: hasAccel,
            time_on_page: Date.now() - startTime,
            interaction_start: interactionStart,
            claimed_ua: navigator.userAgent,
            screen_width: screen.width,
            screen_height: screen.height
        };
        
        fetch('/sentinel/biometrics', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(telemetry),
            keepalive: true
        }).catch(() => {});
    }
    
    // Submit on page visibility change and periodically
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            submitTelemetry();
        }
    });
    
    // Submit every 30 seconds
    setInterval(submitTelemetry, 30000);
    
    // Submit before unload
    window.addEventListener('beforeunload', () => {
        submitTelemetry();
    });
    
    // Set session cookie
    document.cookie = 'sx_bio_session=' + SESSION_ID + '; path=/; max-age=1800; SameSite=Strict';
})();
</script>
`, sessionID)
}
