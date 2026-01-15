// Package challenges - Proof of Work utilities
// Additional PoW-related functions and types
package challenges

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// PoWResult represents the result of a PoW verification
type PoWResult struct {
	Valid     bool
	Nonce     int64
	HashRate  float64
	TimeTaken time.Duration
}

// PoWGenerator generates PoW challenges
type PoWGenerator struct {
	Difficulty  int
	SaltLength  int
	ValidPrefix string // Required prefix of zeros
}

// NewPoWGenerator creates a new PoW generator
func NewPoWGenerator(difficulty int) *PoWGenerator {
	return &PoWGenerator{
		Difficulty:  difficulty,
		SaltLength:  32,
		ValidPrefix: strings.Repeat("0", difficulty),
	}
}

// Verify checks if a nonce produces a valid hash for the given salt
func (p *PoWGenerator) Verify(salt string, nonce int64) bool {
	hash := p.computeHash(salt, nonce)
	// Check if hash ends with required zeros (as specified in requirements)
	return strings.HasSuffix(hash, p.ValidPrefix)
}

// VerifyWithPrefix checks if the hash has the required leading zeros
func (p *PoWGenerator) VerifyWithPrefix(salt string, nonce int64) bool {
	hash := p.computeHash(salt, nonce)
	return strings.HasPrefix(hash, p.ValidPrefix)
}

// FindNonce finds a valid nonce for the given salt (for testing)
func (p *PoWGenerator) FindNonce(salt string) PoWResult {
	start := time.Now()
	var nonce int64 = 0
	
	for {
		if p.Verify(salt, nonce) {
			duration := time.Since(start)
			hashRate := float64(nonce) / duration.Seconds()
			
			return PoWResult{
				Valid:     true,
				Nonce:     nonce,
				HashRate:  hashRate,
				TimeTaken: duration,
			}
		}
		nonce++
		
		// Safety limit
		if nonce > 100000000 {
			return PoWResult{Valid: false}
		}
	}
}

// computeHash computes SHA256(salt + nonce)
func (p *PoWGenerator) computeHash(salt string, nonce int64) string {
	data := fmt.Sprintf("%s%d", salt, nonce)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// DifficultyEstimate estimates the number of hashes needed for a given difficulty
func DifficultyEstimate(difficulty int) int64 {
	// Each hex character has 16 possible values
	// For difficulty N, we need N zeros, which is 1 in 16^N chance
	estimate := int64(1)
	for i := 0; i < difficulty; i++ {
		estimate *= 16
	}
	return estimate
}

// EstimatedTime estimates time to solve at given hash rate
func EstimatedTime(difficulty int, hashRatePerSecond float64) time.Duration {
	hashes := float64(DifficultyEstimate(difficulty))
	seconds := hashes / hashRatePerSecond
	return time.Duration(seconds * float64(time.Second))
}

// AdjustDifficulty suggests a difficulty level based on target solve time
func AdjustDifficulty(targetDuration time.Duration, hashRatePerSecond float64) int {
	targetSeconds := targetDuration.Seconds()
	targetHashes := targetSeconds * hashRatePerSecond
	
	// Find difficulty where estimate is close to target
	for d := 1; d <= 8; d++ {
		if float64(DifficultyEstimate(d)) >= targetHashes {
			return d
		}
	}
	return 8
}
