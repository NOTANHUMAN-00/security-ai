// +build js,wasm

// Package main - WebAssembly Proof of Work Solver
// This Go code compiles to WebAssembly for high-performance PoW solving in the browser
// Compile with: GOOS=js GOARCH=wasm go build -o solver.wasm pkg/wasm/main.go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall/js"
)

// solveChallenge finds a nonce that produces a hash ending in the required zeros
// This function is exposed to JavaScript via WebAssembly
func solveChallenge(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "Expected 2 arguments: salt, difficulty",
		})
	}

	salt := args[0].String()
	difficulty := args[1].Int()

	// Create the target suffix (difficulty zeros)
	targetSuffix := strings.Repeat("0", difficulty)
	
	// Track progress for callbacks
	var progressCallback js.Value
	if len(args) > 2 && args[2].Type() == js.TypeFunction {
		progressCallback = args[2]
	}

	// Brute force search for valid nonce
	nonce := 0
	batchSize := 10000

	for {
		// Process in batches for responsiveness
		for i := 0; i < batchSize; i++ {
			hash := computeHash(salt, nonce)
			
			// Check if hash ends with required zeros
			if strings.HasSuffix(hash, targetSuffix) {
				return js.ValueOf(map[string]interface{}{
					"success": true,
					"nonce":   nonce,
					"hash":    hash,
				})
			}
			nonce++
		}

		// Report progress
		if !progressCallback.IsUndefined() && !progressCallback.IsNull() {
			progressCallback.Invoke(nonce)
		}

		// Safety limit to prevent infinite loops
		if nonce > 100000000 {
			return js.ValueOf(map[string]interface{}{
				"error": "Exceeded maximum attempts",
			})
		}
	}
}

// computeHash calculates SHA256(salt + nonce)
func computeHash(salt string, nonce int) string {
	data := fmt.Sprintf("%s%d", salt, nonce)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// validateHash verifies a nonce produces a valid hash
func validateHash(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf(false)
	}

	salt := args[0].String()
	nonce := args[1].Int()
	difficulty := args[2].Int()

	targetSuffix := strings.Repeat("0", difficulty)
	hash := computeHash(salt, nonce)

	return js.ValueOf(strings.HasSuffix(hash, targetSuffix))
}

// benchmarkHashRate estimates the hash rate on this machine
func benchmarkHashRate(this js.Value, args []js.Value) interface{} {
	salt := "benchmark_salt_1234567890"
	iterations := 100000
	
	// Note: We can't use time package directly in WASM the same way
	// Instead, we just return the iteration count and let JS measure time
	for i := 0; i < iterations; i++ {
		computeHash(salt, i)
	}

	return js.ValueOf(iterations)
}

// collectFingerprint gathers browser fingerprint data
func collectFingerprint(this js.Value, args []js.Value) interface{} {
	document := js.Global().Get("document")
	navigator := js.Global().Get("navigator")
	screen := js.Global().Get("screen")
	
	fingerprint := make(map[string]interface{})
	
	// Navigator properties
	fingerprint["userAgent"] = navigator.Get("userAgent").String()
	fingerprint["language"] = navigator.Get("language").String()
	fingerprint["platform"] = navigator.Get("platform").String()
	fingerprint["hardwareConcurrency"] = navigator.Get("hardwareConcurrency").Int()
	fingerprint["deviceMemory"] = navigator.Get("deviceMemory").Float()
	fingerprint["cookieEnabled"] = navigator.Get("cookieEnabled").Bool()
	fingerprint["doNotTrack"] = navigator.Get("doNotTrack").String()
	
	// Screen properties
	fingerprint["screenWidth"] = screen.Get("width").Int()
	fingerprint["screenHeight"] = screen.Get("height").Int()
	fingerprint["colorDepth"] = screen.Get("colorDepth").Int()
	fingerprint["pixelRatio"] = js.Global().Get("devicePixelRatio").Float()
	
	// Timezone
	fingerprint["timezone"] = js.Global().Get("Intl").
		Get("DateTimeFormat").
		New().
		Call("resolvedOptions").
		Get("timeZone").String()
	
	// Canvas fingerprint
	canvas := document.Call("createElement", "canvas")
	canvas.Set("width", 200)
	canvas.Set("height", 50)
	ctx := canvas.Call("getContext", "2d")
	
	// Draw some text and shapes
	ctx.Set("textBaseline", "top")
	ctx.Set("font", "14px Arial")
	ctx.Set("fillStyle", "#f60")
	ctx.Call("fillRect", 0, 0, 200, 50)
	ctx.Set("fillStyle", "#069")
	ctx.Call("fillText", "Sentinel-X 🛡️", 2, 15)
	ctx.Set("fillStyle", "rgba(102, 204, 0, 0.7)")
	ctx.Call("fillText", "Canvas FP", 4, 17)
	
	// Get canvas data URL and hash it
	canvasData := canvas.Call("toDataURL").String()
	canvasHash := sha256.Sum256([]byte(canvasData))
	fingerprint["canvasHash"] = hex.EncodeToString(canvasHash[:16])
	
	// WebGL fingerprint
	gl := canvas.Call("getContext", "webgl")
	if !gl.IsNull() && !gl.IsUndefined() {
		debugInfo := gl.Call("getExtension", "WEBGL_debug_renderer_info")
		if !debugInfo.IsNull() && !debugInfo.IsUndefined() {
			vendor := gl.Call("getParameter", debugInfo.Get("UNMASKED_VENDOR_WEBGL")).String()
			renderer := gl.Call("getParameter", debugInfo.Get("UNMASKED_RENDERER_WEBGL")).String()
			fingerprint["webglVendor"] = vendor
			fingerprint["webglRenderer"] = renderer
		}
	}
	
	// Audio fingerprint (simplified)
	if audioContext := js.Global().Get("AudioContext"); !audioContext.IsUndefined() {
		fingerprint["audioContextSupported"] = true
	} else {
		fingerprint["audioContextSupported"] = false
	}
	
	// Compute overall fingerprint hash
	fpData := fmt.Sprintf("%v", fingerprint)
	fpHash := sha256.Sum256([]byte(fpData))
	fingerprint["hash"] = hex.EncodeToString(fpHash[:])
	
	return js.ValueOf(fingerprint)
}

func main() {
	// Expose functions to JavaScript
	js.Global().Set("SentinelX", js.ValueOf(map[string]interface{}{
		"solveChallenge":     js.FuncOf(solveChallenge),
		"validateHash":       js.FuncOf(validateHash),
		"benchmarkHashRate":  js.FuncOf(benchmarkHashRate),
		"collectFingerprint": js.FuncOf(collectFingerprint),
	}))

	// Log that WASM is loaded
	js.Global().Get("console").Call("log", "🛡️ Sentinel-X WASM module loaded")

	// Keep the WASM running
	select {}
}
