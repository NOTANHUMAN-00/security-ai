// Package middleware - Hardware-Bound Proof of Space (WebGPU Challenge)
// =============================================================================
// HARDWARE DIFFERENTIATION: Separate real devices from cloud bot servers
//
// Problem: CPU hashing (SHA256, Argon2) can be solved by bots on cloud servers
//          AWS/DigitalOcean servers have powerful CPUs but NO GPUs
//
// Solution: Force WebGPU compute shaders that REQUIRE a GPU
//           - Real users: iPhones, laptops, desktops → have GPUs ✓
//           - Bots: Headless Linux servers → NO GPU ✗
//
// Implementation:
// 1. WebGPU Compute Shader: Matrix multiplication or scene rendering
// 2. Fallback: WebGL if WebGPU not available
// 3. Memory-bound challenge: Allocate GPU memory buffers
// 4. Timing validation: GPU ops have characteristic timing signatures
//
// Result: A Python script on AWS returns "WebGPU not supported" → BLOCKED
// =============================================================================
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"sentinel-x/internal/config"
	"sentinel-x/internal/storage"
)

// =============================================================================
// PROOF OF SPACE CONFIGURATION
// =============================================================================

// ProofOfSpaceChallenge represents a hardware-bound challenge
type ProofOfSpaceChallenge struct {
	ChallengeID    string `json:"challenge_id"`
	Salt           string `json:"salt"`
	MatrixSize     int    `json:"matrix_size"`     // Size of matrix for GPU computation
	MemoryRequired int    `json:"memory_required"` // Bytes of GPU memory needed
	Iterations     int    `json:"iterations"`      // Number of compute passes
	ExpectedHash   string `json:"expected_hash"`   // Hash of expected result
	ExpiresAt      int64  `json:"expires_at"`
	Signature      string `json:"signature"`
}

// ProofOfSpaceStats tracks hardware challenge stats
type ProofOfSpaceStats struct {
	TotalChallenges  uint64
	WebGPUSupported  uint64
	WebGLFallback    uint64
	NoGPUDetected    uint64
	ValidationPassed uint64
	ValidationFailed uint64
}

var globalPoSStats = &ProofOfSpaceStats{}

// GetProofOfSpaceStats returns current stats
func GetProofOfSpaceStats() ProofOfSpaceStats {
	return ProofOfSpaceStats{
		TotalChallenges:  atomic.LoadUint64(&globalPoSStats.TotalChallenges),
		WebGPUSupported:  atomic.LoadUint64(&globalPoSStats.WebGPUSupported),
		WebGLFallback:    atomic.LoadUint64(&globalPoSStats.WebGLFallback),
		NoGPUDetected:    atomic.LoadUint64(&globalPoSStats.NoGPUDetected),
		ValidationPassed: atomic.LoadUint64(&globalPoSStats.ValidationPassed),
		ValidationFailed: atomic.LoadUint64(&globalPoSStats.ValidationFailed),
	}
}

// =============================================================================
// PROOF OF SPACE MIDDLEWARE
// =============================================================================

// ProofOfSpaceMiddleware implements hardware-bound challenges
type ProofOfSpaceMiddleware struct {
	config     *config.Config
	store      storage.Store
	signingKey []byte
}

// ProofOfSpace creates the hardware-bound challenge middleware
func ProofOfSpace(cfg *config.Config, store storage.Store) Middleware {
	signingKey := make([]byte, 32)
	rand.Read(signingKey)

	pos := &ProofOfSpaceMiddleware{
		config:     cfg,
		store:      store,
		signingKey: signingKey,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for hardware proof solution
			hwProof := r.Header.Get("X-Sentinel-HWProof")
			if hwProof == "" {
				hwProof = r.URL.Query().Get("hw_token")
			}

			if hwProof == "" {
				// Check if this request needs hardware verification
				// Only trigger for high-risk or when other checks are suspicious
				riskScore := 0
				if score, ok := r.Context().Value(RiskScoreKey).(int); ok {
					riskScore = score
				}

				// Only require hardware proof for very suspicious requests
				if riskScore > 70 {
					atomic.AddUint64(&globalPoSStats.TotalChallenges, 1)
					pos.sendHardwareChallenge(w, r)
					return
				}
			} else {
				// Validate hardware proof
				valid, reason := pos.validateHardwareProof(r.Context(), hwProof)
				if !valid {
					log.Printf("[POS] Hardware proof failed from %s: %s", GetTrustedClientIP(r), reason)
					atomic.AddUint64(&globalPoSStats.ValidationFailed, 1)
					pos.sendHardwareChallenge(w, r)
					return
				}
				atomic.AddUint64(&globalPoSStats.ValidationPassed, 1)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// sendHardwareChallenge sends a WebGPU/WebGL challenge
func (pos *ProofOfSpaceMiddleware) sendHardwareChallenge(w http.ResponseWriter, r *http.Request) {
	// Generate challenge
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)

	challengeID := hex.EncodeToString(saltBytes[:8])
	expiresAt := time.Now().Add(60 * time.Second).Unix()

	challenge := ProofOfSpaceChallenge{
		ChallengeID:    challengeID,
		Salt:           salt,
		MatrixSize:     128,           // 128x128 matrix
		MemoryRequired: 128 * 128 * 4, // ~64KB GPU memory
		Iterations:     10,
		ExpiresAt:      expiresAt,
	}

	// Sign the challenge
	challenge.Signature = pos.signChallenge(challenge)

	// Store in redis
	ctx := r.Context()
	key := fmt.Sprintf("pos:challenge:%s", challengeID)
	data, _ := json.Marshal(challenge)
	pos.store.Set(ctx, key, string(data), 60*time.Second)

	// Send challenge page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(pos.generateWebGPUChallengePage(challenge)))
}

// signChallenge creates HMAC signature
func (pos *ProofOfSpaceMiddleware) signChallenge(c ProofOfSpaceChallenge) string {
	data := fmt.Sprintf("%s:%s:%d:%d", c.ChallengeID, c.Salt, c.MatrixSize, c.ExpiresAt)
	mac := hmac.New(sha256.New, pos.signingKey)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// validateHardwareProof validates the hardware proof
func (pos *ProofOfSpaceMiddleware) validateHardwareProof(ctx context.Context, proof string) (bool, string) {
	// Parse proof: challengeID:result:gpuInfo:timing
	parts := strings.Split(proof, ":")
	if len(parts) < 4 {
		return false, "invalid format"
	}

	challengeID := parts[0]
	result := parts[1]
	gpuInfo := parts[2]
	timingStr := parts[3]

	// Look up challenge
	key := fmt.Sprintf("pos:challenge:%s", challengeID)
	data, err := pos.store.Get(ctx, key)
	if err != nil {
		return false, "challenge not found"
	}

	var challenge ProofOfSpaceChallenge
	if err := json.Unmarshal([]byte(data), &challenge); err != nil {
		return false, "invalid challenge"
	}

	// Check expiry
	if time.Now().Unix() > challenge.ExpiresAt {
		return false, "challenge expired"
	}

	// Verify signature
	expectedSig := pos.signChallenge(challenge)
	if challenge.Signature != expectedSig {
		return false, "signature mismatch"
	}

	// Check timing (GPU operations have characteristic timing)
	timing, _ := strconv.ParseInt(timingStr, 10, 64)
	if timing < 50 || timing > 30000 {
		// Too fast = simulated, Too slow = something wrong
		return false, "suspicious timing"
	}

	// Check GPU info for known bot patterns
	lowerGPU := strings.ToLower(gpuInfo)
	if strings.Contains(lowerGPU, "swiftshader") ||
		strings.Contains(lowerGPU, "llvmpipe") ||
		strings.Contains(lowerGPU, "software") ||
		gpuInfo == "none" || gpuInfo == "" {
		atomic.AddUint64(&globalPoSStats.NoGPUDetected, 1)
		return false, "no hardware GPU detected"
	}

	// Verify computation result (simplified check)
	// The result should be a hash that proves the GPU work was done
	expectedPrefix := challenge.Salt[:8]
	if !strings.HasPrefix(result, expectedPrefix) {
		return false, "invalid computation result"
	}

	// Mark challenge as used
	pos.store.Delete(ctx, key)
	usedKey := fmt.Sprintf("pos:used:%s", challengeID)
	pos.store.Set(ctx, usedKey, "1", time.Hour)

	return true, ""
}

// =============================================================================
// WEBGPU CHALLENGE PAGE
// =============================================================================

func (pos *ProofOfSpaceMiddleware) generateWebGPUChallengePage(challenge ProofOfSpaceChallenge) string {
	challengeJSON, _ := json.Marshal(challenge)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hardware Verification</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 50%%, #0f3460 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 3rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            max-width: 500px;
        }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { margin-bottom: 1rem; }
        .status { margin: 1.5rem 0; color: rgba(255,255,255,0.7); }
        .progress {
            width: 100%%;
            height: 6px;
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .progress-bar {
            height: 100%%;
            background: linear-gradient(90deg, #00d2ff, #3a7bd5);
            width: 0%%;
            transition: width 0.3s;
        }
        .gpu-info {
            font-size: 0.8rem;
            color: rgba(255,255,255,0.5);
            margin-top: 1rem;
            padding: 0.5rem;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }
        .error {
            color: #ff6b6b;
            padding: 1rem;
            background: rgba(255,107,107,0.1);
            border-radius: 10px;
            margin-top: 1rem;
            display: none;
        }
        .success {
            color: #4ade80;
            display: none;
        }
        canvas { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🖥️</div>
        <h1>Hardware Verification</h1>
        <p>Verifying your device has real graphics hardware...</p>
        
        <div class="progress">
            <div class="progress-bar" id="progress"></div>
        </div>
        
        <p class="status" id="status">Initializing WebGPU...</p>
        
        <div class="gpu-info" id="gpu-info">Detecting GPU...</div>
        
        <p class="success" id="success">✓ Hardware verified!</p>
        <div class="error" id="error"></div>
    </div>
    
    <canvas id="gpu-canvas" width="256" height="256"></canvas>

    <script>
        const challenge = %s;
        
        async function main() {
            const statusEl = document.getElementById('status');
            const progressEl = document.getElementById('progress');
            const gpuInfoEl = document.getElementById('gpu-info');
            const errorEl = document.getElementById('error');
            const successEl = document.getElementById('success');
            
            let gpuInfo = 'unknown';
            let result = '';
            const startTime = performance.now();
            
            // Try WebGPU first (modern browsers)
            if (navigator.gpu) {
                statusEl.textContent = 'WebGPU detected, initializing...';
                progressEl.style.width = '20%%';
                
                try {
                    const adapter = await navigator.gpu.requestAdapter();
                    if (!adapter) throw new Error('No GPU adapter found');
                    
                    const info = await adapter.requestAdapterInfo();
                    gpuInfo = info.description || info.device || info.vendor || 'WebGPU GPU';
                    gpuInfoEl.textContent = 'GPU: ' + gpuInfo;
                    
                    const device = await adapter.requestDevice();
                    statusEl.textContent = 'Running GPU compute shader...';
                    progressEl.style.width = '40%%';
                    
                    // Create compute shader for matrix multiplication
                    const shaderCode = 
                        '@group(0) @binding(0) var<storage, read> inputA: array<f32>;\\n' +
                        '@group(0) @binding(1) var<storage, read> inputB: array<f32>;\\n' +
                        '@group(0) @binding(2) var<storage, read_write> output: array<f32>;\\n' +
                        '@compute @workgroup_size(8, 8)\\n' +
                        'fn main(@builtin(global_invocation_id) id: vec3<u32>) {\\n' +
                        '    let size = ' + challenge.matrix_size + 'u;\\n' +
                        '    let row = id.x;\\n' +
                        '    let col = id.y;\\n' +
                        '    if (row >= size || col >= size) { return; }\\n' +
                        '    var sum: f32 = 0.0;\\n' +
                        '    for (var k: u32 = 0u; k < size; k = k + 1u) {\\n' +
                        '        sum = sum + inputA[row * size + k] * inputB[k * size + col];\\n' +
                        '    }\\n' +
                        '    output[row * size + col] = sum;\\n' +
                        '}';
                    
                    const shaderModule = device.createShaderModule({ code: shaderCode });
                    
                    // Create buffers
                    const bufferSize = ${challenge.matrix_size * challenge.matrix_size * 4};
                    const inputBufferA = device.createBuffer({
                        size: bufferSize,
                        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST
                    });
                    const inputBufferB = device.createBuffer({
                        size: bufferSize,
                        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST
                    });
                    const outputBuffer = device.createBuffer({
                        size: bufferSize,
                        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC
                    });
                    const stagingBuffer = device.createBuffer({
                        size: bufferSize,
                        usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ
                    });
                    
                    // Fill input with challenge-based data
                    const inputDataA = new Float32Array(${challenge.matrix_size * challenge.matrix_size});
                    const inputDataB = new Float32Array(${challenge.matrix_size * challenge.matrix_size});
                    const saltBytes = challenge.salt.split('').map(c => c.charCodeAt(0));
                    for (let i = 0; i < inputDataA.length; i++) {
                        inputDataA[i] = (saltBytes[i %% saltBytes.length] + i) / 255.0;
                        inputDataB[i] = (saltBytes[(i + 8) %% saltBytes.length] * i) / 255.0;
                    }
                    
                    device.queue.writeBuffer(inputBufferA, 0, inputDataA);
                    device.queue.writeBuffer(inputBufferB, 0, inputDataB);
                    
                    // Create pipeline
                    const pipeline = device.createComputePipeline({
                        layout: 'auto',
                        compute: { module: shaderModule, entryPoint: 'main' }
                    });
                    
                    const bindGroup = device.createBindGroup({
                        layout: pipeline.getBindGroupLayout(0),
                        entries: [
                            { binding: 0, resource: { buffer: inputBufferA } },
                            { binding: 1, resource: { buffer: inputBufferB } },
                            { binding: 2, resource: { buffer: outputBuffer } }
                        ]
                    });
                    
                    // Run compute passes
                    statusEl.textContent = 'Computing matrix multiplication...';
                    for (let iter = 0; iter < ${challenge.iterations}; iter++) {
                        const cmdEncoder = device.createCommandEncoder();
                        const passEncoder = cmdEncoder.beginComputePass();
                        passEncoder.setPipeline(pipeline);
                        passEncoder.setBindGroup(0, bindGroup);
                        passEncoder.dispatchWorkgroups(
                            Math.ceil(${challenge.matrix_size} / 8),
                            Math.ceil(${challenge.matrix_size} / 8)
                        );
                        passEncoder.end();
                        device.queue.submit([cmdEncoder.finish()]);
                        await device.queue.onSubmittedWorkDone();
                        
                        progressEl.style.width = (40 + (iter + 1) * 50 / ${challenge.iterations}) + '%%';
                    }
                    
                    // Read result
                    const cmdEncoder = device.createCommandEncoder();
                    cmdEncoder.copyBufferToBuffer(outputBuffer, 0, stagingBuffer, 0, bufferSize);
                    device.queue.submit([cmdEncoder.finish()]);
                    
                    await stagingBuffer.mapAsync(GPUMapMode.READ);
                    const resultData = new Float32Array(stagingBuffer.getMappedRange().slice(0));
                    stagingBuffer.unmap();
                    
                    // Hash the result
                    const resultSum = resultData.reduce((a, b) => a + b, 0);
                    const hashInput = challenge.salt + ':' + resultSum.toFixed(6);
                    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(hashInput));
                    result = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
                    
                    progressEl.style.width = '100%%';
                    statusEl.textContent = 'Verification complete!';
                    
                } catch (e) {
                    console.error('WebGPU error:', e);
                    // Fall back to WebGL
                    return webglFallback();
                }
                
            } else if (document.createElement('canvas').getContext('webgl2') || 
                       document.createElement('canvas').getContext('webgl')) {
                // WebGL fallback
                return webglFallback();
            } else {
                // No GPU support
                errorEl.style.display = 'block';
                errorEl.textContent = 'Your browser does not support GPU acceleration. Please use a modern browser.';
                gpuInfo = 'none';
                submitResult(challenge.challenge_id, '', gpuInfo, 0);
                return;
            }
            
            const endTime = performance.now();
            const timing = Math.round(endTime - startTime);
            
            successEl.style.display = 'block';
            submitResult(challenge.challenge_id, result, gpuInfo, timing);
        }
        
        async function webglFallback() {
            const statusEl = document.getElementById('status');
            const progressEl = document.getElementById('progress');
            const gpuInfoEl = document.getElementById('gpu-info');
            const successEl = document.getElementById('success');
            
            statusEl.textContent = 'Using WebGL fallback...';
            
            const canvas = document.getElementById('gpu-canvas');
            const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
            
            if (!gl) {
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'WebGL not supported';
                return;
            }
            
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            let gpuInfo = 'WebGL GPU';
            if (debugInfo) {
                gpuInfo = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            }
            gpuInfoEl.textContent = 'GPU: ' + gpuInfo;
            
            const startTime = performance.now();
            
            // Simple WebGL compute (render many triangles)
            const vertexShader = gl.createShader(gl.VERTEX_SHADER);
            gl.shaderSource(vertexShader, 
                'attribute vec2 position;\n' +
                'void main() {\n' +
                '    gl_Position = vec4(position, 0.0, 1.0);\n' +
                '}'
            );
            gl.compileShader(vertexShader);
            
            const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
            gl.shaderSource(fragmentShader, 
                'precision mediump float;\n' +
                'uniform float time;\n' +
                'void main() {\n' +
                '    float r = sin(gl_FragCoord.x * 0.01 + time) * 0.5 + 0.5;\n' +
                '    float g = cos(gl_FragCoord.y * 0.01 + time) * 0.5 + 0.5;\n' +
                '    float b = sin((gl_FragCoord.x + gl_FragCoord.y) * 0.01) * 0.5 + 0.5;\n' +
                '    gl_FragColor = vec4(r, g, b, 1.0);\n' +
                '}'
            );
            gl.compileShader(fragmentShader);
            
            const program = gl.createProgram();
            gl.attachShader(program, vertexShader);
            gl.attachShader(program, fragmentShader);
            gl.linkProgram(program);
            gl.useProgram(program);
            
            // Create geometry
            const vertices = new Float32Array([-1,-1, 1,-1, -1,1, 1,1]);
            const buffer = gl.createBuffer();
            gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
            gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
            
            const posAttrib = gl.getAttribLocation(program, 'position');
            gl.enableVertexAttribArray(posAttrib);
            gl.vertexAttribPointer(posAttrib, 2, gl.FLOAT, false, 0, 0);
            
            const timeUniform = gl.getUniformLocation(program, 'time');
            
            // Render multiple frames
            let pixels = new Uint8Array(256 * 256 * 4);
            for (let i = 0; i < ${challenge.iterations * 10}; i++) {
                gl.uniform1f(timeUniform, i * 0.1);
                gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
                progressEl.style.width = (i / ${challenge.iterations * 10} * 100) + '%%';
                
                if (i === ${challenge.iterations * 10 - 1}) {
                    gl.readPixels(0, 0, 256, 256, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
                }
            }
            
            // Hash the rendered pixels
            const pixelSum = pixels.reduce((a, b) => a + b, 0);
            const hashInput = challenge.salt + ':' + pixelSum;
            const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(hashInput));
            const result = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            
            const endTime = performance.now();
            const timing = Math.round(endTime - startTime);
            
            progressEl.style.width = '100%%';
            successEl.style.display = 'block';
            statusEl.textContent = 'Verification complete!';
            
            submitResult(challenge.challenge_id, result, gpuInfo, timing);
        }
        
        function submitResult(challengeId, result, gpuInfo, timing) {
            const proof = challengeId + ':' + result + ':' + encodeURIComponent(gpuInfo) + ':' + timing;
            
            document.cookie = 'X-Sentinel-HWProof=' + proof + '; path=/; max-age=300; SameSite=Strict';
            
            setTimeout(() => {
                const url = new URL(location.href);
                url.searchParams.set('hw_token', proof);
                location.href = url.toString();
            }, 1000);
        }
        
        main().catch(e => {
            console.error(e);
            document.getElementById('error').style.display = 'block';
            document.getElementById('error').textContent = 'Hardware verification failed: ' + e.message;
        });
    </script>
</body>
</html>`, string(challengeJSON))
}
