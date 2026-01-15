// Sentinel-X WASM Loader
// This script loads the WebAssembly module and provides the JavaScript interface

(function() {
    'use strict';

    // Check for WebAssembly support
    if (typeof WebAssembly === 'undefined') {
        console.error('Sentinel-X: WebAssembly is not supported in this browser');
        window.SentinelX = createFallback();
        return;
    }

    // Load the WASM module
    const go = new Go();
    
    async function loadWasm() {
        try {
            const result = await WebAssembly.instantiateStreaming(
                fetch('/static/solver.wasm'),
                go.importObject
            );
            go.run(result.instance);
            console.log('🛡️ Sentinel-X WASM solver loaded successfully');
        } catch (error) {
            console.error('Sentinel-X: Failed to load WASM module:', error);
            window.SentinelX = createFallback();
        }
    }

    // Fallback implementation using pure JavaScript
    function createFallback() {
        console.log('Sentinel-X: Using JavaScript fallback solver');
        
        return {
            solveChallenge: async function(salt, difficulty, progressCallback) {
                const targetSuffix = '0'.repeat(difficulty);
                let nonce = 0;
                const batchSize = 10000;
                
                return new Promise((resolve) => {
                    function processBatch() {
                        for (let i = 0; i < batchSize; i++) {
                            const hash = sha256(salt + nonce);
                            if (hash.endsWith(targetSuffix)) {
                                resolve({
                                    success: true,
                                    nonce: nonce,
                                    hash: hash
                                });
                                return;
                            }
                            nonce++;
                        }
                        
                        if (progressCallback) {
                            progressCallback(nonce);
                        }
                        
                        if (nonce > 100000000) {
                            resolve({ error: 'Exceeded maximum attempts' });
                            return;
                        }
                        
                        requestAnimationFrame(processBatch);
                    }
                    
                    processBatch();
                });
            },
            
            validateHash: function(salt, nonce, difficulty) {
                const targetSuffix = '0'.repeat(difficulty);
                const hash = sha256(salt + nonce);
                return hash.endsWith(targetSuffix);
            },
            
            collectFingerprint: function() {
                const fingerprint = {
                    userAgent: navigator.userAgent,
                    language: navigator.language,
                    platform: navigator.platform,
                    screenWidth: screen.width,
                    screenHeight: screen.height,
                    colorDepth: screen.colorDepth,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    cookieEnabled: navigator.cookieEnabled,
                    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown'
                };
                
                // Canvas fingerprint
                try {
                    const canvas = document.createElement('canvas');
                    canvas.width = 200;
                    canvas.height = 50;
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(0, 0, 200, 50);
                    ctx.fillStyle = '#069';
                    ctx.fillText('Sentinel-X 🛡️', 2, 15);
                    fingerprint.canvasHash = sha256(canvas.toDataURL()).substring(0, 32);
                } catch (e) {
                    fingerprint.canvasHash = 'unavailable';
                }
                
                fingerprint.hash = sha256(JSON.stringify(fingerprint));
                return fingerprint;
            }
        };
    }

    // Simple SHA-256 implementation for the fallback
    // Using Web Crypto API when available
    async function sha256(message) {
        if (crypto.subtle) {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }
        
        // Fallback to synchronous implementation
        return sha256Sync(message);
    }

    // Synchronous SHA-256 (minimal implementation)
    function sha256Sync(message) {
        // This is a placeholder - in production, use a proper library
        // For the WASM version, this won't be called
        let hash = 0;
        for (let i = 0; i < message.length; i++) {
            const char = message.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16).padStart(64, '0');
    }

    // Load WebAssembly
    loadWasm();
})();
