// Package middleware - Polymorphic Challenge Generator (The "Chameleon" Defense)
// =============================================================================
// ANTI-BOT EVASION: Randomize EVERYTHING on every request
//
// Bot script writers target specific elements:
//   - "If I see div#captcha, click the button"
//   - "Wait for element.challenge-box to appear"
//   - "Find the variable 'solveChallenge' and call it"
//
// Our Defense: Nothing is static. Everything changes every request:
//   - Random element IDs: #captcha → #x9f2k_a8m3
//   - Random class names: .challenge-box → .r4n_d0m_cl4ss
//   - Random JS variable names: solveChallenge → fn_8x2m_solve
//   - Random DOM structure: div > span > button → section > article > a
//   - Random CSS property names via CSS variables
//   - Random attribute names for data storage
//
// Result: Bot scripts break instantly because their targets keep moving.
// =============================================================================
package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"math/big"
	mrand "math/rand"
	"strings"
	"time"
)

// =============================================================================
// POLYMORPHIC GENERATOR
// =============================================================================

// PolymorphicChallenge holds randomized identifiers for a challenge page
type PolymorphicChallenge struct {
	// HTML Element IDs
	ContainerID    string
	ProgressID     string
	StatusID       string
	ButtonID       string
	FormID         string
	InputID        string
	SpinnerID      string
	TimerID        string
	ErrorID        string
	SuccessID      string

	// CSS Class Names
	ContainerClass   string
	ProgressClass    string
	ButtonClass      string
	SpinnerClass     string
	CardClass        string
	HiddenClass      string
	ActiveClass      string
	LoadingClass     string
	ErrorClass       string
	SuccessClass     string

	// JavaScript Variables/Functions
	MainFunctionName     string
	SolverFunctionName   string
	ValidatorFunctionName string
	HashFunctionName     string
	CallbackFunctionName string
	ConfigVarName        string
	StateVarName         string
	ResultVarName        string
	NonceVarName         string
	SaltVarName          string
	CounterVarName       string
	TimerVarName         string

	// Data Attribute Names
	DataChallengeAttr string
	DataSaltAttr      string
	DataDifficultyAttr string
	DataTimestampAttr string
	DataTokenAttr     string

	// CSS Variable Names
	CSSPrimaryColor   string
	CSSSecondaryColor string
	CSSBackgroundVar  string
	CSSFontVar        string
	CSSAnimationVar   string

	// Random Structural Elements
	WrapperTag      string
	InnerTag        string
	ButtonTag       string
	ContainerTag    string

	// Random Strings for Obfuscation
	Salt1    string
	Salt2    string
	Nonce    string
	Token    string

	// Timestamp
	GeneratedAt int64
}

// NewPolymorphicChallenge generates a completely randomized challenge structure
func NewPolymorphicChallenge() *PolymorphicChallenge {
	pc := &PolymorphicChallenge{
		GeneratedAt: time.Now().UnixNano(),
	}

	// Generate random HTML IDs
	pc.ContainerID = randomID("c")
	pc.ProgressID = randomID("p")
	pc.StatusID = randomID("s")
	pc.ButtonID = randomID("b")
	pc.FormID = randomID("f")
	pc.InputID = randomID("i")
	pc.SpinnerID = randomID("sp")
	pc.TimerID = randomID("t")
	pc.ErrorID = randomID("e")
	pc.SuccessID = randomID("ok")

	// Generate random CSS classes
	pc.ContainerClass = randomClass()
	pc.ProgressClass = randomClass()
	pc.ButtonClass = randomClass()
	pc.SpinnerClass = randomClass()
	pc.CardClass = randomClass()
	pc.HiddenClass = randomClass()
	pc.ActiveClass = randomClass()
	pc.LoadingClass = randomClass()
	pc.ErrorClass = randomClass()
	pc.SuccessClass = randomClass()

	// Generate random JS function/variable names
	pc.MainFunctionName = randomJSName("fn")
	pc.SolverFunctionName = randomJSName("slv")
	pc.ValidatorFunctionName = randomJSName("vld")
	pc.HashFunctionName = randomJSName("hsh")
	pc.CallbackFunctionName = randomJSName("cb")
	pc.ConfigVarName = randomJSName("cfg")
	pc.StateVarName = randomJSName("st")
	pc.ResultVarName = randomJSName("res")
	pc.NonceVarName = randomJSName("nc")
	pc.SaltVarName = randomJSName("slt")
	pc.CounterVarName = randomJSName("cnt")
	pc.TimerVarName = randomJSName("tmr")

	// Generate random data attribute names
	pc.DataChallengeAttr = randomDataAttr()
	pc.DataSaltAttr = randomDataAttr()
	pc.DataDifficultyAttr = randomDataAttr()
	pc.DataTimestampAttr = randomDataAttr()
	pc.DataTokenAttr = randomDataAttr()

	// Generate random CSS variable names
	pc.CSSPrimaryColor = randomCSSVar("primary")
	pc.CSSSecondaryColor = randomCSSVar("secondary")
	pc.CSSBackgroundVar = randomCSSVar("bg")
	pc.CSSFontVar = randomCSSVar("font")
	pc.CSSAnimationVar = randomCSSVar("anim")

	// Randomize DOM structure
	pc.WrapperTag = randomTag([]string{"div", "section", "article", "main", "aside"})
	pc.InnerTag = randomTag([]string{"div", "span", "p", "article", "section"})
	pc.ButtonTag = randomTag([]string{"button", "a", "span"})
	pc.ContainerTag = randomTag([]string{"div", "section", "main", "article"})

	// Generate random salts/tokens
	pc.Salt1 = randomHex(16)
	pc.Salt2 = randomHex(16)
	pc.Nonce = randomHex(8)
	pc.Token = randomBase64(24)

	return pc
}

// =============================================================================
// RANDOM GENERATORS
// =============================================================================

// randomID generates a random HTML ID with prefix
func randomID(prefix string) string {
	bytes := make([]byte, 6)
	rand.Read(bytes)
	// Use only alphanumeric characters
	return fmt.Sprintf("_%s%s", prefix, hex.EncodeToString(bytes)[:8])
}

// randomClass generates a random CSS class name
func randomClass() string {
	// CSS classes can't start with numbers, use underscore or letter prefix
	prefixes := []string{"_", "x", "z", "q", "k", "m", "w"}
	bytes := make([]byte, 4)
	rand.Read(bytes)
	prefix := prefixes[mrand.Intn(len(prefixes))]
	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(bytes))
}

// randomJSName generates a random JavaScript variable/function name
func randomJSName(prefix string) string {
	// JS names must start with letter, underscore, or $
	bytes := make([]byte, 4)
	rand.Read(bytes)
	// Mix of letters and numbers
	suffix := hex.EncodeToString(bytes)
	// Add some underscores for variation
	parts := []string{prefix, suffix[:3], suffix[3:5]}
	return strings.Join(parts, "_")
}

// randomDataAttr generates a random data attribute name
func randomDataAttr() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return fmt.Sprintf("data-%s", hex.EncodeToString(bytes))
}

// randomCSSVar generates a random CSS custom property name
func randomCSSVar(base string) string {
	bytes := make([]byte, 3)
	rand.Read(bytes)
	return fmt.Sprintf("--%s-%s", hex.EncodeToString(bytes), base)
}

// randomTag selects a random HTML tag from the list
func randomTag(tags []string) string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(tags))))
	return tags[n.Int64()]
}

// randomHex generates a random hex string
func randomHex(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// randomBase64 generates a random URL-safe base64 string
func randomBase64(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

// =============================================================================
// POLYMORPHIC HTML GENERATOR
// =============================================================================

// GeneratePolymorphicPoWPage generates a PoW challenge page with randomized structure
func GeneratePolymorphicPoWPage(challenge map[string]interface{}) string {
	pc := NewPolymorphicChallenge()
	
	// Extract challenge data
	salt, _ := challenge["salt"].(string)
	difficulty, _ := challenge["difficulty"].(int)
	timestamp, _ := challenge["timestamp"].(int64)
	signature, _ := challenge["signature"].(string)
	_, _ = challenge["risk_level"].(string)  // riskLevel - used for future badge
	expiresAt, _ := challenge["expires_at"].(int64)

	// Generate randomized HTML with all identifiers replaced
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <style>
        :root {
            %s: #667eea;
            %s: #764ba2;
            %s: linear-gradient(135deg, #0a0a0a 0%%, #1a1a2e 50%%, #16213e 100%%);
            %s: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            %s: spin 1s linear infinite;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(%s);
            background: var(%s);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .%s {
            text-align: center;
            padding: 3rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            max-width: 500px;
        }
        .%s {
            font-size: 4rem;
            margin-bottom: 1.5rem;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%%, 100%% { transform: scale(1); opacity: 1; }
            50%% { transform: scale(1.1); opacity: 0.8; }
        }
        .%s {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            overflow: hidden;
            margin: 1.5rem 0;
            height: 8px;
        }
        .%s > %s {
            height: 100%%;
            background: linear-gradient(90deg, var(%s), var(%s));
            width: 0%%;
            transition: width 0.3s ease;
            border-radius: 10px;
        }
        .%s { font-size: 0.9rem; color: rgba(255, 255, 255, 0.5); }
        .%s {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(255,255,255,0.1);
            border-top-color: var(%s);
            border-radius: 50%%;
            animation: var(%s);
            margin: 1rem auto;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .%s { display: none; color: #ff6b6b; }
        .%s { display: none; color: #4ade80; }
        .%s {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1.5rem;
        }
        .%s > %s { text-align: center; }
    </style>
</head>
<body>
    <%s class="%s" id="%s" %s="%s" %s="%d" %s="%d" %s="%s">
        <%s class="%s">🛡️</%s>
        <h1 style="font-size: 1.75rem; margin-bottom: 1rem;">Security Verification</h1>
        <p style="color: rgba(255,255,255,0.7); margin-bottom: 2rem;">
            Verifying you're human. This takes a moment.
        </p>
        
        <%s class="%s" id="%s">
            <%s id="%s"></%s>
        </%s>
        
        <p class="%s" id="%s">Initializing...</p>
        
        <%s class="%s" id="%s"></%s>
        
        <p class="%s" id="%s"></p>
        <p class="%s" id="%s">✓ Verified! Redirecting...</p>
        
        <%s class="%s">
            <%s>
                <strong id="%s">0</strong>
                <small style="display:block;color:rgba(255,255,255,0.5);">Attempts</small>
            </%s>
            <%s>
                <strong id="%s">0s</strong>
                <small style="display:block;color:rgba(255,255,255,0.5);">Time</small>
            </%s>
        </%s>
    </%s>

    <script>
        // Polymorphic JavaScript - all names randomized
        (function() {
            'use strict';
            
            // Configuration with randomized variable names
            const %s = {
                %s: '%s',
                %s: %d,
                %s: %d,
                %s: '%s'
            };
            
            // State variables with randomized names
            let %s = 0;
            let %s = null;
            let %s = Date.now();
            let %s = false;
            
            // DOM references with randomized selectors
            const %s = {
                container: document.getElementById('%s'),
                progress: document.getElementById('%s'),
                status: document.getElementById('%s'),
                spinner: document.getElementById('%s'),
                error: document.getElementById('%s'),
                success: document.getElementById('%s'),
                attempts: document.querySelector('#%s strong'),
                timer: document.querySelector('#%s strong')
            };
            
            // Hash function with randomized name
            async function %s(%s) {
                const %s = new TextEncoder().encode(%s);
                const %s = await crypto.subtle.digest('SHA-256', %s);
                return Array.from(new Uint8Array(%s))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            }
            
            // Solver function with randomized name
            async function %s() {
                const %s = '0'.repeat(%s.%s);
                
                while (!%s) {
                    const %s = %s.%s + %s;
                    const %s = await %s(%s);
                    
                    if (%s.endsWith(%s)) {
                        return %s.toString();
                    }
                    
                    %s++;
                    
                    if (%s %% 1000 === 0) {
                        // Update UI
                        %s.progress.style.width = Math.min(%s / 100000 * 100, 95) + '%%';
                        %s.attempts.textContent = %s.toLocaleString();
                        %s.timer.textContent = ((Date.now() - %s) / 1000).toFixed(1) + 's';
                        %s.status.textContent = 'Computing (' + %s.toLocaleString() + ' attempts)...';
                        
                        await new Promise(r => setTimeout(r, 0));
                    }
                    
                    if (%s > 50000000) {
                        throw new Error('Max attempts exceeded');
                    }
                }
                return null;
            }
            
            // Callback function with randomized name
            function %s(%s) {
                const %s = %s.%s + ':' + %s;
                
                document.cookie = 'X-Sentinel-PoW=' + %s + '; path=/; max-age=300; SameSite=Strict';
                
                %s.progress.style.width = '100%%';
                %s.spinner.style.display = 'none';
                %s.success.style.display = 'block';
                %s.status.textContent = 'Verified!';
                
                setTimeout(() => {
                    const url = new URL(location.href);
                    url.searchParams.set('pow_token', %s);
                    location.href = url.toString();
                }, 500);
            }
            
            // Main function with randomized name
            async function %s() {
                try {
                    %s.status.textContent = 'Starting verification...';
                    
                    const %s = await %s();
                    
                    if (%s) {
                        %s(%s);
                    }
                } catch (e) {
                    %s.error.textContent = 'Error: ' + e.message;
                    %s.error.style.display = 'block';
                    %s.spinner.style.display = 'none';
                }
            }
            
            // Start with randomized entry point
            %s();
        })();
    </script>
</body>
</html>`,
		// CSS Variables
		pc.CSSPrimaryColor, pc.CSSSecondaryColor, pc.CSSBackgroundVar, pc.CSSFontVar, pc.CSSAnimationVar,
		pc.CSSFontVar, pc.CSSBackgroundVar,
		// CSS Classes
		pc.ContainerClass, pc.CardClass, pc.ProgressClass, pc.ProgressClass, pc.InnerTag,
		pc.CSSPrimaryColor, pc.CSSSecondaryColor,
		pc.LoadingClass, pc.SpinnerClass, pc.CSSPrimaryColor, pc.CSSAnimationVar,
		pc.ErrorClass, pc.SuccessClass, pc.ActiveClass, pc.ActiveClass, pc.InnerTag,
		// HTML Structure
		pc.ContainerTag, pc.ContainerClass, pc.ContainerID,
		pc.DataSaltAttr, salt, pc.DataDifficultyAttr, difficulty, pc.DataTimestampAttr, timestamp, pc.DataTokenAttr, signature,
		// Icon wrapper
		pc.WrapperTag, pc.CardClass, pc.WrapperTag,
		// Progress bar
		pc.WrapperTag, pc.ProgressClass, pc.ProgressID, pc.InnerTag, pc.StatusID, pc.InnerTag, pc.WrapperTag,
		// Status
		pc.LoadingClass, pc.TimerID,
		// Spinner
		pc.InnerTag, pc.SpinnerClass, pc.SpinnerID, pc.InnerTag,
		// Error/Success
		pc.ErrorClass, pc.ErrorID, pc.SuccessClass, pc.SuccessID,
		// Stats
		pc.WrapperTag, pc.ActiveClass, pc.InnerTag, pc.ButtonID, pc.InnerTag, pc.InnerTag, pc.FormID, pc.InnerTag, pc.WrapperTag,
		pc.ContainerTag,
		// JavaScript config
		pc.ConfigVarName,
		pc.SaltVarName, salt,
		pc.NonceVarName, difficulty,
		pc.TimerVarName, expiresAt,
		pc.ResultVarName, signature,
		// State variables
		pc.CounterVarName, pc.StateVarName, pc.TimerVarName+"_start", pc.NonceVarName+"_done",
		// DOM refs
		pc.StateVarName+"_dom",
		pc.ContainerID, pc.StatusID, pc.TimerID, pc.SpinnerID, pc.ErrorID, pc.SuccessID,
		pc.ButtonID, pc.FormID,
		// Hash function
		pc.HashFunctionName, pc.SaltVarName+"_in",
		pc.ResultVarName+"_enc", pc.SaltVarName+"_in",
		pc.ResultVarName+"_buf", pc.ResultVarName+"_enc",
		pc.ResultVarName+"_buf",
		// Solver function
		pc.SolverFunctionName,
		pc.ResultVarName+"_target", pc.ConfigVarName, pc.NonceVarName,
		pc.NonceVarName+"_done",
		pc.ResultVarName+"_data", pc.ConfigVarName, pc.SaltVarName, pc.CounterVarName,
		pc.ResultVarName+"_hash", pc.HashFunctionName, pc.ResultVarName+"_data",
		pc.ResultVarName+"_hash", pc.ResultVarName+"_target",
		pc.CounterVarName,
		pc.CounterVarName,
		pc.CounterVarName,
		// UI updates
		pc.StateVarName+"_dom", pc.CounterVarName,
		pc.StateVarName+"_dom", pc.CounterVarName,
		pc.StateVarName+"_dom", pc.TimerVarName+"_start",
		pc.StateVarName+"_dom", pc.CounterVarName,
		// Max check
		pc.CounterVarName,
		// Callback
		pc.CallbackFunctionName, pc.ResultVarName+"_nonce",
		pc.ResultVarName+"_token", pc.ConfigVarName, pc.SaltVarName, pc.ResultVarName+"_nonce",
		pc.ResultVarName+"_token",
		pc.StateVarName+"_dom", pc.StateVarName+"_dom", pc.StateVarName+"_dom", pc.StateVarName+"_dom",
		pc.ResultVarName+"_token",
		// Main function
		pc.MainFunctionName,
		pc.StateVarName+"_dom",
		pc.ResultVarName+"_solution", pc.SolverFunctionName,
		pc.ResultVarName+"_solution",
		pc.CallbackFunctionName, pc.ResultVarName+"_solution",
		pc.StateVarName+"_dom", pc.StateVarName+"_dom", pc.StateVarName+"_dom",
		// Entry point
		pc.MainFunctionName,
	)
}


// =============================================================================
// POLYMORPHIC HONEYPOT FIELD GENERATOR
// =============================================================================

// GeneratePolymorphicHoneypotFields generates randomized honeypot form fields
func GeneratePolymorphicHoneypotFields() template.HTML {
	pc := NewPolymorphicChallenge()

	// Multiple honeypot strategies with randomized names
	fields := []string{
		// Hidden field with random name
		fmt.Sprintf(`<input type="text" name="%s" value="" style="display:none !important" tabindex="-1" autocomplete="off">`,
			randomID("hp")),
		// Field hidden via CSS class
		fmt.Sprintf(`<input type="email" name="%s" class="%s" placeholder="Email" autocomplete="off">
			<style>.%s{position:absolute;left:-9999px;}</style>`,
			randomID("email"), pc.HiddenClass, pc.HiddenClass),
		// Field with aria-hidden
		fmt.Sprintf(`<div aria-hidden="true" style="height:0;overflow:hidden;"><input name="%s" tabindex="-1"></div>`,
			randomID("field")),
		// Checkbox honeypot
		fmt.Sprintf(`<label style="display:none"><input type="checkbox" name="%s" value="1">I am human</label>`,
			randomID("human")),
	}

	// Randomly select 1-2 honeypot methods
	mrand.Shuffle(len(fields), func(i, j int) { fields[i], fields[j] = fields[j], fields[i] })
	numFields := 1 + mrand.Intn(2)

	return template.HTML(strings.Join(fields[:numFields], "\n"))
}

// =============================================================================
// OBFUSCATED SCRIPT GENERATOR
// =============================================================================

// GenerateObfuscatedWASMLoader generates a randomized WASM loader script
func GenerateObfuscatedWASMLoader(wasmPath string) string {
	pc := NewPolymorphicChallenge()

	// Randomize everything in the WASM loader
	return fmt.Sprintf(`
(function() {
    'use strict';
    
    // Obfuscated loader with randomized names
    const %s = '%s';
    let %s = null;
    let %s = {};
    
    const %s = async () => {
        try {
            const %s = await fetch(%s);
            const %s = await %s.arrayBuffer();
            const %s = await WebAssembly.instantiate(%s, %s);
            %s = %s.instance;
            
            if (%s.exports && %s.exports.%s) {
                return true;
            }
            return false;
        } catch (%s) {
            console.error('Module load failed');
            return false;
        }
    };
    
    const %s = (...%s) => {
        if (!%s || !%s.exports) return null;
        return %s.exports.%s(...%s);
    };
    
    // Export with randomized global name
    window['%s'] = {
        %s: %s,
        %s: %s
    };
})();
`,
		// Variable names
		pc.ConfigVarName, wasmPath,
		pc.StateVarName,
		pc.ResultVarName,
		// Loader function
		pc.SolverFunctionName,
		pc.NonceVarName, pc.ConfigVarName,
		pc.SaltVarName, pc.NonceVarName,
		pc.TimerVarName, pc.SaltVarName, pc.ResultVarName,
		pc.StateVarName, pc.TimerVarName,
		pc.StateVarName, pc.StateVarName, pc.HashFunctionName,
		pc.CounterVarName,
		// Invoke function
		pc.ValidatorFunctionName, pc.CallbackFunctionName,
		pc.StateVarName, pc.StateVarName,
		pc.StateVarName, pc.HashFunctionName, pc.CallbackFunctionName,
		// Global export
		randomID("sx"),
		pc.SolverFunctionName, pc.SolverFunctionName,
		pc.ValidatorFunctionName, pc.ValidatorFunctionName,
	)
}

// =============================================================================
// RANDOM ELEMENT STRUCTURE GENERATOR
// =============================================================================

// RandomDOMStructure generates a random nested DOM structure
type RandomDOMStructure struct {
	OpenTag  string
	CloseTag string
	ID       string
	Class    string
}

// GenerateRandomStructure creates a randomized DOM wrapper
func GenerateRandomStructure(depth int) []RandomDOMStructure {
	structures := make([]RandomDOMStructure, depth)
	tags := []string{"div", "section", "article", "aside", "main", "span", "nav", "header", "footer"}

	for i := 0; i < depth; i++ {
		tag := tags[mrand.Intn(len(tags))]
		id := randomID("w")
		class := randomClass()
		
		structures[i] = RandomDOMStructure{
			OpenTag:  fmt.Sprintf(`<%s id="%s" class="%s">`, tag, id, class),
			CloseTag: fmt.Sprintf(`</%s>`, tag),
			ID:       id,
			Class:    class,
		}
	}

	return structures
}

// WrapWithRandomStructure wraps content in random DOM elements
func WrapWithRandomStructure(content string, depth int) string {
	structures := GenerateRandomStructure(depth)
	
	var builder strings.Builder
	
	// Opening tags
	for _, s := range structures {
		builder.WriteString(s.OpenTag)
		builder.WriteString("\n")
	}
	
	builder.WriteString(content)
	
	// Closing tags (reverse order)
	for i := len(structures) - 1; i >= 0; i-- {
		builder.WriteString("\n")
		builder.WriteString(structures[i].CloseTag)
	}
	
	return builder.String()
}

// =============================================================================
// CSS OBFUSCATION
// =============================================================================

// GenerateObfuscatedCSS generates CSS with randomized class names
func GenerateObfuscatedCSS(pc *PolymorphicChallenge) string {
	return fmt.Sprintf(`
        .%s { display: flex; align-items: center; justify-content: center; }
        .%s { background: rgba(255,255,255,0.05); padding: 2rem; border-radius: 16px; }
        .%s { width: 100%%; height: 6px; background: #333; border-radius: 3px; }
        .%s { animation: spin 1s linear infinite; }
        .%s { display: none !important; visibility: hidden; position: absolute; left: -9999px; }
        .%s { opacity: 1; transition: opacity 0.3s; }
        .%s { opacity: 0.5; pointer-events: none; }
        .%s { color: #ff6b6b; }
        .%s { color: #4ade80; }
    `,
		pc.ContainerClass,
		pc.CardClass,
		pc.ProgressClass,
		pc.SpinnerClass,
		pc.HiddenClass,
		pc.ActiveClass,
		pc.LoadingClass,
		pc.ErrorClass,
		pc.SuccessClass,
	)
}

// =============================================================================
// ANTI-DEBUGGING MEASURES
// =============================================================================

// GenerateAntiDebuggingCode generates randomized anti-debugging JavaScript
func GenerateAntiDebuggingCode() string {
	pc := NewPolymorphicChallenge()

	return fmt.Sprintf(`
(function() {
    const %s = () => {
        const %s = /./;
        %s.toString = function() {
            %s = true;
        };
        console.log(%s);
    };
    
    const %s = () => {
        const %s = new Date();
        debugger;
        const %s = new Date();
        if (%s - %s > 100) {
            %s = true;
        }
    };
    
    let %s = false;
    
    setInterval(() => {
        if (%s) {
            document.body.innerHTML = '';
            window.location.href = 'about:blank';
        }
    }, 1000);
})();
`,
		pc.SolverFunctionName,
		pc.ConfigVarName,
		pc.ConfigVarName,
		pc.StateVarName,
		pc.ConfigVarName,
		pc.ValidatorFunctionName,
		pc.NonceVarName,
		pc.SaltVarName,
		pc.SaltVarName, pc.NonceVarName,
		pc.StateVarName,
		pc.StateVarName,
		pc.StateVarName,
	)
}
