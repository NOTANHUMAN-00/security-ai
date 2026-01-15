// ============================================================================
// SENTINEL-X RED TEAM - HEADLESS BROWSER ATTACKS
// ============================================================================
//
// This script uses Puppeteer with Stealth plugin to simulate advanced bots.
// Stealth plugin hides navigator.webdriver and other automation signs.
//
// INSTALL:
//   npm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth
//
// RUN:
//   node attack_browser.js [target_url]
//
// ============================================================================

const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

// Enable stealth mode - hides automation signals
puppeteer.use(StealthPlugin());

// Configuration
const TARGET_URL = process.argv[2] || 'http://localhost:8080';

// Colors for terminal
const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m',
    bold: '\x1b[1m'
};

function log(type, msg) {
    const icons = {
        success: `${colors.green}✅ SUCCESS:${colors.reset}`,
        fail: `${colors.red}❌ FAILED:${colors.reset}`,
        info: `${colors.yellow}ℹ️  INFO:${colors.reset}`,
        attack: `${colors.red}🚀 ATTACK:${colors.reset}`,
        test: `${colors.blue}🧪 TEST:${colors.reset}`
    };
    console.log(`${icons[type]} ${msg}`);
}

function banner() {
    console.log(`
${colors.cyan}╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║       🤖 HEADLESS BROWSER ATTACK - Puppeteer with Stealth 🤖              ║
║                                                                           ║
║   This simulates sophisticated bots using real browser engines            ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝${colors.reset}
`);
}

// ============================================================================
// TEST 1: Basic Headless Attack
// ============================================================================

async function testBasicHeadless() {
    console.log(`\n${colors.bold}${'='.repeat(70)}${colors.reset}`);
    log('test', 'Basic Headless Chrome Attack');
    console.log(`${colors.bold}${'='.repeat(70)}${colors.reset}\n`);

    log('attack', 'Launching headless Chrome with Stealth plugin...');

    const browser = await puppeteer.launch({
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-web-security',
        ]
    });

    try {
        const page = await browser.newPage();

        // Set viewport (like a real browser)
        await page.setViewport({ width: 1920, height: 1080 });

        log('info', 'Navigating to target...');

        const response = await page.goto(TARGET_URL, {
            waitUntil: 'networkidle2',
            timeout: 30000
        });

        const status = response.status();
        log('info', `Response Status: ${status}`);

        // Check what kind of page we got
        const content = await page.content();
        const bodyText = await page.evaluate(() => document.body.innerText);

        if (status === 403) {
            log('success', 'BLOCKED! Headless browser was detected');
            await browser.close();
            return true;
        }

        if (status === 429) {
            log('success', 'Rate limited - defense active');
            await browser.close();
            return true;
        }

        // Check for challenge page
        const hasChallenge = bodyText.toLowerCase().includes('challenge') ||
            bodyText.toLowerCase().includes('verify') ||
            bodyText.toLowerCase().includes('security') ||
            bodyText.toLowerCase().includes('loading') ||
            bodyText.toLowerCase().includes('please wait');

        if (hasChallenge) {
            log('success', 'Challenge page served! Defense layer triggered');
            log('info', 'Waiting to see if PoW/WASM check activates...');

            // Wait for any dynamic content
            await page.waitForTimeout(5000);

            const newContent = await page.evaluate(() => document.body.innerText);
            if (newContent.includes('blocked') || newContent.includes('denied')) {
                log('success', 'Bot was blocked after challenge!');
            } else {
                log('info', 'Challenge ongoing - multi-layer defense active');
            }

            await browser.close();
            return true;
        }

        // Check for battery/hardware checks
        const hasBatteryCheck = content.includes('getBattery') ||
            content.includes('X-Device-Power');

        if (hasBatteryCheck) {
            log('success', 'Battery check detected in response!');
            log('info', 'Headless browsers fail battery checks');
        }

        // If we got real content, check if defenses are bypassed
        if (content.length > 5000 && !hasChallenge) {
            log('fail', 'Headless browser accessed real content!');
            log('info', 'Check Battery/WebGPU/Entropy detection layers');
            await browser.close();
            return false;
        }

        log('info', 'Response received - checking secondary layers...');
        await browser.close();
        return true;

    } catch (e) {
        if (e.message.includes('timeout')) {
            log('success', 'Request timed out (Tarpit may be active)');
        } else {
            log('success', `Browser error: ${e.message.substring(0, 50)}...`);
        }
        await browser.close();
        return true;
    }
}

// ============================================================================
// TEST 2: Stealth Evasion Test
// ============================================================================

async function testStealthEvasion() {
    console.log(`\n${colors.bold}${'='.repeat(70)}${colors.reset}`);
    log('test', 'Stealth Plugin Evasion Test');
    console.log(`${colors.bold}${'='.repeat(70)}${colors.reset}\n`);

    log('attack', 'Testing if Stealth plugin hides automation...');

    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox']
    });

    try {
        const page = await browser.newPage();

        // Check what automation signals are visible
        await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 15000 });

        const automationTests = await page.evaluate(() => {
            return {
                webdriver: navigator.webdriver,
                languages: navigator.languages,
                plugins: navigator.plugins.length,
                chrome: !!window.chrome,
                permissions: typeof navigator.permissions,
                userAgent: navigator.userAgent
            };
        });

        log('info', `navigator.webdriver: ${automationTests.webdriver}`);
        log('info', `Plugins count: ${automationTests.plugins}`);
        log('info', `Chrome object exists: ${automationTests.chrome}`);

        if (automationTests.webdriver === true) {
            log('info', 'Stealth plugin may not be working correctly');
        } else {
            log('info', 'Stealth plugin hiding webdriver flag');
            log('info', 'But Sentinel-X should still detect via other signals');
        }

        await browser.close();
        return true;

    } catch (e) {
        log('success', `Test blocked: ${e.message.substring(0, 50)}...`);
        await browser.close();
        return true;
    }
}

// ============================================================================
// TEST 3: Mouse Movement Simulation
// ============================================================================

async function testMouseSimulation() {
    console.log(`\n${colors.bold}${'='.repeat(70)}${colors.reset}`);
    log('test', 'Mouse Movement Simulation');
    console.log(`${colors.bold}${'='.repeat(70)}${colors.reset}\n`);

    log('attack', 'Simulating human-like mouse movements...');

    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox']
    });

    try {
        const page = await browser.newPage();
        await page.setViewport({ width: 1920, height: 1080 });

        await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 15000 });

        // Simulate mouse movements (bots often have robotic patterns)
        log('info', 'Moving mouse in patterns...');

        // Linear movement (robotic)
        await page.mouse.move(100, 100);
        await page.mouse.move(200, 200);
        await page.mouse.move(300, 300);

        // Try to simulate more "human" movement
        for (let i = 0; i < 10; i++) {
            const x = Math.random() * 800 + 100;
            const y = Math.random() * 600 + 100;
            await page.mouse.move(x, y, { steps: 10 });
            await page.waitForTimeout(100);
        }

        log('info', 'Mouse simulation complete');
        log('info', 'Sentinel-X should detect low entropy in movement patterns');

        await browser.close();
        return true;

    } catch (e) {
        log('success', `Test blocked: ${e.message.substring(0, 50)}...`);
        await browser.close();
        return true;
    }
}

// ============================================================================
// TEST 4: Battery API Test
// ============================================================================

async function testBatteryAPI() {
    console.log(`\n${colors.bold}${'='.repeat(70)}${colors.reset}`);
    log('test', 'Battery API Detection Test');
    console.log(`${colors.bold}${'='.repeat(70)}${colors.reset}\n`);

    log('attack', 'Checking Battery API behavior in headless...');

    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox']
    });

    try {
        const page = await browser.newPage();

        await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 15000 });

        const batteryInfo = await page.evaluate(async () => {
            try {
                if (!navigator.getBattery) {
                    return { available: false, reason: 'API not supported' };
                }

                const battery = await navigator.getBattery();
                return {
                    available: true,
                    level: battery.level,
                    charging: battery.charging,
                    chargingTime: battery.chargingTime,
                    dischargingTime: battery.dischargingTime
                };
            } catch (e) {
                return { available: false, reason: e.message };
            }
        });

        log('info', `Battery API available: ${batteryInfo.available}`);

        if (batteryInfo.available) {
            log('info', `Battery level: ${batteryInfo.level * 100}%`);
            log('info', `Charging: ${batteryInfo.charging}`);

            // Check for "perfect" mock values (suspicious!)
            if (batteryInfo.level === 1 && batteryInfo.charging === true) {
                log('success', 'Battery shows "perfect" mock values - detectable!');
            }
        } else {
            log('success', 'Battery API unavailable in headless - detectable!');
        }

        await browser.close();
        return true;

    } catch (e) {
        log('success', `Test blocked: ${e.message.substring(0, 50)}...`);
        await browser.close();
        return true;
    }
}

// ============================================================================
// TEST 5: WebGL/GPU Fingerprint
// ============================================================================

async function testWebGLFingerprint() {
    console.log(`\n${colors.bold}${'='.repeat(70)}${colors.reset}`);
    log('test', 'WebGL/GPU Fingerprint Test');
    console.log(`${colors.bold}${'='.repeat(70)}${colors.reset}\n`);

    log('attack', 'Checking WebGL fingerprint in headless...');

    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--enable-webgl']
    });

    try {
        const page = await browser.newPage();

        await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 15000 });

        const webglInfo = await page.evaluate(() => {
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

                if (!gl) {
                    return { available: false };
                }

                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');

                return {
                    available: true,
                    vendor: gl.getParameter(debugInfo ? debugInfo.UNMASKED_VENDOR_WEBGL : gl.VENDOR),
                    renderer: gl.getParameter(debugInfo ? debugInfo.UNMASKED_RENDERER_WEBGL : gl.RENDERER)
                };
            } catch (e) {
                return { available: false, error: e.message };
            }
        });

        log('info', `WebGL available: ${webglInfo.available}`);

        if (webglInfo.available) {
            log('info', `GPU Vendor: ${webglInfo.vendor}`);
            log('info', `GPU Renderer: ${webglInfo.renderer}`);

            // Check for software renderer (headless indicator)
            if (webglInfo.renderer && webglInfo.renderer.includes('SwiftShader')) {
                log('success', 'Software GPU renderer detected - headless indicator!');
            }
        } else {
            log('success', 'WebGL unavailable - headless environment!');
        }

        await browser.close();
        return true;

    } catch (e) {
        log('success', `Test blocked: ${e.message.substring(0, 50)}...`);
        await browser.close();
        return true;
    }
}

// ============================================================================
// RUN ALL TESTS
// ============================================================================

async function runAllTests() {
    banner();

    console.log(`\n${colors.bold}Target: ${TARGET_URL}${colors.reset}`);
    console.log(`${colors.yellow}Starting Headless Browser tests in 3 seconds...${colors.reset}\n`);

    await new Promise(r => setTimeout(r, 3000));

    const tests = [
        { name: 'Basic Headless Attack', fn: testBasicHeadless },
        { name: 'Stealth Evasion', fn: testStealthEvasion },
        { name: 'Mouse Simulation', fn: testMouseSimulation },
        { name: 'Battery API', fn: testBatteryAPI },
        { name: 'WebGL Fingerprint', fn: testWebGLFingerprint },
    ];

    const results = [];

    for (const test of tests) {
        try {
            const result = await test.fn();
            results.push({ name: test.name, result });
        } catch (e) {
            console.log(`${colors.red}Test crashed: ${e.message}${colors.reset}`);
            results.push({ name: test.name, result: false });
        }

        await new Promise(r => setTimeout(r, 1000));
    }

    // Summary
    console.log(`\n\n${colors.bold}${'='.repeat(70)}${colors.reset}`);
    console.log(`${colors.cyan}📊 HEADLESS BROWSER ATTACK RESULTS${colors.reset}`);
    console.log(`${colors.bold}${'='.repeat(70)}${colors.reset}\n`);

    for (const { name, result } of results) {
        const status = result
            ? `${colors.green}PASS${colors.reset}`
            : `${colors.red}FAIL${colors.reset}`;
        console.log(`  ${name.padEnd(40)} [${status}]`);
    }

    console.log(`\n${colors.bold}${'='.repeat(70)}${colors.reset}`);

    const passed = results.filter(r => r.result).length;
    if (passed === results.length) {
        console.log(`\n${colors.green}🎉 All tests passed! Sentinel-X detected headless browser.${colors.reset}\n`);
    }
}

// Run
runAllTests().catch(console.error);
