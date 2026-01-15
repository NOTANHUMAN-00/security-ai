// ============================================================================
// SENTINEL-X RED TEAM - K6 LOAD/STRESS TESTING
// ============================================================================
//
// This script uses k6 to stress test Sentinel-X under heavy load.
// We want to verify the WAF doesn't crash under attack.
//
// INSTALL:
//   Windows: choco install k6
//   Mac: brew install k6
//   Linux: https://k6.io/docs/get-started/installation/
//
// RUN:
//   k6 run stress_test.js
//   k6 run --vus 100 --duration 30s stress_test.js
//
// ============================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const blockedRequests = new Counter('blocked_requests');
const challengedRequests = new Counter('challenged_requests');
const successRate = new Rate('success_rate');
const responseTime = new Trend('response_time');

// Configuration
export const options = {
    // Scenario 1: Gradual ramp-up
    scenarios: {
        // Warm-up phase
        warmup: {
            executor: 'constant-vus',
            vus: 10,
            duration: '10s',
            startTime: '0s',
        },
        // Main attack
        attack: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '10s', target: 50 },   // Ramp to 50 users
                { duration: '20s', target: 100 },  // Ramp to 100 users
                { duration: '30s', target: 100 },  // Sustain 100 users
                { duration: '10s', target: 200 },  // Spike to 200
                { duration: '10s', target: 0 },    // Ramp down
            ],
            startTime: '10s',
        },
    },
    thresholds: {
        // Server should never crash (no 500 errors)
        'http_req_failed{error_type:5xx}': ['rate<0.01'],
        // 95% of requests should be under 2 seconds
        'http_req_duration': ['p(95)<2000'],
        // Server should respond (even if blocking)
        'http_reqs': ['count>100'],
    },
};

// Target URL
const TARGET = __ENV.TARGET_URL || 'http://localhost:8080';

// ============================================================================
// ATTACK FUNCTIONS
// ============================================================================

// Standard attack - no spoofing
function standardAttack() {
    const res = http.get(TARGET);
    return res;
}

// Spoofed User-Agent attack
function spoofedAttack() {
    const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
    };

    const res = http.get(TARGET, { headers });
    return res;
}

// API endpoint attack
function apiAttack() {
    const headers = {
        'Content-Type': 'application/json',
    };

    const payload = JSON.stringify({
        action: 'test',
        data: 'attack_payload_' + Math.random(),
    });

    const res = http.post(`${TARGET}/api/test`, payload, { headers });
    return res;
}

// Honeypot probe
function honeypotProbe() {
    const paths = ['/wp-admin', '/.env', '/phpmyadmin'];
    const path = paths[Math.floor(Math.random() * paths.length)];

    const res = http.get(`${TARGET}${path}`);
    return res;
}

// Random path attack
function randomPathAttack() {
    const randomPath = '/path' + Math.floor(Math.random() * 10000);
    const res = http.get(`${TARGET}${randomPath}`);
    return res;
}

// ============================================================================
// MAIN TEST FUNCTION
// ============================================================================

export default function () {
    // Randomly select attack type
    const attackType = Math.floor(Math.random() * 5);
    let res;

    switch (attackType) {
        case 0:
            res = standardAttack();
            break;
        case 1:
            res = spoofedAttack();
            break;
        case 2:
            res = apiAttack();
            break;
        case 3:
            res = honeypotProbe();
            break;
        default:
            res = randomPathAttack();
    }

    // Record response time
    responseTime.add(res.timings.duration);

    // Analyze response
    const status = res.status;
    const body = res.body || '';

    // Check results
    const checks = check(res, {
        // Server didn't crash
        'server_not_crashed': (r) => r.status !== 500 && r.status !== 502 && r.status !== 503,

        // Response was received (any status)
        'response_received': (r) => r.status > 0,

        // Latency acceptable (even under load)
        'latency_acceptable': (r) => r.timings.duration < 5000,
    });

    // Track blocked vs allowed
    if (status === 403 || status === 429) {
        blockedRequests.add(1);
    } else if (body.toLowerCase().includes('challenge') || body.toLowerCase().includes('verify')) {
        challengedRequests.add(1);
    }

    // Success rate (server responded properly)
    successRate.add(status !== 500);

    // Small random sleep to simulate real traffic
    sleep(Math.random() * 0.5);
}

// ============================================================================
// LIFECYCLE HOOKS
// ============================================================================

export function setup() {
    console.log('='.repeat(70));
    console.log('🔴 SENTINEL-X STRESS TEST STARTING');
    console.log('='.repeat(70));
    console.log(`Target: ${TARGET}`);
    console.log('');

    // Verify target is up
    const res = http.get(TARGET, { timeout: '5s' });
    if (res.status === 0) {
        throw new Error('Target is not responding!');
    }

    console.log(`Target Status: ${res.status}`);
    console.log('Starting attack...\n');
}

export function teardown(data) {
    console.log('\n' + '='.repeat(70));
    console.log('📊 STRESS TEST COMPLETE');
    console.log('='.repeat(70));
    console.log('');
    console.log('Key Results:');
    console.log('  - If you see 500 errors: Server crashed under load ❌');
    console.log('  - If blocked_requests is high: WAF is actively blocking ✅');
    console.log('  - If response_time is low: Server handles load well ✅');
    console.log('');
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
    const summary = {
        'total_requests': data.metrics.http_reqs?.values?.count || 0,
        'blocked': data.metrics.blocked_requests?.values?.count || 0,
        'challenged': data.metrics.challenged_requests?.values?.count || 0,
        'avg_response_time': data.metrics.http_req_duration?.values?.avg || 0,
        'p95_response_time': data.metrics.http_req_duration?.values?.['p(95)'] || 0,
        'failed_requests': data.metrics.http_req_failed?.values?.rate || 0,
    };

    console.log('\n' + '='.repeat(70));
    console.log('📈 FINAL SUMMARY');
    console.log('='.repeat(70));
    console.log(`Total Requests:      ${summary.total_requests}`);
    console.log(`Blocked by WAF:      ${summary.blocked}`);
    console.log(`Challenged:          ${summary.challenged}`);
    console.log(`Avg Response Time:   ${summary.avg_response_time.toFixed(2)}ms`);
    console.log(`P95 Response Time:   ${summary.p95_response_time.toFixed(2)}ms`);
    console.log(`Server Errors:       ${(summary.failed_requests * 100).toFixed(2)}%`);
    console.log('='.repeat(70));

    if (summary.failed_requests < 0.01) {
        console.log('\n✅ SUCCESS: Server remained stable under load!');
    } else {
        console.log('\n❌ WARNING: Server showed instability!');
    }

    return {
        'stdout': '',
        'stress_test_results.json': JSON.stringify(summary, null, 2),
    };
}
