// =============================================================================
// SENTINEL-X DASHBOARD - Security Analytics & Visualization
// =============================================================================
//
// A beautiful, real-time dashboard for monitoring Sentinel-X WAF
//
// FEATURES:
//   - Live request/block graphs
//   - Attack map with geolocation
//   - Detection reason breakdown
//   - Real-time statistics
//   - Basic auth protection
//
// =============================================================================
package dashboard

import (
	"crypto/subtle"
	"encoding/json"
	"html/template"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// DASHBOARD CONFIGURATION
// =============================================================================

// DashboardConfig configures the dashboard
type DashboardConfig struct {
	Enabled      bool
	Username     string
	Password     string
	RefreshRate  time.Duration
	MaxHistory   int
}

// DefaultConfig returns default dashboard configuration
func DefaultConfig() *DashboardConfig {
	return &DashboardConfig{
		Enabled:     true,
		Username:    "admin",
		Password:    "sentinel-x-secure",
		RefreshRate: 5 * time.Second,
		MaxHistory:  60, // 5 minutes at 5s intervals
	}
}

// =============================================================================
// METRICS COLLECTION
// =============================================================================

// TimeSeriesPoint represents a single data point
type TimeSeriesPoint struct {
	Timestamp  int64 `json:"timestamp"`
	Requests   int64 `json:"requests"`
	Blocks     int64 `json:"blocks"`
	Tarpitted  int64 `json:"tarpitted"`
	Challenged int64 `json:"challenged"`
}

// BlockReason tracks blocking reasons
type BlockReason struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

// GeoBlock represents a blocked IP's geographic info
type GeoBlock struct {
	IP        string `json:"ip"`
	Country   string `json:"country"`
	City      string `json:"city"`
	Reason    string `json:"reason"`
	Timestamp int64  `json:"timestamp"`
}

// DashboardMetrics holds all dashboard metrics
type DashboardMetrics struct {
	// Counters (updated in real-time)
	TotalRequests      uint64
	TotalBlocked       uint64
	TotalTarpitted     uint64
	TotalChallenged    uint64
	ActiveConnections  int64
	ActiveTarpits      int64
	
	// Time series (for graphs)
	TimeSeries    []TimeSeriesPoint
	TimeSeriesMu  sync.RWMutex
	
	// Block reasons (for pie chart)
	BlockReasons   map[string]*int64
	BlockReasonsMu sync.RWMutex
	
	// Recent geo-blocks (for map)
	GeoBlocks    []GeoBlock
	GeoBlocksMu  sync.RWMutex
	
	// Detection method stats
	DetectionStats map[string]*int64
	DetectionMu    sync.RWMutex
	
	// Last update
	LastUpdate time.Time
}

// Global metrics instance
var metrics = &DashboardMetrics{
	TimeSeries:     make([]TimeSeriesPoint, 0, 60),
	BlockReasons:   make(map[string]*int64),
	GeoBlocks:      make([]GeoBlock, 0, 100),
	DetectionStats: make(map[string]*int64),
}

// RecordRequest records a request
func RecordRequest() {
	atomic.AddUint64(&metrics.TotalRequests, 1)
}

// RecordBlock records a block with reason
func RecordBlock(reason string) {
	atomic.AddUint64(&metrics.TotalBlocked, 1)
	
	metrics.BlockReasonsMu.Lock()
	if metrics.BlockReasons[reason] == nil {
		var count int64
		metrics.BlockReasons[reason] = &count
	}
	atomic.AddInt64(metrics.BlockReasons[reason], 1)
	metrics.BlockReasonsMu.Unlock()
}

// RecordTarpit records a tarpitted connection
func RecordTarpit() {
	atomic.AddUint64(&metrics.TotalTarpitted, 1)
}

// RecordChallenge records a challenge issued
func RecordChallenge() {
	atomic.AddUint64(&metrics.TotalChallenged, 1)
}

// RecordGeoBlock records a blocked IP with geo info
func RecordGeoBlock(ip, country, city, reason string) {
	metrics.GeoBlocksMu.Lock()
	defer metrics.GeoBlocksMu.Unlock()
	
	block := GeoBlock{
		IP:        ip,
		Country:   country,
		City:      city,
		Reason:    reason,
		Timestamp: time.Now().UnixMilli(),
	}
	
	// Keep only last 100
	if len(metrics.GeoBlocks) >= 100 {
		metrics.GeoBlocks = metrics.GeoBlocks[1:]
	}
	metrics.GeoBlocks = append(metrics.GeoBlocks, block)
}

// RecordDetection records a detection by method
func RecordDetection(method string) {
	metrics.DetectionMu.Lock()
	if metrics.DetectionStats[method] == nil {
		var count int64
		metrics.DetectionStats[method] = &count
	}
	atomic.AddInt64(metrics.DetectionStats[method], 1)
	metrics.DetectionMu.Unlock()
}

// =============================================================================
// TIME SERIES COLLECTION
// =============================================================================

var (
	lastRequests   uint64
	lastBlocks     uint64
	lastTarpits    uint64
	lastChallenges uint64
)

// StartMetricsCollection starts collecting time series data
func StartMetricsCollection(maxHistory int) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		
		for range ticker.C {
			currentRequests := atomic.LoadUint64(&metrics.TotalRequests)
			currentBlocks := atomic.LoadUint64(&metrics.TotalBlocked)
			currentTarpits := atomic.LoadUint64(&metrics.TotalTarpitted)
			currentChallenges := atomic.LoadUint64(&metrics.TotalChallenged)
			
			point := TimeSeriesPoint{
				Timestamp:  time.Now().UnixMilli(),
				Requests:   int64(currentRequests - lastRequests),
				Blocks:     int64(currentBlocks - lastBlocks),
				Tarpitted:  int64(currentTarpits - lastTarpits),
				Challenged: int64(currentChallenges - lastChallenges),
			}
			
			lastRequests = currentRequests
			lastBlocks = currentBlocks
			lastTarpits = currentTarpits
			lastChallenges = currentChallenges
			
			metrics.TimeSeriesMu.Lock()
			metrics.TimeSeries = append(metrics.TimeSeries, point)
			if len(metrics.TimeSeries) > maxHistory {
				metrics.TimeSeries = metrics.TimeSeries[1:]
			}
			metrics.TimeSeriesMu.Unlock()
			
			metrics.LastUpdate = time.Now()
		}
	}()
}

// =============================================================================
// DASHBOARD HANDLERS
// =============================================================================

// Dashboard creates the dashboard handler
func Dashboard(cfg *DashboardConfig) http.Handler {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	
	// Start metrics collection
	StartMetricsCollection(cfg.MaxHistory)
	
	mux := http.NewServeMux()
	
	// Main dashboard page (protected)
	mux.HandleFunc("/", basicAuth(cfg.Username, cfg.Password, dashboardPage))
	
	// API endpoints (protected)
	mux.HandleFunc("/api/stats", basicAuth(cfg.Username, cfg.Password, statsAPI))
	mux.HandleFunc("/api/timeseries", basicAuth(cfg.Username, cfg.Password, timeSeriesAPI))
	mux.HandleFunc("/api/reasons", basicAuth(cfg.Username, cfg.Password, reasonsAPI))
	mux.HandleFunc("/api/geoblocks", basicAuth(cfg.Username, cfg.Password, geoBlocksAPI))
	mux.HandleFunc("/api/detections", basicAuth(cfg.Username, cfg.Password, detectionsAPI))
	
	return http.StripPrefix("/dashboard", mux)
}

// basicAuth implements HTTP Basic Authentication
func basicAuth(username, password string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Sentinel-X Dashboard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		handler(w, r)
	}
}

// =============================================================================
// API HANDLERS
// =============================================================================

func statsAPI(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_requests":     atomic.LoadUint64(&metrics.TotalRequests),
		"total_blocked":      atomic.LoadUint64(&metrics.TotalBlocked),
		"total_tarpitted":    atomic.LoadUint64(&metrics.TotalTarpitted),
		"total_challenged":   atomic.LoadUint64(&metrics.TotalChallenged),
		"active_connections": atomic.LoadInt64(&metrics.ActiveConnections),
		"active_tarpits":     atomic.LoadInt64(&metrics.ActiveTarpits),
		"last_update":        metrics.LastUpdate.UnixMilli(),
		"uptime":             time.Since(startTime).String(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func timeSeriesAPI(w http.ResponseWriter, r *http.Request) {
	metrics.TimeSeriesMu.RLock()
	series := make([]TimeSeriesPoint, len(metrics.TimeSeries))
	copy(series, metrics.TimeSeries)
	metrics.TimeSeriesMu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(series)
}

func reasonsAPI(w http.ResponseWriter, r *http.Request) {
	metrics.BlockReasonsMu.RLock()
	reasons := make([]BlockReason, 0, len(metrics.BlockReasons))
	for reason, count := range metrics.BlockReasons {
		reasons = append(reasons, BlockReason{
			Reason: reason,
			Count:  atomic.LoadInt64(count),
		})
	}
	metrics.BlockReasonsMu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reasons)
}

func geoBlocksAPI(w http.ResponseWriter, r *http.Request) {
	metrics.GeoBlocksMu.RLock()
	blocks := make([]GeoBlock, len(metrics.GeoBlocks))
	copy(blocks, metrics.GeoBlocks)
	metrics.GeoBlocksMu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blocks)
}

func detectionsAPI(w http.ResponseWriter, r *http.Request) {
	metrics.DetectionMu.RLock()
	detections := make(map[string]int64)
	for method, count := range metrics.DetectionStats {
		detections[method] = atomic.LoadInt64(count)
	}
	metrics.DetectionMu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detections)
}

// Start time for uptime calculation
var startTime = time.Now()

// =============================================================================
// DASHBOARD HTML TEMPLATE
// =============================================================================

func dashboardPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	tmpl.Execute(w, nil)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel-X Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a25;
            --accent: #00ffc8;
            --accent-glow: rgba(0, 255, 200, 0.3);
            --danger: #ff4757;
            --warning: #ffa502;
            --success: #2ed573;
            --text-primary: #ffffff;
            --text-secondary: #888;
            --border: #2a2a35;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent) 0%, #00a8ff 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 1.5rem;
        }
        
        .logo-text {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(90deg, var(--accent), #fff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .status-badge {
            background: var(--success);
            color: #000;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.875rem;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .container {
            padding: 2rem;
            max-width: 1800px;
            margin: 0 auto;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-card);
            border-radius: 15px;
            padding: 1.5rem;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            border-color: var(--accent);
            box-shadow: 0 0 20px var(--accent-glow);
            transform: translateY(-2px);
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            font-feature-settings: "tnum";
        }
        
        .stat-value.danger { color: var(--danger); }
        .stat-value.warning { color: var(--warning); }
        .stat-value.success { color: var(--success); }
        .stat-value.accent { color: var(--accent); }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .chart-card {
            background: var(--bg-card);
            border-radius: 15px;
            padding: 1.5rem;
            border: 1px solid var(--border);
        }
        
        .chart-title {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .chart-title::before {
            content: '';
            width: 4px;
            height: 20px;
            background: var(--accent);
            border-radius: 2px;
        }
        
        .chart-container {
            height: 300px;
            position: relative;
        }
        
        .table-card {
            background: var(--bg-card);
            border-radius: 15px;
            padding: 1.5rem;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            text-align: left;
            padding: 1rem;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        
        .ip-badge {
            font-family: 'Consolas', monospace;
            background: var(--bg-secondary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }
        
        .reason-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .reason-badge.tarpit {
            background: rgba(255, 71, 87, 0.2);
            color: var(--danger);
        }
        
        .reason-badge.challenge {
            background: rgba(255, 165, 2, 0.2);
            color: var(--warning);
        }
        
        .reason-badge.block {
            background: rgba(0, 255, 200, 0.2);
            color: var(--accent);
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        
        .update-indicator {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }
        
        @media (max-width: 768px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">
            <div class="logo-icon">S</div>
            <span class="logo-text">Sentinel-X</span>
        </div>
        <span class="status-badge">● PROTECTING</span>
    </header>
    
    <div class="container">
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value accent" id="totalRequests">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Blocked</div>
                <div class="stat-value danger" id="totalBlocked">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Tarpitted</div>
                <div class="stat-value warning" id="totalTarpitted">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Challenged</div>
                <div class="stat-value success" id="totalChallenged">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Tarpits</div>
                <div class="stat-value danger" id="activeTarpits">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Block Rate</div>
                <div class="stat-value" id="blockRate">0%</div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts-grid">
            <div class="chart-card">
                <div class="chart-title">Traffic Over Time</div>
                <div class="chart-container">
                    <canvas id="trafficChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <div class="chart-title">Block Reasons</div>
                <div class="chart-container">
                    <canvas id="reasonsChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Detection Methods -->
        <div class="charts-grid">
            <div class="chart-card">
                <div class="chart-title">Detection Methods</div>
                <div class="chart-container">
                    <canvas id="detectionsChart"></canvas>
                </div>
            </div>
            <div class="table-card">
                <div class="chart-title">Recent Blocks</div>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Country</th>
                            <th>Reason</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody id="recentBlocks">
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <footer class="footer">
        <p>Sentinel-X WAF Dashboard &mdash; <span id="uptime"></span></p>
        <p class="update-indicator">Last update: <span id="lastUpdate"></span></p>
    </footer>
    
    <script>
        // Chart.js configuration
        Chart.defaults.color = '#888';
        Chart.defaults.borderColor = '#2a2a35';
        
        // Traffic Chart
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Requests',
                        data: [],
                        borderColor: '#00ffc8',
                        backgroundColor: 'rgba(0, 255, 200, 0.1)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Blocked',
                        data: [],
                        borderColor: '#ff4757',
                        backgroundColor: 'rgba(255, 71, 87, 0.1)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Reasons Chart
        const reasonsCtx = document.getElementById('reasonsChart').getContext('2d');
        const reasonsChart = new Chart(reasonsCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#00ffc8',
                        '#ff4757',
                        '#ffa502',
                        '#2ed573',
                        '#3742fa',
                        '#a55eea'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
        
        // Detections Chart
        const detectionsCtx = document.getElementById('detectionsChart').getContext('2d');
        const detectionsChart = new Chart(detectionsCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Detections',
                    data: [],
                    backgroundColor: 'rgba(0, 255, 200, 0.5)',
                    borderColor: '#00ffc8',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Format numbers
        function formatNumber(num) {
            if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
            if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
            return num.toString();
        }
        
        // Format time
        function formatTime(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        }
        
        // Update stats
        async function updateStats() {
            try {
                const res = await fetch('/dashboard/api/stats');
                const data = await res.json();
                
                document.getElementById('totalRequests').textContent = formatNumber(data.total_requests);
                document.getElementById('totalBlocked').textContent = formatNumber(data.total_blocked);
                document.getElementById('totalTarpitted').textContent = formatNumber(data.total_tarpitted);
                document.getElementById('totalChallenged').textContent = formatNumber(data.total_challenged);
                document.getElementById('activeTarpits').textContent = data.active_tarpits;
                
                const blockRate = data.total_requests > 0 
                    ? ((data.total_blocked / data.total_requests) * 100).toFixed(1) 
                    : '0';
                document.getElementById('blockRate').textContent = blockRate + '%';
                
                document.getElementById('uptime').textContent = data.uptime;
                document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
            } catch (e) {
                console.error('Failed to fetch stats:', e);
            }
        }
        
        // Update traffic chart
        async function updateTrafficChart() {
            try {
                const res = await fetch('/dashboard/api/timeseries');
                const data = await res.json();
                
                trafficChart.data.labels = data.map(p => formatTime(p.timestamp));
                trafficChart.data.datasets[0].data = data.map(p => p.requests);
                trafficChart.data.datasets[1].data = data.map(p => p.blocks);
                trafficChart.update('none');
            } catch (e) {
                console.error('Failed to fetch timeseries:', e);
            }
        }
        
        // Update reasons chart
        async function updateReasonsChart() {
            try {
                const res = await fetch('/dashboard/api/reasons');
                const data = await res.json();
                
                reasonsChart.data.labels = data.map(r => r.reason);
                reasonsChart.data.datasets[0].data = data.map(r => r.count);
                reasonsChart.update('none');
            } catch (e) {
                console.error('Failed to fetch reasons:', e);
            }
        }
        
        // Update detections chart
        async function updateDetectionsChart() {
            try {
                const res = await fetch('/dashboard/api/detections');
                const data = await res.json();
                
                const labels = Object.keys(data);
                const values = Object.values(data);
                
                detectionsChart.data.labels = labels;
                detectionsChart.data.datasets[0].data = values;
                detectionsChart.update('none');
            } catch (e) {
                console.error('Failed to fetch detections:', e);
            }
        }
        
        // Update recent blocks
        async function updateRecentBlocks() {
            try {
                const res = await fetch('/dashboard/api/geoblocks');
                const data = await res.json();
                
                const tbody = document.getElementById('recentBlocks');
                tbody.innerHTML = data.slice(-10).reverse().map(block => ` + "`" + `
                    <tr>
                        <td><span class="ip-badge">${block.ip}</span></td>
                        <td>${block.country || 'Unknown'}</td>
                        <td><span class="reason-badge block">${block.reason}</span></td>
                        <td>${formatTime(block.timestamp)}</td>
                    </tr>
                ` + "`" + `).join('');
            } catch (e) {
                console.error('Failed to fetch geoblocks:', e);
            }
        }
        
        // Initial load
        updateStats();
        updateTrafficChart();
        updateReasonsChart();
        updateDetectionsChart();
        updateRecentBlocks();
        
        // Periodic updates
        setInterval(updateStats, 5000);
        setInterval(updateTrafficChart, 5000);
        setInterval(updateReasonsChart, 10000);
        setInterval(updateDetectionsChart, 10000);
        setInterval(updateRecentBlocks, 5000);
    </script>
</body>
</html>
`
