package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

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

