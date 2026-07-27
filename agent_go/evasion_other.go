//go:build !windows

package main

import (
	"context"
	"time"
)

func initWindowsEvasion()                                             {}
func findExplorerPID() uint32                                         { return 0 }
func ExecuteWithPPIDSpoof(command string, ppid uint32) ([]byte, error) {
	return runCommand(context.Background(), "sh", "-c", command)
}
func sleepEncrypted(duration time.Duration)  { time.Sleep(duration) }
func initSyscallTable()                      {}
func initSleepEncryption()                   {}
func refreshHardwareBreakpoints()            {}
func storeSensitive(data []byte) uintptr     { return 0 }
func readSensitive(offset uintptr) []byte    { return nil }
