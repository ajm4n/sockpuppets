//go:build !windows

package main

func executeShellcode(data []byte) string {
	return "Error: shellcode injection only supported on Windows"
}
