//go:build !windows

package main

func executeAssembly(data []byte, args string) string {
	return "Error: execute-assembly only supported on Windows"
}
