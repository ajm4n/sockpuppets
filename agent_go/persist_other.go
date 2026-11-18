//go:build !windows

package main

func handlePersist(args string) string {
	return "Error: persistence only supported on Windows"
}
