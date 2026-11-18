//go:build !windows

package main

func handleTokenOp(op string) string {
	return "Error: token manipulation only supported on Windows"
}
