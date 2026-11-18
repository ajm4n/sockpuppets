//go:build !windows

package main

func captureScreenshot() string {
	return "Error: screenshot only supported on Windows"
}
