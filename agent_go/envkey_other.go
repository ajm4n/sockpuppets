//go:build !windows

package main

// matchRegistry is a no-op on non-Windows platforms.
// Registry checks are only meaningful on Windows.
func matchRegistry(_ string) bool {
	return true
}
