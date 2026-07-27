//go:build !windows

package main

func getSyscallNumber(name string) (uint16, bool) { return 0, false }
