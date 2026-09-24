//go:build !windows

package main

func nativeUser() string { return "" }

func handleHiddenDesktop(cmd string) string {
	return "hidden desktop requires windows"
}

func hdTakeHost() bool { return false }
func hdHostMain() int  { return 0 }
