//go:build !windows

package main

func executeBOF(coffData []byte, args []byte, entryPoint string) string {
	return "Error: BOF execution only supported on Windows"
}
