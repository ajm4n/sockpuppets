//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

const (
	_HKEY_LOCAL_MACHINE = 0x80000002
	_HKEY_CURRENT_USER  = 0x80000001
	_HKEY_CLASSES_ROOT  = 0x80000000
	_HKEY_USERS         = 0x80000003
	_KEY_READ           = 0x20019
)

func matchRegistry(path string) bool {
	parts := strings.SplitN(path, `\`, 2)
	if len(parts) != 2 {
		return false
	}

	var rootKey uintptr
	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		rootKey = _HKEY_LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		rootKey = _HKEY_CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		rootKey = _HKEY_CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		rootKey = _HKEY_USERS
	default:
		return false
	}

	subKey, err := syscall.UTF16PtrFromString(parts[1])
	if err != nil {
		return false
	}

	regOpen := getProc(mAdvapi32, fRegOpenKeyExW)
	regClose := getProc(mAdvapi32, fRegCloseKey)

	var handle syscall.Handle
	ret, _, _ := syscall.SyscallN(regOpen,
		rootKey,
		uintptr(unsafe.Pointer(subKey)),
		0,
		_KEY_READ,
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return false
	}
	syscall.SyscallN(regClose, uintptr(handle))
	return true
}
