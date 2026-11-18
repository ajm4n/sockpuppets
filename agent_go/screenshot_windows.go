//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	SM_CXSCREEN    = 0
	SM_CYSCREEN    = 1
	SRCCOPY        = 0x00CC0020
	BI_RGB         = 0
	DIB_RGB_COLORS = 0
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
}

func captureScreenshot() string {
	pGetSysMetrics := getProc(mUser32, fGetSystemMetrics)
	pGetDCp := getProc(mUser32, fGetDC)
	pRelDC := getProc(mUser32, fReleaseDC)
	pCreateDC := getProc(mGdi32, fCreateCompatibleDC)
	pCreateBmp := getProc(mGdi32, fCreateCompatibleBitmap)
	pSelObj := getProc(mGdi32, fSelectObject)
	pBlt := getProc(mGdi32, fBitBlt)
	pDIBits := getProc(mGdi32, fGetDIBits)
	pDelObj := getProc(mGdi32, fDeleteObject)
	pDelDC := getProc(mGdi32, fDeleteDC)

	width, _, _ := syscall.SyscallN(pGetSysMetrics, SM_CXSCREEN)
	height, _, _ := syscall.SyscallN(pGetSysMetrics, SM_CYSCREEN)
	if width == 0 || height == 0 {
		return "Error: failed to get screen dimensions"
	}

	hdc, _, _ := syscall.SyscallN(pGetDCp, 0)
	if hdc == 0 {
		return "Error: GetDC failed"
	}
	defer syscall.SyscallN(pRelDC, 0, hdc)

	memDC, _, _ := syscall.SyscallN(pCreateDC, hdc)
	if memDC == 0 {
		return "Error: CreateCompatibleDC failed"
	}
	defer syscall.SyscallN(pDelDC, memDC)

	bmp, _, _ := syscall.SyscallN(pCreateBmp, hdc, width, height)
	if bmp == 0 {
		return "Error: CreateCompatibleBitmap failed"
	}
	defer syscall.SyscallN(pDelObj, bmp)

	old, _, _ := syscall.SyscallN(pSelObj, memDC, bmp)
	defer syscall.SyscallN(pSelObj, memDC, old)

	syscall.SyscallN(pBlt, memDC, 0, 0, width, height, hdc, 0, 0, SRCCOPY)

	w := int32(width)
	h := int32(height)
	bi := bitmapInfo{
		BmiHeader: bitmapInfoHeader{
			BiSize:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			BiWidth:    w,
			BiHeight:   -h,
			BiPlanes:   1,
			BiBitCount: 24,
		},
	}
	rowSize := ((w*3 + 3) / 4) * 4
	dataSize := int(rowSize) * int(h)
	pixels := make([]byte, dataSize)
	syscall.SyscallN(pDIBits, memDC, bmp, 0, uintptr(h), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&bi)), DIB_RGB_COLORS)

	fileSize := 54 + dataSize
	bmpData := make([]byte, fileSize)
	bmpData[0], bmpData[1] = 'B', 'M'
	le32(bmpData[2:], uint32(fileSize))
	le32(bmpData[10:], 54)
	le32(bmpData[14:], 40)
	le32s(bmpData[18:], w)
	le32s(bmpData[22:], -h)
	bmpData[26] = 1
	bmpData[28] = 24
	le32(bmpData[34:], uint32(dataSize))
	copy(bmpData[54:], pixels)

	encoded := base64.StdEncoding.EncodeToString(bmpData)
	if len(encoded) > 500000 {
		return fmt.Sprintf("SCREENSHOT:%dx%d:%s", w, h, encoded[:500000])
	}
	return fmt.Sprintf("SCREENSHOT:%dx%d:%s", w, h, encoded)
}

func le32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func le32s(b []byte, v int32) {
	le32(b, uint32(v))
}
