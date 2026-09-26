#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetNativeSystemInfo(LPSYSTEM_INFO);

void go(char* args, int alen)
{
    char user[256] = {0};
    char domain[256] = {0};
    DWORD ulen = 256;

    ADVAPI32$GetUserNameA(user, &ulen);
    KERNEL32$GetEnvironmentVariableA("USERDOMAIN", domain, 256);

    SYSTEM_INFO si;
    KERNEL32$GetNativeSystemInfo(&si);

    BeaconPrintf(CALLBACK_OUTPUT,
        "user: %s\\%s\narch: %s\nprocs: %d",
        domain, user,
        si.wProcessorArchitecture == 9 ? "x64" : "x86",
        si.dwNumberOfProcessors);
}
