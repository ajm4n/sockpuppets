#include <windows.h>
#include <wtsapi32.h>
#include <stdio.h>

int main(int argc, char **argv) {
    DWORD sid;
    HANDLE tok = NULL, dup = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[1024];
    if (argc < 2) return 2;
    sid = WTSGetActiveConsoleSessionId();
    if (sid == 0xFFFFFFFF || !WTSQueryUserToken(sid, &tok)) {
        printf("token %lu\n", GetLastError());
        return 3;
    }
    if (!DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup)) {
        printf("dup %lu\n", GetLastError());
        return 4;
    }
    CloseHandle(tok);
    snprintf(cmd, sizeof(cmd), "\"%s\"", argv[1]);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = "winsta0\\default";
    if (!CreateProcessAsUserA(dup, NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("start %lu\n", GetLastError());
        return 5;
    }
    printf("pid %lu\n", pi.dwProcessId);
    CloseHandle(dup);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
