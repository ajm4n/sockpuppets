#include <windows.h>
#include <wtsapi32.h>
#include <stdio.h>
int main(void) {
    DWORD sid = WTSGetActiveConsoleSessionId();
    HANDLE tok = NULL, dup = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "%s%s", "C:/Users/Public/", "hdcmd.exe");
    FILE *log = fopen("C:\\Users\\Public\\hdcmdrun.txt", "w");
    if (!WTSQueryUserToken(sid, &tok) || !DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup)) {
        if (log) { fprintf(log, "token %lu\n", GetLastError()); fclose(log); }
        return 1;
    }
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = "winsta0\\default";
    if (!CreateProcessAsUserA(dup, NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        if (log) { fprintf(log, "spawn %lu\n", GetLastError()); fclose(log); }
        return 1;
    }
    WaitForSingleObject(pi.hProcess, 20000);
    if (log) { fputs("ran\n", log); fclose(log); }
    return 0;
}
