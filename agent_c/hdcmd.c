#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static HWND g_note;
static int g_pop;
static HWND g_pop_hwnd;
static HWND g_dlg;
static int g_cmd;
static int g_spawn_err;
static int g_frame_dark;
static int g_switched;
static int g_sx, g_sy;
static int g_nwin;
static char g_probe[32];
static RECT g_pop_rc;
static BOOL CALLBACK find_dlg(HWND hwnd, LPARAM lp) {
    char cls[32];
    (void)lp;
    if (!g_dlg && GetClassNameA(hwnd, cls, 32) && !strcmp(cls, "#32770")) g_dlg = hwnd;
    return TRUE;
}
static BOOL CALLBACK find_pop(HWND hwnd, LPARAM lp) {
    char cls[32];
    RECT rc;
    (void)lp;
    if (GetClassNameA(hwnd, cls, 32) && !strcmp(cls, "#32768")) {
        if (!GetWindowRect(hwnd, &rc)) return TRUE;
        if (rc.right - rc.left < 140 || rc.bottom - rc.top < 80) return TRUE;
        g_pop++;
        if (!g_pop_hwnd) g_pop_hwnd = hwnd;
    }
    return TRUE;
}
static BOOL CALLBACK find_note(HWND hwnd, LPARAM lp) {
    char cls[64];
    (void)lp;
    GetClassNameA(hwnd, cls, 64);
    if (!g_note && !strcmp(cls, "Notepad")) g_note = hwnd;
    return TRUE;
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
static HMENU g_track_menu;
static HWND g_track_owner;
static int g_track_x, g_track_y;
static DWORD WINAPI track_menu(LPVOID p) {
    SetThreadDesktop((HDESK)p);
    TrackPopupMenu(g_track_menu, TPM_LEFTALIGN | TPM_NONOTIFY, g_track_x, g_track_y, 0, g_track_owner, NULL);
    return 0;
}
static void spawn_note(void) {
    char name[64] = {0}, deskpath[96];
    FILE *f = fopen("C:\\Users\\Public\\hddesk.txt", "r");
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char *nl;
    if (!f || !fgets(name, 64, f)) return;
    fclose(f);
    nl = strpbrk(name, "\r\n");
    if (nl) *nl = 0;
    snprintf(deskpath, sizeof(deskpath), "WinSta0\\%s", name);
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.lpDesktop = deskpath;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    {
        char cmd[] = "C:\\Windows\\System32\\notepad.exe";
        if (CreateProcessA(cmd, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            g_spawn_err = 0;
        } else g_spawn_err = (int)GetLastError();
    }
}
static void write_out(const char *s) {
    FILE *f = fopen("C:\\Users\\Public\\hdout.txt", "wb");
    if (f) { fputs(s, f); fclose(f); }
}
static int open_desk(HDESK *desk, HDESK *back) {
    char name[64] = {0};
    FILE *in = fopen("C:\\Users\\Public\\hddesk.txt", "r");
    if (!in || !fgets(name, 64, in)) return 0;
    fclose(in);
    *desk = OpenDesktopA(name, 0, FALSE, 0x01FF);
    if (!*desk || !SetThreadDesktop(*desk)) return 0;
    *back = OpenDesktopA("Default", 0, FALSE, 0x0100);
    g_switched = SwitchDesktop(*desk) ? 1 : 0;
    return 1;
}
static char *frame_window(HWND hwnd) {
    RECT rc;
    HDC hdc, mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    int w, h, stride, x, y;
    unsigned char *pix, *file;
    char *enc, *out;
    size_t flen;
    if (!hwnd || !GetWindowRect(hwnd, &rc)) return _strdup("no frame");
    w = rc.right - rc.left;
    h = rc.bottom - rc.top;
    if (w < 40 || h < 40 || w > 1400 || h > 1000) return _strdup("no frame");
    hdc = GetWindowDC(hwnd);
    if (!hdc) return _strdup("no frame");
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, w, h);
    old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);
    SendMessageTimeout(hwnd, WM_PRINT, (WPARAM)mem, PRF_CLIENT | PRF_NONCLIENT | PRF_CHILDREN | PRF_ERASEBKGND, SMTO_ABORTIFHUNG | SMTO_BLOCK, 400, NULL);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = 40;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    stride = ((w * 3 + 3) / 4) * 4;
    pix = (unsigned char *)calloc(1, stride * (size_t)h);
    GetDIBits(mem, bmp, 0, h, pix, &bi, DIB_RGB_COLORS);
    g_frame_dark = 0;
    for (y = 0; y < h && y < 80; y++) {
        for (x = 0; x < w && x < 200; x++) {
            int p = y * stride + x * 3;
            if (pix[p] + pix[p + 1] + pix[p + 2] < 400) g_frame_dark++;
        }
    }
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(hwnd, hdc);
    flen = 54 + stride * (size_t)h;
    file = (unsigned char *)calloc(1, flen);
    memcpy(file, "BM", 2);
    *(unsigned *)(file + 2) = (unsigned)flen;
    *(unsigned *)(file + 10) = 54;
    *(unsigned *)(file + 14) = 40;
    *(int *)(file + 18) = w;
    *(int *)(file + 22) = h;
    *(unsigned short *)(file + 26) = 1;
    *(unsigned short *)(file + 28) = 24;
    memcpy(file + 54, pix, stride * (size_t)h);
    free(pix);
    enc = b64(file, flen);
    free(file);
    out = (char *)malloc(32 + strlen(enc));
    sprintf(out, "HDIMG:%d,%d:%s", w, h, enc);
    free(enc);
    return out;
}
static char *frame_at(int sx, int sy, int w, int h) {
    HDC hdc, mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    int stride;
    unsigned char *pix, *file;
    char *enc, *out;
    size_t flen;
    if (w < 40) w = 40;
    if (h < 40) h = 40;
    if (w > 1400) w = 1400;
    if (h > 1200) h = 1200;
    hdc = GetDC(NULL);
    if (!hdc) return _strdup("no frame");
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, w, h);
    old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, hdc, sx, sy, SRCCOPY);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = 40;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    stride = ((w * 3 + 3) / 4) * 4;
    pix = (unsigned char *)calloc(1, stride * (size_t)h);
    GetDIBits(mem, bmp, 0, h, pix, &bi, DIB_RGB_COLORS);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    flen = 54 + stride * (size_t)h;
    file = (unsigned char *)calloc(1, flen);
    memcpy(file, "BM", 2);
    *(unsigned *)(file + 2) = (unsigned)flen;
    *(unsigned *)(file + 10) = 54;
    *(unsigned *)(file + 14) = 40;
    *(int *)(file + 18) = w;
    *(int *)(file + 22) = h;
    *(unsigned short *)(file + 26) = 1;
    *(unsigned short *)(file + 28) = 24;
    memcpy(file + 54, pix, stride * (size_t)h);
    free(pix);
    enc = b64(file, flen);
    free(file);
    out = (char *)malloc(32 + strlen(enc));
    sprintf(out, "HDIMG:%d,%d:%s", w, h, enc);
    free(enc);
    return out;
}
static int popup_ink(RECT pr) {
    HDC hdc, mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    int w = pr.right - pr.left, h = pr.bottom - pr.top, stride, x, y, n = 0;
    unsigned char *pix;
    if (w < 8 || h < 8) return 0;
    if (w > 400) w = 400;
    if (h > 400) h = 400;
    hdc = GetDC(NULL);
    if (!hdc) return 0;
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, w, h);
    old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, hdc, pr.left, pr.top, SRCCOPY);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = 40;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    stride = ((w * 3 + 3) / 4) * 4;
    pix = (unsigned char *)calloc(1, stride * (size_t)h);
    GetDIBits(mem, bmp, 0, h, pix, &bi, DIB_RGB_COLORS);
    for (y = 0; y < h && y < 40; y++) {
        for (x = 0; x < w && x < 180; x++) {
            int p = y * stride + x * 3;
            if (pix[p] + pix[p + 1] + pix[p + 2] < 500) n++;
        }
    }
    free(pix);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    return n;
}
static char *frame_with_menu(RECT wr, RECT pr) {
    int w = wr.right - wr.left, h = wr.bottom - wr.top;
    int pw = pr.right - pr.left, ph = pr.bottom - pr.top;
    HDC hdc, mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    int stride;
    unsigned char *pix, *file;
    char *enc, *out;
    size_t flen;
    if (w < 40) w = 40;
    if (h < 40) h = 40;
    if (w > 1400) w = 1400;
    if (h > 1000) h = 1000;
    hdc = GetDC(NULL);
    if (!hdc) return frame_at(wr.left, wr.top, w, h);
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, w, h);
    old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, hdc, wr.left, wr.top, SRCCOPY);
    if (pw > 10 && ph > 10) {
        int dx = pr.left - wr.left, dy = pr.top - wr.top;
        if (dx < 0) dx = 0;
        if (dy < 0) dy = 0;
        BitBlt(mem, dx, dy, pw, ph, hdc, pr.left, pr.top, SRCCOPY);
        if (g_pop_hwnd) {
            HDC pdc = CreateCompatibleDC(hdc);
            HBITMAP pb = CreateCompatibleBitmap(hdc, pw, ph);
            HGDIOBJ pold = SelectObject(pdc, pb);
            if (PrintWindow(g_pop_hwnd, pdc, 2))
                BitBlt(mem, dx, dy, pw, ph, pdc, 0, 0, SRCCOPY);
            SelectObject(pdc, pold);
            DeleteObject(pb);
            DeleteDC(pdc);
        }
    }
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = 40;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    stride = ((w * 3 + 3) / 4) * 4;
    pix = (unsigned char *)calloc(1, stride * (size_t)h);
    GetDIBits(mem, bmp, 0, h, pix, &bi, DIB_RGB_COLORS);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    flen = 54 + stride * (size_t)h;
    file = (unsigned char *)calloc(1, flen);
    memcpy(file, "BM", 2);
    *(unsigned *)(file + 2) = (unsigned)flen;
    *(unsigned *)(file + 10) = 54;
    *(unsigned *)(file + 14) = 40;
    *(int *)(file + 18) = w;
    *(int *)(file + 22) = h;
    *(unsigned short *)(file + 26) = 1;
    *(unsigned short *)(file + 28) = 24;
    memcpy(file + 54, pix, stride * (size_t)h);
    free(pix);
    enc = b64(file, flen);
    free(file);
    out = (char *)malloc(32 + strlen(enc));
    sprintf(out, "HDIMG:%d,%d:%s", w, h, enc);
    free(enc);
    return out;
}
static char *frame(void) {
    HDC hdc, mem;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    int w = 800, h = 600, stride, y;
    unsigned char *pix, *file;
    char *enc, *out;
    size_t flen;
    hdc = GetDC(NULL);
    if (!hdc) return _strdup("no dc");
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, w, h);
    old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = 40;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    stride = ((w * 3 + 3) / 4) * 4;
    pix = (unsigned char *)calloc(1, stride * (size_t)h);
    GetDIBits(mem, bmp, 0, h, pix, &bi, DIB_RGB_COLORS);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    flen = 54 + stride * (size_t)h;
    file = (unsigned char *)calloc(1, flen);
    memcpy(file, "BM", 2);
    *(unsigned *)(file + 2) = (unsigned)flen;
    *(unsigned *)(file + 10) = 54;
    *(unsigned *)(file + 14) = 40;
    *(int *)(file + 18) = w;
    *(int *)(file + 22) = h;
    *(unsigned short *)(file + 26) = 1;
    *(unsigned short *)(file + 28) = 24;
    memcpy(file + 54, pix, stride * (size_t)h);
    free(pix);
    enc = b64(file, flen);
    free(file);
    out = (char *)malloc(32 + strlen(enc));
    sprintf(out, "HDIMG:%d,%d:%s", w, h, enc);
    free(enc);
    (void)y;
    return out;
}
int main(void) {
    char inbuf[512] = {0}, text[160] = {0};
    const char *arg = "";
    HDESK desk = NULL, back = NULL;
    FILE *in = fopen("C:\\Users\\Public\\hdin.txt", "r");
    HWND edit;
    if (!in || !fgets(inbuf, sizeof(inbuf), in)) { write_out("no command"); return 1; }
    fclose(in);
    if (!open_desk(&desk, &back)) { write_out("desktop open failed"); return 1; }
    if (!strstr(inbuf, "frame")) Sleep(800);
    g_note = NULL;
    EnumDesktopWindows(desk, find_note, 0);
    edit = g_note ? FindWindowExA(g_note, NULL, "Edit", NULL) : NULL;
    if (strstr(inbuf, "read")) {
        int nwin = 0;
        char line[400] = "read";
        HWND w = NULL;
        if (edit) SendMessageTimeoutA(edit, WM_GETTEXT, 160, (LPARAM)text, SMTO_ABORTIFHUNG | SMTO_BLOCK, 2000, NULL);
        while ((w = FindWindowExA(NULL, w, "Notepad", NULL)) != NULL) {
            char buf[80] = {0};
            HWND ed = FindWindowExA(w, NULL, "Edit", NULL);
            nwin++;
            if (ed) SendMessageTimeoutA(ed, WM_GETTEXT, 60, (LPARAM)buf, SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, NULL);
            snprintf(line + strlen(line), sizeof(line) - strlen(line), " %d:[%s]", nwin, buf);
            if (nwin > 4) break;
        }
        if (back) SwitchDesktop(back);
        write_out(line);
        return 0;
    }
    if (strstr(inbuf, "type")) {
        arg = strstr(inbuf, "type");
        arg = arg ? arg + 4 : "";
        while (*arg == ' ') arg++;
        {
            char *nl = strpbrk(arg, "\r\n");
            if (nl) *nl = 0;
        }
        {
            DWORD_PTR sm = 0;
            if (arg[0]) {
                HWND w = NULL;
                g_nwin = 0;
                g_probe[0] = 0;
                while ((w = FindWindowExA(NULL, w, NULL, NULL)) != NULL) {
                    HWND ed = FindWindowExA(w, NULL, "Edit", NULL);
                    char probe[32] = {0};
                    if (!ed || !SendMessageTimeoutA(ed, WM_GETTEXT, 32, (LPARAM)probe, SMTO_ABORTIFHUNG | SMTO_BLOCK, 250, NULL))
                        continue;
                    g_nwin++;
                    if (!g_probe[0]) snprintf(g_probe, sizeof(g_probe), "%s", probe);
                    SendMessageTimeoutA(ed, 0x00B1, 0, -1, SMTO_ABORTIFHUNG | SMTO_BLOCK, 400, NULL);
                    SendMessageTimeoutA(ed, 0x00C2, 0, (LPARAM)arg, SMTO_ABORTIFHUNG | SMTO_BLOCK, 800, NULL);
                    text[0] = 0;
                    SendMessageTimeoutA(ed, WM_GETTEXT, 160, (LPARAM)text, SMTO_ABORTIFHUNG | SMTO_BLOCK, 800, NULL);
                    if (strcmp(text, arg) == 0) {
                        edit = ed;
                        sm = 1;
                        break;
                    }
                }
                if (!edit) {
                    HWND w = NULL;
                    spawn_note();
                    Sleep(1200);
                    while ((w = FindWindowExA(NULL, w, "Notepad", NULL)) != NULL) {
                        HWND ed = FindWindowExA(w, NULL, "Edit", NULL);
                        DWORD_PTR ok;
                        if (!ed) continue;
                        ok = SendMessageTimeoutA(ed, WM_SETTEXT, 0, (LPARAM)arg, SMTO_ABORTIFHUNG | SMTO_BLOCK, 800, NULL);
                        if (!ok) continue;
                        edit = ed;
                        sm = ok;
                        SendMessageTimeoutA(ed, WM_GETTEXT, 160, (LPARAM)text, SMTO_ABORTIFHUNG | SMTO_BLOCK, 800, NULL);
                        break;
                    }
                }
            }
            if (back) SwitchDesktop(back);
            {
                char line[220];
                snprintf(line, sizeof(line), "typed %d [%s] sm=%lu arg=%s v=52 n=%d probe=%s", (int)strlen(text), text, (unsigned long)sm, arg, g_nwin, g_probe);
                write_out(line);
            }
        }
        return 0;
    }
    if (strstr(inbuf, "click")) {
        int x = 18, y = 32;
        const char *p = strstr(inbuf, "click");
        char cls[32] = "none";
        RECT rc;
        if (p) sscanf(p + 5, "%d %d", &x, &y);
        {
            HWND w = NULL, live = NULL;
            while ((w = FindWindowExA(NULL, w, NULL, NULL)) != NULL) {
                HWND ed = FindWindowExA(w, NULL, "Edit", NULL);
                char probe[32] = {0};
                if (!ed || !SendMessageTimeoutA(ed, WM_GETTEXT, 32, (LPARAM)probe, SMTO_ABORTIFHUNG | SMTO_BLOCK, 300, NULL))
                    continue;
                if (strstr(probe, "goagent")) live = w;
                else if (!live) live = w;
            }
            if (live) g_note = live;
        }
        if (g_note && GetWindowRect(g_note, &rc)) {
            HMENU menu = GetMenu(g_note);
            RECT item;
            int sw = GetSystemMetrics(SM_CXSCREEN);
            int sh = GetSystemMetrics(SM_CYSCREEN);
            int sx = rc.left + x;
            int sy = rc.top + y;
            HWND hit;
            char *img;
            AllowSetForegroundWindow(ASFW_ANY);
            LockSetForegroundWindow(LSFW_UNLOCK);
            PostMessageA(g_note, WM_CANCELMODE, 0, 0);
            SetForegroundWindow(g_note);
            g_pop = 0;
            g_pop_hwnd = NULL;
            EnumDesktopWindows(desk, find_pop, 0);
            if (!g_pop_hwnd && y < 48) {
                DWORD tid = GetWindowThreadProcessId(g_note, NULL);
                int sw = GetSystemMetrics(SM_CXSCREEN);
                int sh = GetSystemMetrics(SM_CYSCREEN);
                RECT item;
                int sx = rc.left + 24, sy = rc.top + 40;
                if (menu && GetMenuItemRect(g_note, menu, 0, &item)
                    && item.left >= rc.left - 8 && item.top >= rc.top && item.bottom <= rc.top + 80) {
                    sx = (item.left + item.right) / 2;
                    sy = (item.top + item.bottom) / 2;
                }
                g_sx = sx;
                g_sy = sy;
                if (sw < 1) sw = 1;
                if (sh < 1) sh = 1;
                AttachThreadInput(GetCurrentThreadId(), tid, TRUE);
                SetForegroundWindow(g_note);
                BringWindowToTop(g_note);
                mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE, (DWORD)(sx * 65535 / sw), (DWORD)(sy * 65535 / sh), 0, 0);
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                PostMessageA(g_note, WM_SYSCOMMAND, SC_KEYMENU, (LPARAM)'f');
                AttachThreadInput(GetCurrentThreadId(), tid, FALSE);
                Sleep(700);
                g_pop = 0;
                g_pop_hwnd = NULL;
            }
            (void)sw; (void)sh; (void)sx; (void)sy; (void)item;
            g_dlg = NULL;
            EnumDesktopWindows(desk, find_pop, 0);
            if (!g_pop_hwnd && menu) {
                HMENU sub = GetSubMenu(menu, 0);
                RECT item;
                if (sub && GetMenuItemRect(g_note, menu, 0, &item)) {
                    g_track_menu = sub;
                    g_track_owner = g_note;
                    g_track_x = item.left;
                    g_track_y = item.bottom;
                    CreateThread(NULL, 0, track_menu, desk, 0, NULL);
                    Sleep(700);
                    g_pop = 0;
                    g_pop_hwnd = NULL;
                    EnumDesktopWindows(desk, find_pop, 0);
                }
            }
            if (!g_pop_hwnd) {
                spawn_note();
                Sleep(1500);
                g_note = NULL;
                EnumDesktopWindows(desk, find_note, 0);
                if (g_note) {
                    PostMessageA(g_note, WM_SYSCOMMAND, SC_KEYMENU, (LPARAM)'f');
                    Sleep(500);
                    g_pop = 0;
                    g_pop_hwnd = NULL;
                    EnumDesktopWindows(desk, find_pop, 0);
                }
            }
            g_cmd = 0;
            if (y < 48 && menu) {
                HMENU sub = GetSubMenu(menu, 0);
                UINT id = sub ? GetMenuItemID(sub, 0) : 0;
                g_cmd = (int)id;
            }
            g_dlg = NULL;
            EnumDesktopWindows(desk, find_dlg, 0);
            if (g_note) GetClassNameA(g_note, cls, 32);
            ZeroMemory(&g_pop_rc, sizeof(g_pop_rc));
            if (g_pop_hwnd) {
                int tries;
                RedrawWindow(g_pop_hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE | RDW_FRAME);
                GetWindowRect(g_pop_hwnd, &g_pop_rc);
                for (tries = 0; tries < 8 && popup_ink(g_pop_rc) < 30; tries++) Sleep(150);
            }
            {
                int x0 = rc.left, y0 = rc.top, x1 = rc.right, y1 = rc.bottom;
                RECT extra;
                if (g_pop_rc.right > g_pop_rc.left) {
                    if (g_pop_rc.left < x0) x0 = g_pop_rc.left;
                    if (g_pop_rc.top < y0) y0 = g_pop_rc.top;
                    if (g_pop_rc.right > x1) x1 = g_pop_rc.right;
                    if (g_pop_rc.bottom > y1) y1 = g_pop_rc.bottom;
                }
                if (g_dlg && GetWindowRect(g_dlg, &extra)) {
                    if (extra.left < x0) x0 = extra.left;
                    if (extra.top < y0) y0 = extra.top;
                    if (extra.right > x1) x1 = extra.right;
                    if (extra.bottom > y1) y1 = extra.bottom;
                }
                if (g_pop_rc.right > g_pop_rc.left)
                    img = frame_with_menu(rc, g_pop_rc);
                else
                    img = frame_at(x0, y0, x1 - x0, y1 - y0);
            }
            {
                FILE *st = fopen("C:\\Users\\Public\\hdclick.txt", "wb");
                if (st) {
                    fprintf(st, "click %d %d %s pop=%d dlg=%d cmd=%d v=60 sw=%d at=%d,%d note=%ld,%ld,%ld,%ld %ld,%ld,%ld,%ld\n", x, y, cls, g_pop, g_dlg ? 1 : 0, g_cmd, g_switched, g_sx, g_sy,
                        (long)rc.left, (long)rc.top, (long)rc.right, (long)rc.bottom,
                        (long)g_pop_rc.left, (long)g_pop_rc.top, (long)g_pop_rc.right, (long)g_pop_rc.bottom);
                    fclose(st);
                }
            }
            if (back) SwitchDesktop(back);
            if (img && strncmp(img, "HDIMG:", 6) == 0) {
                write_out(img);
                free(img);
            } else {
                char line[120];
                snprintf(line, sizeof(line), "click %d %d %s pop=%d %ld,%ld,%ld,%ld", x, y, cls, g_pop,
                    (long)g_pop_rc.left, (long)g_pop_rc.top, (long)g_pop_rc.right, (long)g_pop_rc.bottom);
                write_out(line);
                free(img);
            }
            return 0;
        }
        if (back) SwitchDesktop(back);
        write_out("click no window");
        return 0;
    }
    if (strstr(inbuf, "frame")) {
        char *img = NULL;
        g_pop = 0;
        g_pop_hwnd = NULL;
        EnumDesktopWindows(desk, find_pop, 0);
        if (g_note && g_pop_hwnd && GetWindowRect(g_note, &g_pop_rc)) {
            RECT nr, pr;
            nr = g_pop_rc;
            if (GetWindowRect(g_pop_hwnd, &pr))
                img = frame_with_menu(nr, pr);
        }
        if (!img && g_note) {
            HWND ed = FindWindowExA(g_note, NULL, "Edit", NULL);
            char cur[160] = {0};
            RECT wr;
            if (ed) {
                SendMessageTimeoutA(ed, WM_GETTEXT, 160, (LPARAM)cur, SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, NULL);
                SendMessageTimeoutA(ed, WM_SETTEXT, 0, (LPARAM)cur, SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, NULL);
            }
            Sleep(200);
            if (GetWindowRect(g_note, &wr))
                img = frame_at(wr.left, wr.top, wr.right - wr.left, wr.bottom - wr.top);
            if (!img) img = frame_window(g_note);
        }
        if (!img) img = frame();
        if (back) SwitchDesktop(back);
        write_out(img ? img : "no frame");
        free(img);
        return 0;
    }
    if (back) SwitchDesktop(back);
    write_out(g_note ? "desktop ready" : "no notepad");
    return 0;
}
