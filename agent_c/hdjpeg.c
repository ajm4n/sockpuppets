#include <windows.h>
#include <objidl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef int GpStatus;
typedef void GpBitmap;
typedef void GpImage;
typedef struct { UINT32 GdiplusVersion; void *DebugEventCallback; int SuppressBackgroundThread; int SuppressExternalCodecs; } GpStartupInput;
typedef struct { GUID Guid; ULONG NumberOfValues; ULONG Type; void *Value; } GpEncParam;
typedef struct { UINT Count; GpEncParam Parameter[1]; } GpEncParams;

static const GUID jpeg_clsid = {0x557cf401,0x1a04,0x11d3,{0x9a,0x73,0x00,0x00,0xf8,0x1e,0xf3,0x2e}};
static const GUID enc_quality = {0x1d5be4b5,0xfa4a,0x452d,{0x9c,0xdd,0x5d,0xb3,0x51,0x05,0xe7,0xeb}};

typedef GpStatus (WINAPI *gp_startup_fn)(ULONG_PTR *, GpStartupInput *, void *);
typedef void (WINAPI *gp_shutdown_fn)(ULONG_PTR);
typedef GpStatus (WINAPI *gp_bmp_fn)(INT, INT, INT, INT, BYTE *, GpBitmap **);
typedef GpStatus (WINAPI *gp_save_fn)(GpImage *, IStream *, const GUID *, const GpEncParams *);
typedef GpStatus (WINAPI *gp_dispose_fn)(GpImage *);

unsigned char *hd_jpeg(const unsigned char *bgr, int w, int h, int stride, int quality, size_t *out_len) {
    HMODULE dll;
    gp_startup_fn startup;
    gp_shutdown_fn shutdown;
    gp_bmp_fn make;
    gp_save_fn save;
    gp_dispose_fn dispose;
    GpStartupInput in;
    ULONG_PTR token = 0;
    GpBitmap *bmp = NULL;
    IStream *stream = NULL;
    HGLOBAL mem = NULL;
    unsigned char *rgb = NULL, *out = NULL;
    int x, y;
    ULONG q;
    GpEncParams param;
    SIZE_T n;
    void *src;
    if (!bgr || w < 1 || h < 1 || !out_len) return NULL;
    *out_len = 0;
    dll = LoadLibraryA("gdiplus.dll");
    if (!dll) return NULL;
    startup = (gp_startup_fn)GetProcAddress(dll, "GdiplusStartup");
    shutdown = (gp_shutdown_fn)GetProcAddress(dll, "GdiplusShutdown");
    make = (gp_bmp_fn)GetProcAddress(dll, "GdipCreateBitmapFromScan0");
    save = (gp_save_fn)GetProcAddress(dll, "GdipSaveImageToStream");
    dispose = (gp_dispose_fn)GetProcAddress(dll, "GdipDisposeImage");
    if (!startup || !shutdown || !make || !save || !dispose) { FreeLibrary(dll); return NULL; }
    {
        int row = (w * 3 + 3) & ~3;
        rgb = (unsigned char *)calloc(1, (size_t)row * h);
        if (!rgb) { FreeLibrary(dll); return NULL; }
        for (y = 0; y < h; y++) {
            for (x = 0; x < w; x++) {
                rgb[y * row + x * 3 + 0] = bgr[y * stride + x * 3 + 2];
                rgb[y * row + x * 3 + 1] = bgr[y * stride + x * 3 + 1];
                rgb[y * row + x * 3 + 2] = bgr[y * stride + x * 3 + 0];
            }
        }
        stride = row;
    }
    memset(&in, 0, sizeof(in));
    in.GdiplusVersion = 1;
    if (startup(&token, &in, NULL) != 0) { free(rgb); FreeLibrary(dll); return NULL; }
    if (make(w, h, stride, 0x00021808, rgb, &bmp) != 0 || !bmp) {
        shutdown(token); free(rgb); FreeLibrary(dll); return NULL;
    }
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) {
        dispose((GpImage *)bmp); shutdown(token); free(rgb); FreeLibrary(dll); return NULL;
    }
    q = quality < 40 ? 40 : (ULONG)quality;
    memset(&param, 0, sizeof(param));
    param.Count = 1;
    param.Parameter[0].Guid = enc_quality;
    param.Parameter[0].NumberOfValues = 1;
    param.Parameter[0].Type = 4;
    param.Parameter[0].Value = &q;
    if (save((GpImage *)bmp, stream, &jpeg_clsid, &param) != 0) {
        stream->lpVtbl->Release(stream);
        dispose((GpImage *)bmp); shutdown(token); free(rgb); FreeLibrary(dll); return NULL;
    }
    GetHGlobalFromStream(stream, &mem);
    n = GlobalSize(mem);
    src = GlobalLock(mem);
    if (src && n > 32 && n < 900000) {
        out = (unsigned char *)malloc(n);
        if (out) { memcpy(out, src, n); *out_len = n; }
    }
    GlobalUnlock(mem);
    stream->lpVtbl->Release(stream);
    dispose((GpImage *)bmp);
    shutdown(token);
    free(rgb);
    FreeLibrary(dll);
    return out;
}
