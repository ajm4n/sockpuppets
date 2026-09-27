#include <windows.h>
#include <gdiplus.h>
#include <stdlib.h>
#include <string.h>

using namespace Gdiplus;

extern "C" unsigned char *hd_jpeg(const unsigned char *bgr, int w, int h, int stride, int quality, size_t *out_len) {
    if (!bgr || w < 1 || h < 1 || !out_len) return NULL;
    *out_len = 0;
    GdiplusStartupInput in;
    ULONG_PTR token = 0;
    if (GdiplusStartup(&token, &in, NULL) != Ok) return NULL;
    Bitmap bmp(w, h, PixelFormat24bppRGB);
    BitmapData data;
    Rect rect(0, 0, w, h);
    if (bmp.LockBits(&rect, ImageLockModeWrite, PixelFormat24bppRGB, &data) != Ok) {
        GdiplusShutdown(token);
        return NULL;
    }
    for (int y = 0; y < h; y++) {
        unsigned char *dst = (unsigned char *)data.Scan0 + y * data.Stride;
        const unsigned char *src = bgr + y * stride;
        for (int x = 0; x < w; x++) {
            dst[x * 3 + 0] = src[x * 3 + 2];
            dst[x * 3 + 1] = src[x * 3 + 1];
            dst[x * 3 + 2] = src[x * 3 + 0];
        }
    }
    bmp.UnlockBits(&data);
    UINT count = 0, bytes = 0;
    GetImageEncodersSize(&count, &bytes);
    ImageCodecInfo *info = (ImageCodecInfo *)malloc(bytes);
    CLSID jpeg = {};
    int found = 0;
    if (info && GetImageEncoders(count, bytes, info) == Ok) {
        for (UINT i = 0; i < count; i++) {
            if (wcscmp(info[i].MimeType, L"image/jpeg") == 0) {
                jpeg = info[i].Clsid;
                found = 1;
                break;
            }
        }
    }
    free(info);
    if (!found) {
        GdiplusShutdown(token);
        return NULL;
    }
    EncoderParameters param;
    param.Count = 1;
    param.Parameter[0].Guid = EncoderQuality;
    param.Parameter[0].Type = EncoderParameterValueTypeLong;
    param.Parameter[0].NumberOfValues = 1;
    ULONG q = quality < 30 ? 30 : (ULONG)quality;
    param.Parameter[0].Value = &q;
    IStream *stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) {
        GdiplusShutdown(token);
        return NULL;
    }
    if (bmp.Save(stream, &jpeg, &param) != Ok) {
        stream->Release();
        GdiplusShutdown(token);
        return NULL;
    }
    HGLOBAL mem = NULL;
    GetHGlobalFromStream(stream, &mem);
    SIZE_T n = GlobalSize(mem);
    void *src = GlobalLock(mem);
    unsigned char *out = (unsigned char *)malloc(n);
    if (out && src) memcpy(out, src, n);
    GlobalUnlock(mem);
    stream->Release();
    GdiplusShutdown(token);
    if (!out) return NULL;
    *out_len = n;
    return out;
}
