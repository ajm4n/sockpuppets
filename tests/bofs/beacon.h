#pragma once
#include <windows.h>

#define CALLBACK_OUTPUT     0x0
#define CALLBACK_OUTPUT_OEM 0x1e
#define CALLBACK_ERROR      0x0d

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, const char* data, int len);
extern void BeaconDataParse(datap* parser, char* buffer, int size);
extern int  BeaconDataInt(datap* parser);
extern short BeaconDataShort(datap* parser);
extern char* BeaconDataExtract(datap* parser, int* size);
