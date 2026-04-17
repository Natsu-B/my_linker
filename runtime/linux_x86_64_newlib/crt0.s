    .section .text.start, "ax", @progbits
    .globl _start
    .type _start, @function

    .extern main
    .extern exit
    .extern atexit
    .extern __libc_init_array
    .extern __libc_fini_array

_start:
    xorl    %ebp, %ebp

    mov     (%rsp), %r12
    lea     8(%rsp), %r13
    lea     16(%rsp,%r12,8), %r14

    andq    $-16, %rsp

    leaq    __libc_fini_array(%rip), %rdi
    call    atexit

    call    __libc_init_array

    mov     %r12, %rdi
    mov     %r13, %rsi
    mov     %r14, %rdx
    call    main

    mov     %eax, %edi
    call    exit

    ud2

    .globl _init
    .type _init, @function
_init:
    ret

    .globl _fini
    .type _fini, @function
_fini:
    ret

    .section .note.GNU-stack,"",@progbits
