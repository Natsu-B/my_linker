#ifndef RUNTIME_LINUX_X86_64_NEWLIB_LINUX_SYSCALL_H
#define RUNTIME_LINUX_X86_64_NEWLIB_LINUX_SYSCALL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#define LINUX_SYS_read         0L
#define LINUX_SYS_write        1L
#define LINUX_SYS_open         2L
#define LINUX_SYS_close        3L
#define LINUX_SYS_stat         4L
#define LINUX_SYS_fstat        5L
#define LINUX_SYS_lseek        8L
#define LINUX_SYS_brk          12L
#define LINUX_SYS_ioctl        16L
#define LINUX_SYS_getpid       39L
#define LINUX_SYS_kill         62L
#define LINUX_SYS_rename       82L
#define LINUX_SYS_mkdir        83L
#define LINUX_SYS_link         86L
#define LINUX_SYS_unlink       87L
#define LINUX_SYS_gettimeofday 96L
#define LINUX_SYS_times        100L
#define LINUX_SYS_exit         60L
#define LINUX_SYS_exit_group   231L
#define LINUX_SYS_newfstatat   262L
#define LINUX_SYS_getrandom    318L

#define LINUX_AT_FDCWD         (-100)
#define LINUX_TCGETS           0x5401UL

static inline int linux_syscall_is_error(long ret) {
    return ret < 0 && ret >= -4095;
}

static inline int linux_set_errno_from_ret(long ret) {
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return -1;
    }
    return (int)ret;
}

static inline long linux_syscall0(long nr) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long linux_syscall1(long nr, long a1) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long linux_syscall2(long nr, long a1, long a2) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long linux_syscall3(long nr, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory");
    return ret;
}

static inline long linux_syscall4(long nr, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
        : "rcx", "r11", "memory");
    return ret;
}

#endif
