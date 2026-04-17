#include "linux_syscall.h"

#include <errno.h>
#include <stddef.h>

void *sbrk(ptrdiff_t incr) {
    static long current_brk;

    if (current_brk == 0) {
        long initial = linux_syscall1(LINUX_SYS_brk, 0);
        if (linux_syscall_is_error(initial)) {
            errno = (int)-initial;
            return (void *)-1;
        }
        current_brk = initial;
    }

    long old_brk = current_brk;
    long new_brk = old_brk + (long)incr;
    long ret = linux_syscall1(LINUX_SYS_brk, new_brk);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return (void *)-1;
    }
    if (ret < new_brk) {
        errno = ENOMEM;
        return (void *)-1;
    }

    current_brk = ret;
    return (void *)old_brk;
}
