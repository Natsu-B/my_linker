#include "linux_syscall.h"

void _exit(int status) {
    (void)linux_syscall1(LINUX_SYS_exit_group, (long)status);
    (void)linux_syscall1(LINUX_SYS_exit, (long)status);
    for (;;) {
        __asm__ volatile ("pause");
    }
}
