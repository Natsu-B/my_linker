#include "linux_syscall.h"

int close(int fd) {
    long ret = linux_syscall1(LINUX_SYS_close, (long)fd);
    return linux_set_errno_from_ret(ret);
}
