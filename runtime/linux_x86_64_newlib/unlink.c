#include "linux_syscall.h"

int unlink(const char *path) {
    long ret = linux_syscall1(LINUX_SYS_unlink, (long)path);
    return linux_set_errno_from_ret(ret);
}
