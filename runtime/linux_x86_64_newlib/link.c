#include "linux_syscall.h"

int link(const char *oldpath, const char *newpath) {
    long ret = linux_syscall2(LINUX_SYS_link, (long)oldpath, (long)newpath);
    return linux_set_errno_from_ret(ret);
}
