#include "linux_syscall.h"

#include <sys/types.h>
#include <sys/stat.h>

int mkdir(const char *path, mode_t mode) {
    long ret = linux_syscall2(LINUX_SYS_mkdir, (long)path, (long)mode);
    return linux_set_errno_from_ret(ret);
}
