#include "linux_syscall.h"

#include <fcntl.h>
#include <stdarg.h>

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    long ret = linux_syscall3(LINUX_SYS_open, (long)path, (long)flags, (long)mode);
    return linux_set_errno_from_ret(ret);
}
