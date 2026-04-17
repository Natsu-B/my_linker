#include "linux_syscall.h"

#include <sys/types.h>

off_t lseek(int fd, off_t offset, int whence) {
    long ret = linux_syscall3(LINUX_SYS_lseek, (long)fd, (long)offset, (long)whence);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return (off_t)-1;
    }
    return (off_t)ret;
}
