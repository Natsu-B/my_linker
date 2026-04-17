#include "linux_syscall.h"

#include <stddef.h>
#include <sys/types.h>

ssize_t read(int fd, void *buf, size_t count) {
    long ret = linux_syscall3(LINUX_SYS_read, (long)fd, (long)buf, (long)count);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return (ssize_t)-1;
    }
    return (ssize_t)ret;
}
