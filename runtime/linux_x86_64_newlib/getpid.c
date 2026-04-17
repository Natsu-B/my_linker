#include "linux_syscall.h"

#include <sys/types.h>

pid_t getpid(void) {
    long ret = linux_syscall0(LINUX_SYS_getpid);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return (pid_t)-1;
    }
    return (pid_t)ret;
}
