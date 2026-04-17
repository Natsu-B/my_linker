#include "linux_syscall.h"

#include <sys/times.h>

clock_t times(struct tms *buf) {
    long ret = linux_syscall1(LINUX_SYS_times, (long)buf);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return (clock_t)-1;
    }
    return (clock_t)ret;
}
