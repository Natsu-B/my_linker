#include "linux_syscall.h"

#include <sys/time.h>

int gettimeofday(struct timeval *tv, void *tz) {
    long ret = linux_syscall2(LINUX_SYS_gettimeofday, (long)tv, (long)tz);
    return linux_set_errno_from_ret(ret);
}
