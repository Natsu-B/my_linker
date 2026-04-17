#include "linux_stat.h"
#include "linux_syscall.h"

int fstat(int fd, struct stat *st) {
    struct linux_kernel_stat kst;
    long ret = linux_syscall2(LINUX_SYS_fstat, (long)fd, (long)&kst);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return -1;
    }
    linux_translate_stat(&kst, st);
    return 0;
}
