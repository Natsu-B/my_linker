#include "linux_stat.h"
#include "linux_syscall.h"

int stat(const char *path, struct stat *st) {
    struct linux_kernel_stat kst;
    long ret = linux_syscall4(
        LINUX_SYS_newfstatat,
        (long)LINUX_AT_FDCWD,
        (long)path,
        (long)&kst,
        0);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return -1;
    }
    linux_translate_stat(&kst, st);
    return 0;
}
