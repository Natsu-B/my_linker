#include "linux_syscall.h"

int isatty(int fd) {
    unsigned char termios_buf[256];
    long ret = linux_syscall3(
        LINUX_SYS_ioctl,
        (long)fd,
        (long)LINUX_TCGETS,
        (long)termios_buf);
    if (linux_syscall_is_error(ret)) {
        errno = (int)-ret;
        return 0;
    }
    return 1;
}
