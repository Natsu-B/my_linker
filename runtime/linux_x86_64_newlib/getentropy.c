#include "linux_syscall.h"

#include <errno.h>
#include <stddef.h>

int getentropy(void *buffer, size_t length) {
    unsigned char *out = (unsigned char *)buffer;
    size_t done = 0;

    while (done < length) {
        long ret = linux_syscall3(
            LINUX_SYS_getrandom,
            (long)(out + done),
            (long)(length - done),
            0L);
        if (linux_syscall_is_error(ret)) {
            errno = (int)-ret;
            return -1;
        }
        if (ret == 0) {
            errno = EIO;
            return -1;
        }
        done += (size_t)ret;
    }

    return 0;
}
