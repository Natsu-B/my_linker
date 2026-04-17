#include "linux_syscall.h"

#include <signal.h>
#include <sys/types.h>

int kill(pid_t pid, int sig) {
    long ret = linux_syscall2(LINUX_SYS_kill, (long)pid, (long)sig);
    return linux_set_errno_from_ret(ret);
}
