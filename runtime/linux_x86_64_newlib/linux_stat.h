#ifndef RUNTIME_LINUX_X86_64_NEWLIB_LINUX_STAT_H
#define RUNTIME_LINUX_X86_64_NEWLIB_LINUX_STAT_H

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

struct linux_kernel_timespec {
    long tv_sec;
    long tv_nsec;
};

struct linux_kernel_stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    unsigned int st_mode;
    unsigned int st_uid;
    unsigned int st_gid;
    unsigned int __pad0;
    unsigned long st_rdev;
    long st_size;
    long st_blksize;
    long st_blocks;
    struct linux_kernel_timespec st_atim;
    struct linux_kernel_timespec st_mtim;
    struct linux_kernel_timespec st_ctim;
    long __unused[3];
};

static inline void linux_translate_stat(const struct linux_kernel_stat *src, struct stat *dst) {
    memset(dst, 0, sizeof(*dst));
    dst->st_dev = src->st_dev;
    dst->st_ino = src->st_ino;
    dst->st_mode = src->st_mode;
    dst->st_nlink = src->st_nlink;
    dst->st_uid = src->st_uid;
    dst->st_gid = src->st_gid;
    dst->st_rdev = src->st_rdev;
    dst->st_size = src->st_size;
    dst->st_blksize = src->st_blksize;
    dst->st_blocks = src->st_blocks;
}

#endif
