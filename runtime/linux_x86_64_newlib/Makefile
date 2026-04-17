CC      ?= x86_64-elf-gcc
AR      ?= x86_64-elf-ar

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -Wall -Wextra -Werror
ASFLAGS ?= $(CFLAGS)
ARFLAGS := rcs

LIBSYS  := libsyscalls.a

SYSCALL_SRCS := \
	_exit.c \
	close.c \
	fstat.c \
	getentropy.c \
	getpid.c \
	gettimeofday.c \
	isatty.c \
	kill.c \
	link.c \
	lseek.c \
	mkdir.c \
	open.c \
	read.c \
	rename.c \
	sbrk.c \
	stat.c \
	times.c \
	unlink.c \
	write.c	\
	shim.c

SYSCALL_OBJS := $(SYSCALL_SRCS:.c=.o)

.PHONY: all clean

all: $(CRT0) $(LIBSYS)

$(CRT0): crt0.s
	$(CC) $(ASFLAGS) -c $< -o $@

$(LIBSYS): $(SYSCALL_OBJS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c linux_syscall.h linux_stat.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(CRT0) $(SYSCALL_OBJS) $(LIBSYS)
