/* Lab 7 - Fase 3 - Paso 5.3 de WazuhAlpine.pdf
 * Shim de compatibilidad glibc->musl para compilar el agente Wazuh 4.12 en Alpine.
 * Se copia a /root/wazuh/src/external/musl_compat/musl_compat.c y se compila con:
 *   gcc -c -fPIC musl_compat.c -o musl_compat.o
 * (transcrito del PDF corrigiendo comillas tipograficas que rompen el codigo)
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct random_data { unsigned int seed; };
int srandom_r(unsigned int seed, struct random_data *buf) {
    if (!buf) return -1;
    buf->seed = seed ? seed : 1;
    return 0;
}
int random_r(struct random_data *buf, int32_t *result) {
    if (!buf || !result) return -1;
    *result = (int32_t) rand_r(&buf->seed);
    return 0;
}
int initstate_r(unsigned int seed, char *statebuf, size_t statelen, struct random_data *buf) {
    (void) statebuf; (void) statelen;
    return srandom_r(seed, buf);
}

unsigned int gnu_dev_major(unsigned long long dev) { return major(dev); }
unsigned int gnu_dev_minor(unsigned long long dev) { return minor(dev); }
unsigned long long gnu_dev_makedev(unsigned int maj, unsigned int min) { return makedev(maj, min); }

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    return open(path, flags, mode);
}
int mkstemp64(char *tmpl) { return mkstemp(tmpl); }
int ftruncate64(int fd, off_t length) { return ftruncate(fd, length); }
int stat64(const char *path, struct stat *buf) { return stat(path, buf); }
int fstat64(int fd, struct stat *buf) { return fstat(fd, buf); }
int lstat64(const char *path, struct stat *buf) { return lstat(path, buf); }
off_t lseek64(int fd, off_t offset, int whence) { return lseek(fd, offset, whence); }
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) { return pread(fd, buf, count, offset); }
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) { return pwrite(fd, buf, count, offset); }
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return mmap(addr, length, prot, flags, fd, offset); }
int fseeko64(FILE *stream, off_t offset, int whence) { return fseeko(stream, offset, whence); }
off_t ftello64(FILE *stream) { return ftello(stream); }
FILE *fopen64(const char *path, const char *mode) { return fopen(path, mode); }
FILE *freopen64(const char *path, const char *mode, FILE *stream) { return freopen(path, mode, stream); }
FILE *tmpfile64(void) { return tmpfile(); }

char *__strtok_r(char *str, const char *delim, char **saveptr) { return strtok_r(str, delim, saveptr); }
char *__strdup(const char *s) { return strdup(s); }
void *__rawmemchr(const void *s, int c) { return memchr(s, c, (size_t)-1); }
int glob_pattern_p(const char *pattern, int quote) {
    for (const char *p = pattern; *p; p++) {
        if (*p == '\\' && quote) { if (*(p+1)) p++; continue; }
        if (*p == '*' || *p == '?' || *p == '[') return 1;
    }
    return 0;
}

/* Redirecciones explicitas para libucontext (no depender de sus alias weak) */
int libucontext_getcontext(void *ucp);
int libucontext_setcontext(const void *ucp);
int libucontext_swapcontext(void *oucp, const void *ucp);

__attribute__((visibility("default")))
int getcontext(void *ucp) {
    return libucontext_getcontext(ucp);
}
__attribute__((visibility("default")))
int setcontext(const void *ucp) {
    return libucontext_setcontext(ucp);
}
__attribute__((visibility("default")))
int swapcontext(void *oucp, const void *ucp) {
    return libucontext_swapcontext(oucp, ucp);
}
__asm__(
".text\n"
".global makecontext\n"
".type makecontext, @function\n"
"makecontext:\n"
"    jmp libucontext_makecontext\n"
);
