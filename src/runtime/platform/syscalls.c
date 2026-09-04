// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Default platform beneath Picolibc. Capsule has no file descriptors,
// processes or wall clock, so OS-backed operations fail explicitly. Every
// definition is weak: a guest can provide a real in-memory adapter or a test
// double without rebuilding either Capsule or Picolibc.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CAPSULE_PLATFORM_WEAK __attribute__((weak))

// Picolibc calls this optional extension only for error numbers outside its
// own table. Returning null selects its standard "Unknown error" fallback.
CAPSULE_PLATFORM_WEAK char* _user_strerror(int error, int internal, int* stored_error) {
    (void)error;
    (void)internal;
    (void)stored_error;
    return NULL;
}

CAPSULE_PLATFORM_WEAK int open(const char* path, int flags, ...) {
    (void)path;
    (void)flags;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int close(int fd) {
    (void)fd;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK ssize_t read(int fd, void* buffer, size_t size) {
    (void)fd;
    (void)buffer;
    (void)size;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK ssize_t write(int fd, const void* buffer, size_t size) {
    (void)fd;
    (void)buffer;
    (void)size;
    errno = EBADF;
    return -1;
}

static int capsule_stream_get(FILE* stream) {
    (void)stream;
    unsigned char byte;
    ssize_t result = read(STDIN_FILENO, &byte, 1);
    if (result == 1) {
        return byte;
    }
    return result == 0 ? _FDEV_EOF : _FDEV_ERR;
}

static int capsule_stdout_put(char byte, FILE* stream) {
    (void)stream;
    return write(STDOUT_FILENO, &byte, 1) == 1 ? (unsigned char)byte : _FDEV_ERR;
}

static int capsule_stderr_put(char byte, FILE* stream) {
    (void)stream;
    return write(STDERR_FILENO, &byte, 1) == 1 ? (unsigned char)byte : _FDEV_ERR;
}

static int capsule_stream_flush(FILE* stream) {
    (void)stream;
    return 0;
}

static FILE capsule_stdin = FDEV_SETUP_STREAM(NULL, capsule_stream_get, capsule_stream_flush, _FDEV_SETUP_READ);
static FILE capsule_stdout = FDEV_SETUP_STREAM(capsule_stdout_put, NULL, capsule_stream_flush, _FDEV_SETUP_WRITE);
static FILE capsule_stderr = FDEV_SETUP_STREAM(capsule_stderr_put, NULL, capsule_stream_flush, _FDEV_SETUP_WRITE);

CAPSULE_PLATFORM_WEAK FILE* const stdin = &capsule_stdin;
CAPSULE_PLATFORM_WEAK FILE* const stdout = &capsule_stdout;
CAPSULE_PLATFORM_WEAK FILE* const stderr = &capsule_stderr;

CAPSULE_PLATFORM_WEAK off_t lseek(int fd, off_t offset, int whence) {
    (void)fd;
    (void)offset;
    (void)whence;
    errno = EBADF;
    return (off_t)-1;
}

CAPSULE_PLATFORM_WEAK int fstat(int fd, struct stat* status) {
    (void)fd;
    (void)status;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int isatty(int fd) {
    (void)fd;
    errno = EBADF;
    return 0;
}

CAPSULE_PLATFORM_WEAK int stat(const char* path, struct stat* status) {
    (void)path;
    (void)status;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int unlink(const char* path) {
    (void)path;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int link(const char* old_path, const char* new_path) {
    (void)old_path;
    (void)new_path;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int rename(const char* old_path, const char* new_path) {
    (void)old_path;
    (void)new_path;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK void* mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
    (void)address;
    (void)length;
    (void)protection;
    (void)flags;
    (void)fd;
    (void)offset;
    errno = ENOSYS;
    return MAP_FAILED;
}

CAPSULE_PLATFORM_WEAK int munmap(void* address, size_t length) {
    (void)address;
    (void)length;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int pipe(int fds[2]) {
    (void)fds;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK void* sbrk(ptrdiff_t increment) {
    (void)increment;
    errno = ENOSYS;
    return (void*)-1;
}

CAPSULE_PLATFORM_WEAK pid_t fork(void) {
    errno = ENOSYS;
    return (pid_t)-1;
}

CAPSULE_PLATFORM_WEAK int sigprocmask(int how, const sigset_t* set, sigset_t* old_set) {
    (void)how;
    (void)set;
    (void)old_set;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int raise(int signal) {
    (void)signal;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int execve(const char* path, char* const arguments[], char* const environment[]) {
    (void)path;
    (void)arguments;
    (void)environment;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK pid_t waitpid(pid_t process, int* status, int options) {
    (void)process;
    (void)status;
    (void)options;
    errno = ENOSYS;
    return (pid_t)-1;
}

CAPSULE_PLATFORM_WEAK int getentropy(void* buffer, size_t size) {
    (void)buffer;
    (void)size;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int gettimeofday(struct timeval* time, void* timezone) {
    (void)time;
    (void)timezone;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int clock_gettime(clockid_t clock, struct timespec* time) {
    (void)clock;
    (void)time;
    errno = ENOSYS;
    return -1;
}

// Without an environment or an operating-system timezone database, Capsule's
// default local timezone is UTC. Keep this platform policy below Picolibc so a
// program that supplies a real environment can override it together with the
// other weak OS interfaces. Picolibc still performs the calendar conversion.
CAPSULE_PLATFORM_WEAK struct tm* localtime_r(const time_t* time, struct tm* result) {
    return gmtime_r(time, result);
}

CAPSULE_PLATFORM_WEAK clock_t times(struct tms* times) {
    (void)times;
    errno = ENOSYS;
    return (clock_t)-1;
}

CAPSULE_PLATFORM_WEAK int nanosleep(const struct timespec* requested, struct timespec* remaining) {
    (void)requested;
    (void)remaining;
    errno = ENOSYS;
    return -1;
}
