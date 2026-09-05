// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Default platform beneath Picolibc. Capsule exposes the conventional three
// standard streams, but has no filesystem, processes or wall clock, so other
// OS-backed operations fail explicitly. Every definition is weak: a guest can
// provide a real in-memory adapter or a test double without rebuilding either
// Capsule or Picolibc.
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdio-bufio.h>
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

CAPSULE_PLATFORM_WEAK int fcntl(int fd, int command, ...) {
    (void)fd;
    (void)command;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int close(int fd) {
    (void)fd;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int dup2(int old_fd, int new_fd) {
    (void)old_fd;
    (void)new_fd;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int dup(int fd) {
    (void)fd;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int fsync(int fd) {
    (void)fd;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int fdatasync(int fd) {
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

// Picolibc's descriptor-backed stream is also what makes fileno() report the
// conventional 0/1/2 identities. The syscall functions remain weak hooks for
// an embedding. Streams start unbuffered; setvbuf() may allocate a buffer.
static struct __file_bufio capsule_stdin = FDEV_SETUP_BUFIO(STDIN_FILENO, NULL, 0, read, NULL, lseek, NULL, __SRD, 0);
static struct __file_bufio capsule_stdout = FDEV_SETUP_BUFIO(STDOUT_FILENO, NULL, 0, NULL, write, lseek, NULL, __SWR, 0);
static struct __file_bufio capsule_stderr = FDEV_SETUP_BUFIO(STDERR_FILENO, NULL, 0, NULL, write, lseek, NULL, __SWR, 0);

CAPSULE_PLATFORM_WEAK FILE* const stdin = (FILE*)&capsule_stdin;
CAPSULE_PLATFORM_WEAK FILE* const stdout = (FILE*)&capsule_stdout;
CAPSULE_PLATFORM_WEAK FILE* const stderr = (FILE*)&capsule_stderr;

CAPSULE_PLATFORM_WEAK off_t lseek(int fd, off_t offset, int whence) {
    (void)fd;
    (void)offset;
    (void)whence;
    errno = EBADF;
    return (off_t)-1;
}

CAPSULE_PLATFORM_WEAK int fstat(int fd, struct stat* status) {
    if (fd >= STDIN_FILENO && fd <= STDERR_FILENO && status) {
        *status = (struct stat){0};
        status->st_mode = S_IFCHR | S_IRUSR | S_IWUSR;
        status->st_nlink = 1;
        return 0;
    }
    if (!status) {
        errno = EFAULT;
        return -1;
    }
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int isatty(int fd) {
    errno = fd >= STDIN_FILENO && fd <= STDERR_FILENO ? ENOTTY : EBADF;
    return 0;
}

CAPSULE_PLATFORM_WEAK int stat(const char* path, struct stat* status) {
    (void)path;
    (void)status;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int lstat(const char* path, struct stat* status) {
    (void)path;
    (void)status;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int access(const char* path, int mode) {
    (void)path;
    (void)mode;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int chdir(const char* path) {
    (void)path;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int chroot(const char* path) {
    (void)path;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int fchdir(int fd) {
    (void)fd;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK char* getcwd(char* buffer, size_t size) {
    (void)buffer;
    (void)size;
    errno = ENOSYS;
    return NULL;
}

CAPSULE_PLATFORM_WEAK int mkdir(const char* path, mode_t mode) {
    (void)path;
    (void)mode;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int rmdir(const char* path) {
    (void)path;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int symlink(const char* target, const char* path) {
    (void)target;
    (void)path;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK DIR* opendir(const char* path) {
    (void)path;
    errno = ENOSYS;
    return NULL;
}

CAPSULE_PLATFORM_WEAK int closedir(DIR* directory) {
    (void)directory;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK struct dirent* readdir(DIR* directory) {
    (void)directory;
    errno = EBADF;
    return NULL;
}

CAPSULE_PLATFORM_WEAK int dirfd(DIR* directory) {
    (void)directory;
    errno = EBADF;
    return -1;
}

CAPSULE_PLATFORM_WEAK int utimensat(int directory, const char* path, const struct timespec times[2], int flags) {
    (void)directory;
    (void)path;
    (void)times;
    (void)flags;
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

CAPSULE_PLATFORM_WEAK pid_t getpid(void) {
    errno = ENOSYS;
    return (pid_t)-1;
}

// The BPF ABI and the fixed-memory fallback both use 4 KiB as their minimum
// mapping granularity. Consumers which expose a different virtual-memory
// model can override this together with mmap().
CAPSULE_PLATFORM_WEAK int getpagesize(void) {
    return 4096;
}

CAPSULE_PLATFORM_WEAK mode_t umask(mode_t mask) {
    (void)mask;
    errno = ENOSYS;
    return (mode_t)-1;
}

CAPSULE_PLATFORM_WEAK int pause(void) {
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int sched_yield(void) {
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK int setgroups(int count, const gid_t* groups) {
    (void)count;
    (void)groups;
    errno = ENOSYS;
    return -1;
}

CAPSULE_PLATFORM_WEAK long sysconf(int name) {
    (void)name;
    errno = ENOSYS;
    return -1;
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

CAPSULE_PLATFORM_WEAK _sig_func_ptr signal(int number, _sig_func_ptr handler) {
    (void)number;
    (void)handler;
    errno = ENOSYS;
    return SIG_ERR;
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

CAPSULE_PLATFORM_WEAK int clock_getres(clockid_t clock, struct timespec* resolution) {
    (void)clock;
    (void)resolution;
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
