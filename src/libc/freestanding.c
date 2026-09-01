// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The C library, for a machine with no operating system under it.
//
// Every program compiled into the kernel needs some of this, and none of it
// is program-specific, so it lives here rather than being retyped per port.
// Three groups:
//   - real implementations (string and memory routines),
//   - a synchronized TLSF allocator over the configured Capsule heap,
//   - honest failures for everything that would need an OS (files, time,
//     processes) — they return errors rather than pretending to work.
// Only the guest ABI is needed here; the single-include runtime header that
// owns maps and globals remains in the program's sectioned translation unit.
#include "bpf_capsule.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// ------------------------------------------------------------ memory, strings
// Ordinary out-of-line functions. A single shared copy is reached with arena
// pointers from the program and map pointers from the driver; the verifier
// rejects one instruction serving both ("same insn cannot be used with
// different pointers"). That collision came from codegen tail merging, which
// is disabled globally, so these need no per-call-site duplication.
// Bulk memory runs as bounded native chunk kernels below managed drivers.
// Each kernel is a nosuspend subprogram the verifier checks exactly once,
// with constant-bounded loops; the drivers walk arbitrary lengths by
// looping those bounded chunks. Expanding the loops inline at every call
// site instead pays the loop's verifier cost per site — expanded
// memcpy/memset was 72% of SQLite's object and pushed it past the
// one-million-instruction verifier budget.
// The kernels copy one complete chunk each with exact-trip loops — the shape
// the nosuspend proof accepts — and the drivers' own managed loops handle the
// sub-chunk tail, whose verifier cost is likewise paid once.
#define BPF_MEM_CHUNK 512ul
typedef unsigned long long __attribute__((may_alias, aligned(1))) bpf_mem_word;

CAPSULE_NOSUSPEND unsigned long long __bpf_memcpy_chunk(unsigned long long dst, unsigned long long src) {
    bpf_mem_word* d = (bpf_mem_word*)(unsigned long)dst;
    const bpf_mem_word* s = (const bpf_mem_word*)(unsigned long)src;
    for (unsigned long i = 0; i < BPF_MEM_CHUNK / 8; i++) {
        d[i] = s[i];
    }
    return 0;
}

// The descending twin for overlapping backward moves: copies the chunk
// highest word first.
CAPSULE_NOSUSPEND unsigned long long __bpf_memmove_chunk(unsigned long long dst, unsigned long long src) {
    bpf_mem_word* d = (bpf_mem_word*)(unsigned long)dst;
    const bpf_mem_word* s = (const bpf_mem_word*)(unsigned long)src;
    for (unsigned long i = 0; i < BPF_MEM_CHUNK / 8; i++) {
        unsigned long at = BPF_MEM_CHUNK / 8 - 1 - i;
        d[at] = s[at];
    }
    return 0;
}

CAPSULE_NOSUSPEND unsigned long long __bpf_memset_chunk(unsigned long long dst, unsigned long long value) {
    bpf_mem_word* d = (bpf_mem_word*)(unsigned long)dst;
    unsigned long long word = (value & 0xff) * 0x0101010101010101ull;
    for (unsigned long i = 0; i < BPF_MEM_CHUNK / 8; i++) {
        d[i] = word;
    }
    return 0;
}

__attribute__((noinline)) void* memcpy(void* d, const void* s, unsigned long n) {
    unsigned long long dw = (unsigned long long)(unsigned long)d;
    unsigned long long sw = (unsigned long long)(unsigned long)s;
    while (n >= BPF_MEM_CHUNK) {
        __bpf_memcpy_chunk(dw, sw);
        dw += BPF_MEM_CHUNK;
        sw += BPF_MEM_CHUNK;
        n -= BPF_MEM_CHUNK;
    }
    char* dp = (char*)(unsigned long)dw;
    const char* sp = (const char*)(unsigned long)sw;
    for (unsigned long i = 0; i < n; i++) {
        dp[i] = sp[i];
    }
    return d;
}
__attribute__((noinline)) void* memmove(void* d, const void* s, unsigned long n) {
    if ((uintptr_t)d < (uintptr_t)s) {
        return memcpy(d, s, n);
    }
    char* dp = (char*)d;
    const char* sp = (const char*)s;
    while (n && (n & (BPF_MEM_CHUNK - 1))) {
        n--;
        dp[n] = sp[n];
    }
    while (n) {
        n -= BPF_MEM_CHUNK;
        __bpf_memmove_chunk((unsigned long long)(unsigned long)(dp + n), (unsigned long long)(unsigned long)(sp + n));
    }
    return d;
}
__attribute__((noinline)) void* memset(void* d, int c, unsigned long n) {
    unsigned long long dw = (unsigned long long)(unsigned long)d;
    while (n >= BPF_MEM_CHUNK) {
        __bpf_memset_chunk(dw, (unsigned long long)(unsigned char)c);
        dw += BPF_MEM_CHUNK;
        n -= BPF_MEM_CHUNK;
    }
    char* dp = (char*)(unsigned long)dw;
    for (unsigned long i = 0; i < n; i++) {
        dp[i] = (char)c;
    }
    return d;
}
__attribute__((noinline)) int memcmp(const void* a, const void* b, unsigned long n) {
    const unsigned char* x = a;
    const unsigned char* y = b;
    for (unsigned long i = 0; i < n; i++) {
        if (x[i] != y[i]) {
            return x[i] < y[i] ? -1 : 1;
        }
    }
    return 0;
}
__attribute__((noinline)) void* memchr(const void* s, int c, unsigned long n) {
    const unsigned char* p = s;
    for (unsigned long i = 0; i < n; i++) {
        if (p[i] == (unsigned char)c) {
            return (void*)&p[i];
        }
    }
    return 0;
}
__attribute__((noinline)) unsigned long strlen(const char* s) {
    unsigned long n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}
__attribute__((noinline)) int strcmp(const char* a, const char* b) {
    unsigned long i = 0;
    for (; a[i] && a[i] == b[i]; i++) {
    }
    return (unsigned char)a[i] - (unsigned char)b[i];
}
int strcoll(const char* a, const char* b) {
    return strcmp(a, b);
}
__attribute__((noinline)) int strncmp(const char* a, const char* b, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return (unsigned char)a[i] - (unsigned char)b[i];
        }
        if (!a[i]) {
            return 0;
        }
    }
    return 0;
}
__attribute__((noinline)) char* strcpy(char* d, const char* s) {
    unsigned long i = 0;
    for (; s[i]; i++) {
        d[i] = s[i];
    }
    d[i] = 0;
    return d;
}
__attribute__((noinline)) char* strncpy(char* d, const char* s, unsigned long n) {
    unsigned long i = 0;
    for (; i < n && s[i]; i++) {
        d[i] = s[i];
    }
    for (; i < n; i++) {
        d[i] = 0;
    }
    return d;
}
char* strcat(char* d, const char* s) {
    unsigned long n = strlen(d), i = 0;
    for (; s[i]; i++) {
        d[n + i] = s[i];
    }
    d[n + i] = 0;
    return d;
}
__attribute__((noinline)) char* strchr(const char* s, int c) {
    for (unsigned long i = 0;; i++) {
        if (s[i] == (char)c) {
            return (char*)&s[i];
        }
        if (!s[i]) {
            return 0;
        }
    }
}
__attribute__((noinline)) char* strrchr(const char* s, int c) {
    char* last = 0;
    for (unsigned long i = 0;; i++) {
        if (s[i] == (char)c) {
            last = (char*)&s[i];
        }
        if (!s[i]) {
            return last;
        }
    }
}
unsigned long strspn(const char* s, const char* accept) {
    unsigned long n = 0;
    for (; s[n]; n++) {
        const char* a = accept;
        for (; *a && *a != s[n]; a++) {
        }
        if (!*a) {
            break;
        }
    }
    return n;
}
unsigned long strcspn(const char* s, const char* reject) {
    unsigned long n = 0;
    for (; s[n]; n++) {
        for (const char* r = reject; *r; r++) {
            if (*r == s[n]) {
                return n;
            }
        }
    }
    return n;
}
char* strpbrk(const char* s, const char* accept) {
    for (unsigned long i = 0; s[i]; i++) {
        for (const char* a = accept; *a; a++) {
            if (*a == s[i]) {
                return (char*)&s[i];
            }
        }
    }
    return 0;
}
char* strstr(const char* h, const char* n) {
    unsigned long ln = strlen(n);
    if (!ln) {
        return (char*)h;
    }
    for (unsigned long i = 0; h[i]; i++) {
        if (!strncmp(h + i, n, ln)) {
            return (char*)&h[i];
        }
    }
    return 0;
}
char* strerror(int e) {
    switch (e) {
        case 0:
            return "Success";
        case EINTR:
            return "Interrupted system call";
        case ENOENT:
            return "No such file or directory";
        case EBADF:
            return "Bad file descriptor";
        case ENOMEM:
            return "Cannot allocate memory";
        case EINVAL:
            return "Invalid argument";
        case EDOM:
            return "Numerical argument out of domain";
        case ERANGE:
            return "Numerical result out of range";
        case ENOSYS:
            return "Function not implemented";
        case EOVERFLOW:
            return "Value too large for defined data type";
        default:
            return "Unknown error";
    }
}

// ------------------------------------------------------------------ allocator
//
// Allocation is TLSF (see thirdparty/tlsf/): two-level segregated
// fit and O(1) malloc/free over the load-time-sized Capsule heap.
#include "tlsf.h"

static tlsf_t fs_tlsf;

// Modern BPF JITs implement compare-exchange. Keep the mutex in native map
// storage so taking it is one BPF atomic rather than a HASH update followed
// by a HASH delete for every allocator operation. It cannot live in Capsule
// memory: managed compare-exchange is deliberately unsupported.
#if BPF_CAPSULE_FEATURE_FULL_ATOMICS
static volatile unsigned int fs_allocator_lock_word SEC(".bss.fsalloc");
#else
// Linux 5.15 verifies the modern atomic encodings but old arm64 JITs only
// implement non-fetching XADD and otherwise fall the complete program back to
// the interpreter. A single-entry HASH is the kernel's native atomic
// test-and-set on that tier. This cost stays entirely at allocator entry/exit;
// generated application code and memory accesses are unchanged.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned int);
} fs_allocator_lease SEC(".maps");
#endif

#define FS_ALLOCATOR_BUSY (~0ull)
#define FS_ALLOCATOR_ERROR (~1ull)

static __attribute__((always_inline)) int fs_try_lock(void) {
#if BPF_CAPSULE_FEATURE_FULL_ATOMICS
    unsigned int expected = 0;
    return __atomic_compare_exchange_n(&fs_allocator_lock_word, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
#else
    unsigned int key = 0;
    unsigned int value = 1;
    return bpf_map_update_elem(&fs_allocator_lease, &key, &value, BPF_NOEXIST) == 0;
#endif
}

static __attribute__((always_inline)) int fs_unlock(void) {
#if BPF_CAPSULE_FEATURE_FULL_ATOMICS
    return __atomic_exchange_n(&fs_allocator_lock_word, 0, __ATOMIC_SEQ_CST) == 1;
#else
    unsigned int key = 0;
    return bpf_map_delete_elem(&fs_allocator_lease, &key) == 0;
#endif
}

static __attribute__((always_inline)) int fs_setup(void) {
    unsigned long heap_size = capsule_heap_size();
    unsigned long minimum = tlsf_size() + tlsf_pool_overhead() + tlsf_block_size_min();
    if (heap_size < minimum) {
        return 0;
    }
    fs_tlsf = tlsf_create_with_pool(capsule_heap_start(), heap_size);
    return fs_tlsf != 0;
}

// These four scalar-ABI operations are compiler-enforced no-suspend islands.
// A busy lease returns without touching TLSF; the ordinary managed wrapper
// retries and may suspend there. Once an island acquires the lease it performs
// the complete metadata operation and releases it in the same BPF invocation.
// The compiler rejects any virtualized backedge or managed call that survives
// inside a CAPSULE_NOSUSPEND function.
CAPSULE_NOSUSPEND unsigned long long __bpf_allocator_malloc(unsigned long n) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    if (!fs_tlsf && !fs_setup()) {
        return fs_unlock() ? 0 : FS_ALLOCATOR_ERROR;
    }
    void* result = tlsf_malloc(fs_tlsf, n);
    return fs_unlock() ? (unsigned long long)(unsigned long)result : FS_ALLOCATOR_ERROR;
}

CAPSULE_NOSUSPEND unsigned long long __bpf_allocator_free(unsigned long address) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    if (fs_tlsf) {
        tlsf_free(fs_tlsf, (void*)address);
    }
    return fs_unlock() ? 0 : FS_ALLOCATOR_ERROR;
}

CAPSULE_NOSUSPEND unsigned long long __bpf_allocator_size(unsigned long address) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    unsigned long result = fs_tlsf ? tlsf_block_size((void*)address) : 0;
    return fs_unlock() ? result : FS_ALLOCATOR_ERROR;
}

CAPSULE_NOSUSPEND unsigned long long __bpf_allocator_memalign(unsigned long align, unsigned long n) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    if (!fs_tlsf && !fs_setup()) {
        return fs_unlock() ? 0 : FS_ALLOCATOR_ERROR;
    }
    void* result = tlsf_memalign(fs_tlsf, align, n);
    return fs_unlock() ? (unsigned long long)(unsigned long)result : FS_ALLOCATOR_ERROR;
}

void* malloc(unsigned long n) {
    unsigned long long result;
    do {
        result = __bpf_allocator_malloc(n);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
    if (!result) {
        errno = ENOMEM;
    }
    return (void*)(unsigned long)result;
}

void free(void* p) {
    if (!p) {
        return;
    }
    unsigned long long result;
    do {
        result = __bpf_allocator_free((unsigned long)p);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
}

void* calloc(unsigned long n, unsigned long sz) {
    if (sz && n > ~0ul / sz) {
        errno = ENOMEM;
        return 0;
    }
    unsigned long total = n * sz;
    void* p = malloc(total);
    if (p) {
        memset(p, 0, total);
    }
    return p;
}

unsigned long malloc_usable_size(void* p) {
    if (!p) {
        return 0;
    }
    unsigned long long result;
    do {
        result = __bpf_allocator_size((unsigned long)p);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
    return result;
}

void* realloc(void* p, unsigned long n) {
    if (!p) {
        return malloc(n);
    }
    if (!n) {
        free(p);
        return 0;
    }
    unsigned long old_size = malloc_usable_size(p);
    if (old_size >= n) {
        return p;
    }
    void* replacement = malloc(n);
    if (!replacement) {
        return 0;
    }
    memcpy(replacement, p, old_size);
    free(p);
    return replacement;
}

// malloc's blocks are 8-byte aligned; callers with stricter needs (Rust's
// GlobalAlloc contract, for one) go through TLSF's aligned path. The result
// is an ordinary block, so free() takes it back like any other.
void* memalign(unsigned long align, unsigned long n) {
    unsigned long long result;
    do {
        result = __bpf_allocator_memalign(align, n);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
    if (!result) {
        errno = ENOMEM;
    }
    return (void*)(unsigned long)result;
}
// -------------------------------------------------------------- conversions
int abs(int v) {
    return v < 0 ? -v : v;
}

static int fs_digit(int c, int base) {
    int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'z' ? c - 'a' + 10 : c >= 'A' && c <= 'Z' ? c - 'A' + 10 : 99;
    return v < base ? v : -1;
}

struct fs_integer_parse {
    const char* end;
    unsigned long long value;
    int negative;
    int any;
    int overflow;
};

static struct fs_integer_parse fs_parse_integer(const char* s, int base, unsigned long long limit) {
    struct fs_integer_parse result = {.end = s};
    const char* p = s;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    result.negative = *p == '-';
    if (*p == '-' || *p == '+') {
        p++;
    }
    if (base != 0 && (base < 2 || base > 36)) {
        errno = EINVAL;
        return result;
    }
    if (base == 0) {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') && fs_digit(p[2], 16) >= 0) {
            base = 16;
            p += 2;
        } else if (p[0] == '0') {
            base = 8;
        } else {
            base = 10;
        }
    } else if (base == 16 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X') && fs_digit(p[2], 16) >= 0) {
        p += 2;
    }

    unsigned long long cutoff = limit / (unsigned)base;
    unsigned int cutlim = (unsigned int)(limit % (unsigned)base);
    for (int digit; (digit = fs_digit((unsigned char)*p, base)) >= 0; p++) {
        result.any = 1;
        if (result.value > cutoff || (result.value == cutoff && (unsigned int)digit > cutlim)) {
            result.overflow = 1;
            result.value = limit;
        } else if (!result.overflow) {
            result.value = result.value * (unsigned)base + (unsigned)digit;
        }
    }
    result.end = result.any ? p : s;
    return result;
}

long strtol(const char* s, char** end, int base) {
    const unsigned long long positive_limit = (unsigned long long)(~0ul >> 1);
    struct fs_integer_parse parsed = fs_parse_integer(s, base, positive_limit + 1u);
    if (end) {
        *end = (char*)parsed.end;
    }
    if (!parsed.any) {
        return 0;
    }
    unsigned long long limit = parsed.negative ? positive_limit + 1u : positive_limit;
    if (parsed.overflow || parsed.value > limit) {
        errno = ERANGE;
        return parsed.negative ? (long)(~0ul << (sizeof(unsigned long) * 8u - 1u)) : (long)positive_limit;
    }
    if (!parsed.negative) {
        return (long)parsed.value;
    }
    return parsed.value == positive_limit + 1u ? (long)(~0ul << (sizeof(unsigned long) * 8u - 1u)) : -(long)parsed.value;
}
unsigned long strtoul(const char* s, char** end, int base) {
    struct fs_integer_parse parsed = fs_parse_integer(s, base, ~0ull);
    if (end) {
        *end = (char*)parsed.end;
    }
    if (parsed.overflow) {
        errno = ERANGE;
        return ~0ul;
    }
    unsigned long value = (unsigned long)parsed.value;
    return parsed.negative ? 0ul - value : value;
}

void qsort(void* base, unsigned long n, unsigned long sz, int (*cmp)(const void*, const void*)) {
    // Insertion sort: the call sites here sort small arrays, and a simple
    // algorithm keeps the managed call graph shallow.
    unsigned char* a = base;
    for (unsigned long i = 1; i < n; i++) {
        for (unsigned long j = i; j > 0 && cmp(a + (j - 1) * sz, a + j * sz) > 0; j--) {
            for (unsigned long k = 0; k < sz; k++) {
                unsigned char t = a[(j - 1) * sz + k];
                a[(j - 1) * sz + k] = a[j * sz + k];
                a[j * sz + k] = t;
            }
        }
    }
}

// ------------------------------------------------------------------- ctype
int isdigit(int c) {
    return c >= '0' && c <= '9';
}
int isupper(int c) {
    return c >= 'A' && c <= 'Z';
}
int islower(int c) {
    return c >= 'a' && c <= 'z';
}
int isalpha(int c) {
    return isupper(c) || islower(c);
}
int isalnum(int c) {
    return isalpha(c) || isdigit(c);
}
int isspace(int c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}
int iscntrl(int c) {
    return (unsigned)c < 32 || c == 127;
}
int isgraph(int c) {
    return c > 32 && c < 127;
}
int isprint(int c) {
    return c >= 32 && c < 127;
}
int ispunct(int c) {
    return isgraph(c) && !isalnum(c);
}
int isxdigit(int c) {
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
int toupper(int c) {
    return islower(c) ? c - 'a' + 'A' : c;
}
int tolower(int c) {
    return isupper(c) ? c - 'A' + 'a' : c;
}

// ------------------------------------------------- no operating system here
// A continuation belongs to a Capsule fiber, not to the CPU on which one
// physical step happens to execute. Keep errno with that fiber so concurrent
// calls and cross-CPU resumes cannot observe each other's library failures.
static int fs_errno[BPF_CAPSULE_MAX_FIBERS];

int* __bpf_capsule_errno_location(void) {
    unsigned int fiber = capsule_fiber_index();
    if (fiber >= BPF_CAPSULE_MAX_FIBERS) {
        __bpf_capsule_exit(CAPSULE_ERROR_TRAP);
    }
    return &fs_errno[fiber];
}

struct _FILE {
    int dummy;
};
static struct _FILE fs_null;
FILE* stdin = &fs_null;
FILE* stdout = &fs_null;
FILE* stderr = &fs_null;

FILE* fopen(const char* p, const char* m) {
    (void)p;
    (void)m;
    errno = ENOSYS;
    return 0;
}
FILE* freopen(const char* p, const char* m, FILE* f) {
    (void)p;
    (void)m;
    (void)f;
    errno = ENOSYS;
    return 0;
}
FILE* tmpfile(void) {
    errno = ENOSYS;
    return 0;
}
int fclose(FILE* f) {
    (void)f;
    errno = EBADF;
    return EOF;
}
int fflush(FILE* f) {
    (void)f;
    errno = EBADF;
    return EOF;
}
unsigned long fread(void* p, unsigned long sz, unsigned long n, FILE* f) {
    (void)p;
    (void)sz;
    (void)n;
    (void)f;
    errno = EBADF;
    return 0;
}
unsigned long fwrite(const void* p, unsigned long sz, unsigned long n, FILE* f) {
    (void)p;
    (void)sz;
    (void)n;
    (void)f;
    errno = EBADF;
    return 0;
}
int fputs(const char* s, FILE* f) {
    (void)s;
    (void)f;
    errno = EBADF;
    return EOF;
}
int fputc(int c, FILE* f) {
    (void)c;
    (void)f;
    errno = EBADF;
    return EOF;
}
char* fgets(char* s, int n, FILE* f) {
    (void)s;
    (void)n;
    (void)f;
    errno = EBADF;
    return 0;
}
int getc(FILE* f) {
    (void)f;
    errno = EBADF;
    return EOF;
}
int ungetc(int c, FILE* f) {
    (void)c;
    (void)f;
    errno = EBADF;
    return EOF;
}
int ferror(FILE* f) {
    (void)f;
    return 1;
}
int feof(FILE* f) {
    (void)f;
    return 0;
}
void clearerr(FILE* f) {
    (void)f;
}
int setvbuf(FILE* f, char* b, int m, unsigned long s) {
    (void)f;
    (void)b;
    (void)m;
    (void)s;
    errno = EBADF;
    return -1;
}
int fseek(FILE* f, long o, int w) {
    (void)f;
    (void)o;
    (void)w;
    errno = EBADF;
    return -1;
}
long ftell(FILE* f) {
    (void)f;
    errno = EBADF;
    return -1;
}
int remove(const char* p) {
    (void)p;
    errno = ENOSYS;
    return -1;
}
int rename(const char* a, const char* b) {
    (void)a;
    (void)b;
    errno = ENOSYS;
    return -1;
}
char* tmpnam(char* s) {
    (void)s;
    errno = ENOSYS;
    return 0;
}

// The code a shell observes after SIGABRT kills a process: 128 + 6.
__attribute__((noreturn)) void abort(void) {
    capsule_exit(134);
}
__attribute__((noreturn)) void exit(int code) {
    capsule_exit(code);
}
char* getenv(const char* n) {
    (void)n;
    return 0;
}
int system(const char* c) {
    (void)c;
    errno = ENOSYS;
    return -1;
}

time_t time(time_t* t) {
    if (t) {
        *t = (time_t)-1;
    }
    errno = ENOSYS;
    return (time_t)-1;
}
clock_t clock(void) {
    errno = ENOSYS;
    return (clock_t)-1;
}
struct tm* localtime(const time_t* t) {
    (void)t;
    errno = ENOSYS;
    return 0;
}
struct tm* gmtime(const time_t* t) {
    (void)t;
    errno = ENOSYS;
    return 0;
}
time_t mktime(struct tm* tm) {
    (void)tm;
    errno = ENOSYS;
    return -1;
}
unsigned long strftime(char* s, unsigned long m, const char* f, const struct tm* tm) {
    (void)f;
    (void)tm;
    if (m) {
        s[0] = 0;
    }
    errno = ENOSYS;
    return 0;
}

static struct lconv fs_lconv = {".", ""};
char* setlocale(int c, const char* l) {
    if (c < LC_ALL || c > LC_TIME || (l && *l && strcmp(l, "C"))) {
        return 0;
    }
    return "C";
}
struct lconv* localeconv(void) {
    return &fs_lconv;
}

sighandler_t signal(int sig, sighandler_t h) {
    (void)sig;
    (void)h;
    errno = ENOSYS;
    return SIG_ERR;
}
int raise(int sig) {
    (void)sig;
    errno = ENOSYS;
    return -1;
}

// ------------------------------------------------------------- formatting
//
// Enough of printf for programs that turn numbers into strings: integer and
// floating-point conversions, strings, characters, pointers, width and
// precision.
// Output is emitted directly under the caller's bound; there is no hidden
// fixed-size staging buffer whose numeric writes can run past its end.
struct fs_format_output {
    char* bytes;
    unsigned long capacity;
    unsigned long length;
};

static void fs_format_char(struct fs_format_output* output, char value) {
    if (output->bytes && output->capacity && output->length < output->capacity - 1u) {
        output->bytes[output->length] = value;
    }
    if (output->length != ~0ul) {
        output->length++;
    }
}

static void fs_format_repeat(struct fs_format_output* output, char value, unsigned long count) {
    for (unsigned long index = 0; index < count; ++index) {
        fs_format_char(output, value);
    }
}

static void fs_format_bytes(struct fs_format_output* output, const char* bytes, unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        fs_format_char(output, bytes[index]);
    }
}

static __attribute__((always_inline)) inline void fs_format_padded_bytes(
    struct fs_format_output* output, const char* bytes, unsigned long length, unsigned long width, int left) {
    unsigned long padding = width > length ? width - length : 0;
    if (!left) {
        fs_format_repeat(output, ' ', padding);
    }
    fs_format_bytes(output, bytes, length);
    if (left) {
        fs_format_repeat(output, ' ', padding);
    }
}

static unsigned int fs_utoa_reverse(char* digits, unsigned long long value, unsigned int base, int upper) {
    unsigned int length = 0;
    do {
        unsigned int digit = (unsigned int)(value % base);
        digits[length++] = (char)(digit < 10 ? '0' + digit : (upper ? 'A' : 'a') + (digit - 10));
        value /= base;
    } while (value);
    return length;
}

static char* fs_utoa_end(char* end, unsigned int value) {
    do {
        *--end = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    return end;
}

/*
 * The decimal expansion and rounding below are adapted from musl libc's
 * fmt_fp (src/stdio/vfprintf.c), specialized for the BPF ABI's binary64
 * double and this file's bounded output sink.
 *
 * Copyright (c) 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#define FS_DBL_MANT_DIG __DBL_MANT_DIG__
#define FS_DBL_MAX_EXP __DBL_MAX_EXP__
#define FS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define FS_MAX(a, b) ((a) > (b) ? (a) : (b))

static void fs_format_float_padding(struct fs_format_output* output, const char* prefix, unsigned int prefix_length, unsigned long width,
    unsigned long body_length, int left, int zero_pad, int before) {
    unsigned long content = prefix_length + body_length;
    unsigned long padding = width > content ? width - content : 0;
    if (before) {
        if (!left && !zero_pad) {
            fs_format_repeat(output, ' ', padding);
        }
        fs_format_bytes(output, prefix, prefix_length);
        if (!left && zero_pad) {
            fs_format_repeat(output, '0', padding);
        }
    } else if (left) {
        fs_format_repeat(output, ' ', padding);
    }
}

static int fs_format_float(struct fs_format_output* output, double input, unsigned long width, int precision, int left, int plus, int space, int alternate,
    int zero_pad, int conversion) {
    enum {
        FS_FLOAT_MANTISSA_WORDS = 1 + (FS_DBL_MANT_DIG - 29 + 7) / 8 + 1,
        FS_FLOAT_EXPONENT_WORDS = (FS_DBL_MAX_EXP + FS_DBL_MANT_DIG + 28 + 8) / 9,
        FS_FLOAT_WORDS = FS_FLOAT_MANTISSA_WORDS + FS_FLOAT_EXPONENT_WORDS,
    };
    uint32_t big[FS_FLOAT_WORDS];
    uint32_t *a, *d, *r, *z;
    int exponent2 = 0;
    int exponent10;
    int i;
    int j;
    int body_length;
    char digits[9 + FS_DBL_MANT_DIG / 4];
    char* cursor;
    char exponent_buffer[3 * sizeof(int)];
    char* exponent_end = exponent_buffer + sizeof(exponent_buffer);
    char* exponent_text = exponent_end;
    char prefix[3];
    unsigned int prefix_length = 0;

    uint64_t bits;
    memcpy(&bits, &input, sizeof(bits));
    int negative = (int)(bits >> 63);
    uint64_t magnitude = bits & UINT64_C(0x7fffffffffffffff);
    uint64_t fraction = magnitude & UINT64_C(0x000fffffffffffff);
    unsigned int exponent_field = (unsigned int)(magnitude >> 52);
    if (negative) {
        prefix[prefix_length++] = '-';
    } else if (plus) {
        prefix[prefix_length++] = '+';
    } else if (space) {
        prefix[prefix_length++] = ' ';
    }

    if (exponent_field == 0x7ffu) {
        const char* special = fraction ? ((conversion & 32) ? "nan" : "NAN") : ((conversion & 32) ? "inf" : "INF");
        unsigned long special_body = 3;
        fs_format_float_padding(output, prefix, prefix_length, width, special_body, left, 0, 1);
        fs_format_bytes(output, special, special_body);
        fs_format_float_padding(output, prefix, prefix_length, width, special_body, left, 0, 0);
        return 0;
    }

    double value = 0.0;
    if (exponent_field) {
        uint64_t normalized = UINT64_C(0x3ff0000000000000) | fraction;
        memcpy(&value, &normalized, sizeof(value));
        exponent2 = (int)exponent_field - 1023;
    } else if (fraction) {
        unsigned int top = 63u - (unsigned int)__builtin_clzll(fraction);
        uint64_t normalized = UINT64_C(0x3ff0000000000000) | ((fraction << (52u - top)) & UINT64_C(0x000fffffffffffff));
        memcpy(&value, &normalized, sizeof(value));
        exponent2 = (int)top - 1074;
    }

    if ((conversion | 32) == 'a') {
        double round = 1.0;
        int removed;
        prefix[prefix_length++] = '0';
        prefix[prefix_length++] = (char)((conversion & 32) ? 'x' : 'X');

        if (precision < 0 || precision >= (FS_DBL_MANT_DIG - 1 + 3) / 4) {
            removed = 0;
        } else {
            removed = (FS_DBL_MANT_DIG - 1 + 3) / 4 - precision;
        }
        if (removed) {
            while (removed--) {
                round *= 16.0;
            }
            if (negative) {
                value = -value;
                value -= round;
                value += round;
                value = -value;
            } else {
                value += round;
                value -= round;
            }
        }

        exponent_text = fs_utoa_end(exponent_end, exponent2 < 0 ? (unsigned int)-exponent2 : (unsigned int)exponent2);
        *--exponent_text = exponent2 < 0 ? '-' : '+';
        *--exponent_text = (char)(conversion + ('p' - 'a'));

        static const char hex_digits[] = "0123456789ABCDEF";
        cursor = digits;
        do {
            int digit = (int)value;
            *cursor++ = (char)(hex_digits[digit] | (conversion & 32));
            value = 16.0 * (value - digit);
            if (cursor == digits + 1 && (value || precision > 0 || alternate)) {
                *cursor++ = '.';
            }
        } while (value);

        int exponent_length = (int)(exponent_end - exponent_text);
        int produced = (int)(cursor - digits);
        if (precision > 0x7fffffff - 2 - exponent_length - (int)prefix_length) {
            errno = EOVERFLOW;
            return -1;
        }
        if (precision > 0 && produced - 2 < precision) {
            body_length = precision + 2 + exponent_length;
        } else {
            body_length = produced + exponent_length;
        }
        fs_format_float_padding(output, prefix, prefix_length, width, (unsigned long)body_length, left, zero_pad, 1);
        fs_format_bytes(output, digits, (unsigned long)produced);
        int zeroes = body_length - exponent_length - produced;
        if (zeroes > 0) {
            fs_format_repeat(output, '0', (unsigned long)zeroes);
        }
        fs_format_bytes(output, exponent_text, (unsigned long)exponent_length);
        fs_format_float_padding(output, prefix, prefix_length, width, (unsigned long)body_length, left, zero_pad, 0);
        return 0;
    }

    if (precision < 0) {
        precision = 6;
    }
    if (value) {
        value *= 0x1p28;
        exponent2 -= 28;
    }

    if (exponent2 < 0) {
        a = r = z = big;
    } else {
        a = r = z = big + FS_FLOAT_WORDS - FS_FLOAT_MANTISSA_WORDS - 1;
    }
    do {
        *z = (uint32_t)value;
        value = 1000000000.0 * (value - *z++);
    } while (value);

    while (exponent2 > 0) {
        uint32_t carry = 0;
        int shift = FS_MIN(29, exponent2);
        for (d = z; d > a;) {
            --d;
            uint64_t expanded = ((uint64_t)*d << shift) + carry;
            *d = (uint32_t)(expanded % 1000000000u);
            carry = (uint32_t)(expanded / 1000000000u);
        }
        if (carry) {
            *--a = carry;
        }
        while (z > a && !z[-1]) {
            --z;
        }
        exponent2 -= shift;
    }
    while (exponent2 < 0) {
        uint32_t carry = 0;
        int shift = FS_MIN(9, -exponent2);
        int needed = 1 + (precision + FS_DBL_MANT_DIG / 3 + 8) / 9;
        for (d = a; d < z; ++d) {
            uint32_t remainder = *d & ((1u << shift) - 1u);
            *d = (*d >> shift) + carry;
            carry = (1000000000u >> shift) * remainder;
        }
        if (!*a) {
            ++a;
        }
        if (carry) {
            *z++ = carry;
        }
        uint32_t* base = (conversion | 32) == 'f' ? r : a;
        if (z - base > needed) {
            z = base + needed;
        }
        exponent2 += shift;
    }

    if (a < z) {
        for (i = 10, exponent10 = 9 * (int)(r - a); *a >= (uint32_t)i; i *= 10) {
            ++exponent10;
        }
    } else {
        exponent10 = 0;
    }

    j = precision - ((conversion | 32) != 'f') * exponent10 - ((conversion | 32) == 'g' && precision);
    if (j < 9 * (int)(z - r - 1)) {
        uint32_t x;
        d = r + 1 + ((j + 9 * FS_DBL_MAX_EXP) / 9 - FS_DBL_MAX_EXP);
        j += 9 * FS_DBL_MAX_EXP;
        j %= 9;
        for (i = 10, ++j; j < 9; i *= 10, ++j) {
        }
        x = *d % (uint32_t)i;
        if (x || d + 1 != z) {
            double round = 2.0 / __DBL_EPSILON__;
            double small;
            if (((*d / (uint32_t)i) & 1u) || (i == 1000000000 && d > a && (d[-1] & 1u))) {
                round += 2.0;
            }
            if (x < (uint32_t)i / 2u) {
                small = 0x0.8p0;
            } else if (x == (uint32_t)i / 2u && d + 1 == z) {
                small = 0x1.0p0;
            } else {
                small = 0x1.8p0;
            }
            if (negative) {
                round = -round;
                small = -small;
            }
            *d -= x;
            if (round + small != round) {
                *d += (uint32_t)i;
                while (*d > 999999999u) {
                    *d = 0;
                    if (d == a) {
                        *--a = 0;
                        d = a;
                    } else {
                        --d;
                    }
                    ++*d;
                }
                for (i = 10, exponent10 = 9 * (int)(r - a); *a >= (uint32_t)i; i *= 10) {
                    ++exponent10;
                }
            }
        }
        if (z > d + 1) {
            z = d + 1;
        }
    }
    while (z > a && !z[-1]) {
        --z;
    }

    if ((conversion | 32) == 'g') {
        if (!precision) {
            ++precision;
        }
        if (precision > exponent10 && exponent10 >= -4) {
            --conversion;
            precision -= exponent10 + 1;
        } else {
            conversion -= 2;
            --precision;
        }
        if (!alternate) {
            if (z > a && z[-1]) {
                for (i = 10, j = 0; z[-1] % (uint32_t)i == 0; i *= 10) {
                    ++j;
                }
            } else {
                j = 9;
            }
            if ((conversion | 32) == 'f') {
                precision = FS_MIN(precision, FS_MAX(0, 9 * (int)(z - r - 1) - j));
            } else {
                precision = FS_MIN(precision, FS_MAX(0, 9 * (int)(z - r - 1) + exponent10 - j));
            }
        }
    }

    if (precision > 0x7fffffff - 1 - (precision != 0 || alternate)) {
        errno = EOVERFLOW;
        return -1;
    }
    body_length = 1 + precision + (precision != 0 || alternate);
    if ((conversion | 32) == 'f') {
        if (exponent10 > 0x7fffffff - body_length) {
            errno = EOVERFLOW;
            return -1;
        }
        if (exponent10 > 0) {
            body_length += exponent10;
        }
    } else {
        exponent_text = fs_utoa_end(exponent_end, exponent10 < 0 ? (unsigned int)-exponent10 : (unsigned int)exponent10);
        while (exponent_end - exponent_text < 2) {
            *--exponent_text = '0';
        }
        *--exponent_text = exponent10 < 0 ? '-' : '+';
        *--exponent_text = (char)conversion;
        if (exponent_end - exponent_text > 0x7fffffff - body_length) {
            errno = EOVERFLOW;
            return -1;
        }
        body_length += (int)(exponent_end - exponent_text);
    }

    fs_format_float_padding(output, prefix, prefix_length, width, (unsigned long)body_length, left, zero_pad, 1);
    if ((conversion | 32) == 'f') {
        if (a > r) {
            a = r;
        }
        for (d = a; d <= r; ++d) {
            char* text = fs_utoa_end(digits + 9, *d);
            if (d != a) {
                while (text > digits) {
                    *--text = '0';
                }
            } else if (text == digits + 9) {
                *--text = '0';
            }
            fs_format_bytes(output, text, (unsigned long)(digits + 9 - text));
        }
        if (precision || alternate) {
            fs_format_char(output, '.');
        }
        for (; d < z && precision > 0; ++d, precision -= 9) {
            char* text = fs_utoa_end(digits + 9, *d);
            while (text > digits) {
                *--text = '0';
            }
            fs_format_bytes(output, text, (unsigned long)FS_MIN(9, precision));
        }
        if (precision > 0) {
            fs_format_repeat(output, '0', (unsigned long)precision);
        }
    } else {
        if (z <= a) {
            z = a + 1;
        }
        for (d = a; d < z && precision >= 0; ++d) {
            char* text = fs_utoa_end(digits + 9, *d);
            if (text == digits + 9) {
                *--text = '0';
            }
            if (d != a) {
                while (text > digits) {
                    *--text = '0';
                }
            } else {
                fs_format_char(output, *text++);
                if (precision > 0 || alternate) {
                    fs_format_char(output, '.');
                }
            }
            int available = (int)(digits + 9 - text);
            fs_format_bytes(output, text, (unsigned long)FS_MIN(available, precision));
            precision -= available;
        }
        if (precision > 0) {
            fs_format_repeat(output, '0', (unsigned long)precision);
        }
        fs_format_bytes(output, exponent_text, (unsigned long)(exponent_end - exponent_text));
    }
    fs_format_float_padding(output, prefix, prefix_length, width, (unsigned long)body_length, left, zero_pad, 0);
    return 0;
}

#undef FS_DBL_MANT_DIG
#undef FS_DBL_MAX_EXP
#undef FS_MIN
#undef FS_MAX

enum fs_format_length {
    FS_LENGTH_DEFAULT,
    FS_LENGTH_HH,
    FS_LENGTH_H,
    FS_LENGTH_L,
    FS_LENGTH_LL,
    FS_LENGTH_Z,
    FS_LENGTH_J,
    FS_LENGTH_T,
};

static long long fs_format_signed_arg(va_list* ap, enum fs_format_length length) {
    switch (length) {
        case FS_LENGTH_HH:
            return (signed char)va_arg(*ap, int);
        case FS_LENGTH_H:
            return (short)va_arg(*ap, int);
        case FS_LENGTH_L:
        case FS_LENGTH_Z:
        case FS_LENGTH_T:
            return va_arg(*ap, long);
        case FS_LENGTH_LL:
        case FS_LENGTH_J:
            return va_arg(*ap, long long);
        default:
            return va_arg(*ap, int);
    }
}

static unsigned long long fs_format_unsigned_arg(va_list* ap, enum fs_format_length length) {
    switch (length) {
        case FS_LENGTH_HH:
            return (unsigned char)va_arg(*ap, unsigned int);
        case FS_LENGTH_H:
            return (unsigned short)va_arg(*ap, unsigned int);
        case FS_LENGTH_L:
        case FS_LENGTH_Z:
        case FS_LENGTH_T:
            return va_arg(*ap, unsigned long);
        case FS_LENGTH_LL:
        case FS_LENGTH_J:
            return va_arg(*ap, unsigned long long);
        default:
            return va_arg(*ap, unsigned int);
    }
}

static void fs_format_field(struct fs_format_output* output, const char* prefix, unsigned int prefix_length, const char* reversed_digits,
    unsigned int digit_length, unsigned long precision_zeroes, unsigned long width, int left, int zero_pad) {
    unsigned long content = (unsigned long)prefix_length + precision_zeroes + digit_length;
    unsigned long padding = width > content ? width - content : 0;
    if (!left && !zero_pad) {
        fs_format_repeat(output, ' ', padding);
    }
    fs_format_bytes(output, prefix, prefix_length);
    if (!left && zero_pad) {
        fs_format_repeat(output, '0', padding);
    }
    fs_format_repeat(output, '0', precision_zeroes);
    for (unsigned int index = digit_length; index > 0; --index) {
        fs_format_char(output, reversed_digits[index - 1]);
    }
    if (left) {
        fs_format_repeat(output, ' ', padding);
    }
}

int vsnprintf(char* out, unsigned long cap, const char* fmt, va_list ap) {
    struct fs_format_output output = {.bytes = out, .capacity = cap};
    for (const char* f = fmt; *f; ++f) {
        if (*f != '%') {
            fs_format_char(&output, *f);
            continue;
        }

        ++f;
        int left = 0;
        int plus = 0;
        int space = 0;
        int alternate = 0;
        int zero_pad = 0;
        for (;; ++f) {
            if (*f == '-') {
                left = 1;
            } else if (*f == '+') {
                plus = 1;
            } else if (*f == ' ') {
                space = 1;
            } else if (*f == '#') {
                alternate = 1;
            } else if (*f == '0') {
                zero_pad = 1;
            } else {
                break;
            }
        }

        unsigned long width = 0;
        if (*f == '*') {
            int dynamic_width = va_arg(ap, int);
            if (dynamic_width < 0) {
                left = 1;
                width = (unsigned long)(0u - (unsigned int)dynamic_width);
            } else {
                width = (unsigned long)dynamic_width;
            }
            ++f;
        } else {
            while (*f >= '0' && *f <= '9') {
                unsigned int digit = (unsigned int)(*f++ - '0');
                width = width > (~0ul - digit) / 10u ? ~0ul : width * 10u + digit;
            }
        }

        long precision = -1;
        if (*f == '.') {
            ++f;
            precision = 0;
            if (*f == '*') {
                int dynamic_precision = va_arg(ap, int);
                precision = dynamic_precision >= 0 ? dynamic_precision : -1;
                ++f;
            } else {
                while (*f >= '0' && *f <= '9') {
                    unsigned int digit = (unsigned int)(*f++ - '0');
                    precision = precision > (0x7fffffff - (long)digit) / 10 ? 0x7fffffff : precision * 10 + digit;
                }
            }
        }

        enum fs_format_length length = FS_LENGTH_DEFAULT;
        if (*f == 'h') {
            length = *++f == 'h' ? (++f, FS_LENGTH_HH) : FS_LENGTH_H;
        } else if (*f == 'l') {
            length = *++f == 'l' ? (++f, FS_LENGTH_LL) : FS_LENGTH_L;
        } else if (*f == 'z') {
            length = FS_LENGTH_Z;
            ++f;
        } else if (*f == 'j') {
            length = FS_LENGTH_J;
            ++f;
        } else if (*f == 't') {
            length = FS_LENGTH_T;
            ++f;
        }

        switch (*f) {
            case 'd':
            case 'i': {
                long long signed_value = fs_format_signed_arg(&ap, length);
                unsigned long long value = signed_value < 0 ? 0ull - (unsigned long long)signed_value : (unsigned long long)signed_value;
                char digits[24];
                unsigned int digit_length = precision == 0 && value == 0 ? 0 : fs_utoa_reverse(digits, value, 10, 0);
                char prefix = signed_value < 0 ? '-' : plus ? '+' : space ? ' ' : 0;
                unsigned long precision_zeroes = precision > (long)digit_length ? (unsigned long)precision - digit_length : 0;
                fs_format_field(&output, &prefix, prefix != 0, digits, digit_length, precision_zeroes, width, left, zero_pad && precision < 0);
                break;
            }
            case 'u':
            case 'o':
            case 'x':
            case 'X': {
                unsigned long long value = fs_format_unsigned_arg(&ap, length);
                unsigned int base = *f == 'u' ? 10 : *f == 'o' ? 8 : 16;
                char digits[24];
                unsigned int digit_length = precision == 0 && value == 0 ? 0 : fs_utoa_reverse(digits, value, base, *f == 'X');
                char prefix[2] = {'0', *f};
                unsigned int prefix_length = alternate && value && base == 16 ? 2 : alternate && base == 8 && !digit_length ? 1 : 0;
                if (alternate && base == 8 && digit_length && digits[digit_length - 1] != '0') {
                    prefix_length = 1;
                }
                unsigned long precision_zeroes = precision > (long)digit_length ? (unsigned long)precision - digit_length : 0;
                fs_format_field(&output, prefix, prefix_length, digits, digit_length, precision_zeroes, width, left, zero_pad && precision < 0);
                break;
            }
            case 'c': {
                char value = (char)va_arg(ap, int);
                fs_format_padded_bytes(&output, &value, 1, width, left);
                break;
            }
            case 's': {
                const char* s = va_arg(ap, const char*);
                if (!s) {
                    s = "(null)";
                }
                unsigned long length = strlen(s);
                if (precision >= 0 && length > (unsigned long)precision) {
                    length = (unsigned long)precision;
                }
                fs_format_padded_bytes(&output, s, length, width, left);
                break;
            }
            case 'p': {
                unsigned long long value = (unsigned long)(va_arg(ap, void*));
                char digits[24];
                unsigned int digit_length = fs_utoa_reverse(digits, value, 16, 0);
                fs_format_field(&output, "0x", 2, digits, digit_length, 0, width, left, zero_pad);
                break;
            }
            case 'g':
            case 'f':
            case 'e':
            case 'G':
            case 'F':
            case 'E':
            case 'a':
            case 'A': {
                double value = va_arg(ap, double);
                if (fs_format_float(&output, value, width, precision < 0 ? -1 : (int)precision, left, plus, space, alternate, zero_pad, *f)) {
                    if (out && cap) {
                        unsigned long terminator = output.length < cap ? output.length : cap - 1u;
                        out[terminator] = 0;
                    }
                    return -1;
                }
                break;
            }
            case '%':
                fs_format_char(&output, '%');
                break;
            default:
                fs_format_char(&output, '%');
                if (*f) {
                    fs_format_char(&output, *f);
                }
                break;
        }
    }

    if (out && cap) {
        unsigned long terminator = output.length < cap ? output.length : cap - 1u;
        out[terminator] = 0;
    }
    if (output.length > 0x7ffffffful) {
        errno = EOVERFLOW;
        return -1;
    }
    return (int)output.length;
}
int snprintf(char* s, unsigned long n, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(s, n, fmt, ap);
    va_end(ap);
    return r;
}
int sprintf(char* s, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(s, ~0ul, fmt, ap);
    va_end(ap);
    return r;
}
int fprintf(FILE* f, const char* fmt, ...) {
    (void)f;
    (void)fmt;
    errno = EBADF;
    return EOF;
}
int printf(const char* fmt, ...) {
    (void)fmt;
    errno = EBADF;
    return EOF;
}

unsigned long strnlen(const char* s, unsigned long max) {
    unsigned long n = 0;
    while (n < max && s[n]) {
        n++;
    }
    return n;
}

unsigned long long strtoull(const char* s, char** end, int base) {
    struct fs_integer_parse parsed = fs_parse_integer(s, base, ~0ull);
    if (end) {
        *end = (char*)parsed.end;
    }
    if (parsed.overflow) {
        errno = ERANGE;
        return ~0ull;
    }
    return parsed.negative ? 0ull - parsed.value : parsed.value;
}
int putc(int c, FILE* f) {
    return fputc(c, f);
}
int putchar(int c) {
    return fputc(c, stdout);
}

// File-backed mapping has no meaning without an operating system; programs
// that reach for it are given a clean failure, and the ports stage their data
// through a map instead.
int open(const char* path, int flags, ...) {
    (void)path;
    (void)flags;
    errno = ENOSYS;
    return -1;
}
int close(int fd) {
    (void)fd;
    errno = EBADF;
    return -1;
}
void* mmap(void* addr, unsigned long len, int prot, int flags, int fd, long off) {
    (void)addr;
    (void)len;
    (void)prot;
    (void)flags;
    (void)fd;
    (void)off;
    errno = ENOSYS;
    return (void*)-1;
}
int munmap(void* addr, unsigned long len) {
    (void)addr;
    (void)len;
    errno = ENOSYS;
    return -1;
}

int clock_gettime(int clk, struct timespec* ts) {
    (void)clk;
    (void)ts;
    errno = ENOSYS;
    return -1;
}

void* bsearch(const void* key, const void* base, unsigned long n, unsigned long sz, int (*cmp)(const void*, const void*)) {
    const char* a = base;
    unsigned long lo = 0, hi = n;
    while (lo < hi) {
        unsigned long mid = lo + (hi - lo) / 2;
        int r = cmp(key, a + mid * sz);
        if (r == 0) {
            return (void*)(a + mid * sz);
        }
        if (r < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return 0;
}

double atof(const char* s) {
    return strtod(s, 0);
}
int atoi(const char* s) {
    return (int)strtol(s, 0, 10);
}

int gettimeofday(struct timeval* tv, struct timezone* tz) {
    (void)tv;
    (void)tz;
    errno = ENOSYS;
    return -1;
}

struct tm* localtime_r(const time_t* t, struct tm* out) {
    (void)t;
    (void)out;
    errno = ENOSYS;
    return 0;
}
