// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <errno.h>
#include <fenv.h>
#include <inttypes.h>
#include <malloc.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule.h"
#include "libc_test.h"

volatile struct libc_test_result libc_test_output SEC(".data.libctest");

// A guest can replace the weak platform beneath Picolibc. printf reaches this
// implementation through Capsule's default stdout stream.
ssize_t write(int fd, const void* buffer, size_t size) {
    struct libc_test_result* output = (struct libc_test_result*)&libc_test_output;
    if (fd != STDOUT_FILENO) {
        errno = EBADF;
        return -1;
    }
    if (!size) {
        return 0;
    }
    if (size != 1 || output->printed_length == sizeof(output->printed)) {
        errno = ENOSPC;
        return -1;
    }
    output->printed[output->printed_length++] = *(const char*)buffer;
    return 1;
}

static double from_bits(unsigned long long bits) {
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static unsigned long long to_bits(double value) {
    unsigned long long bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static void libc_exit_handler(void) {
    libc_test_output.atexit_calls++;
}

static void libc_test_body(void) {
    struct libc_test_result* output = (struct libc_test_result*)&libc_test_output;
    const long long signed_min = (-9223372036854775807ll - 1ll);
    char truncated[sizeof(output->truncated)];
    char formatted[sizeof(output->formatted)];
    char floats[sizeof(output->floats)];
    char float_edges[sizeof(output->float_edges)];
    output->truncated_length = snprintf(truncated, sizeof(truncated), "%lld", signed_min);
    output->formatted_length = snprintf(formatted, sizeof(formatted), "%hhd/%hd/%ld/%lld/%zu/%jd/%#08x/%#o/%3c/%-5s/%.*s/%%", (int)-7, (int)-32000, (long)-9,
        signed_min, (unsigned long)17, (intmax_t)signed_min, 0x2au, 9u, 'Q', "xy", 3, "abcdef");
    output->float_length = snprintf(floats, sizeof(floats), "%.15g/%+.2f/%.3e/%a/%A/%.0f/%#.0f/%g/%G", 12.5, 1.25, 1234.0, 3.0, 0.1, 2.5, 2.5,
        from_bits(0x7ff0000000000000ull), from_bits(0x7ff8000000000000ull));
    output->float_edge_length = snprintf(float_edges, sizeof(float_edges), "%.17g|%.17g|%010.2f|%#.0a|%.0f|%g|%.3g|%.3g", from_bits(1),
        from_bits(0x7fefffffffffffffull), -1.5, 1.0, 3.5, from_bits(0x8000000000000000ull), 999.5, 0.00009995);
    memcpy(output->truncated, truncated, sizeof(truncated));
    memcpy(output->formatted, formatted, sizeof(formatted));
    memcpy(output->floats, floats, sizeof(floats));
    memcpy(output->float_edges, float_edges, sizeof(float_edges));

    char* end = 0;
    errno = 0;
    output->parsed_max = strtoull("18446744073709551615!", &end, 10);
    if (!end || *end != '!') {
        output->failures |= 1ull << 0;
    }
    errno = 0;
    output->parsed_overflow = strtoull("18446744073709551616x", &end, 10);
    output->overflow_errno = errno;
    if (!end || *end != 'x') {
        output->failures |= 1ull << 1;
    }
    output->parsed_negative = strtoull("-1", &end, 0);
    output->parsed_min = strtol("-9223372036854775808", &end, 10);
    if (!end || *end) {
        output->failures |= 1ull << 2;
    }

    double positive_infinity = from_bits(0x7ff0000000000000ull);
    int exponent = 123;
    double fraction = frexp(positive_infinity, &exponent);
    if (!isinf(fraction) || exponent != 0) {
        output->failures |= 1ull << 3;
    }
    if (!isinf(log(positive_infinity)) || !isinf(sqrt(positive_infinity))) {
        output->failures |= 1ull << 4;
    }
    if (!isnan(sin(positive_infinity)) || !isnan(fmod(positive_infinity, 3.0))) {
        output->failures |= 1ull << 5;
    }
    if (fmod(3.0, positive_infinity) != 3.0 || fmin(from_bits(0x7ff8000000000000ull), 7.0) != 7.0) {
        output->failures |= 1ull << 6;
    }
    double negative_zero = from_bits(0x8000000000000000ull);
    if (signbit(fabs(negative_zero)) || !signbit(floor(negative_zero)) || !signbit(ceil(negative_zero)) || !signbit(trunc(negative_zero)) ||
        !signbit(round(negative_zero))) {
        output->failures |= 1ull << 7;
    }
    if (to_bits(sqrt(from_bits(0x0010000000000000ull))) != 0x2000000000000000ull) {
        output->failures |= 1ull << 9;
    }
    if (nearbyint(0.5) != 0.0 || nearbyint(1.5) != 2.0 || nearbyint(2.5) != 2.0) {
        output->failures |= 1ull << 10;
    }
    if (!isinf(pow(0.0, -1.0))) {
        output->failures |= 1ull << 11;
    }
    double diagonal = hypot(1.0e308, 1.0e308);
    if (!(diagonal > 1.4e308 && diagonal < 1.42e308)) {
        output->failures |= 1ull << 12;
    }
    if (!signbit(fmin(0.0, negative_zero)) || signbit(fmax(negative_zero, 0.0))) {
        output->failures |= 1ull << 13;
    }
    double infinity = from_bits(0x7ff0000000000000ull);
    if (pow(1.0, infinity) != 1.0 || pow(-1.0, infinity) != 1.0) {
        output->failures |= 1ull << 14;
    }
    if (rintf(0.5f) != 0.0f || rintf(1.5f) != 2.0f || rintf(2.5f) != 2.0f || rintf(-1.5f) != -2.0f) {
        output->failures |= 1ull << 15;
    }

    errno = 0;
    if (fopen("missing", "r") != NULL || errno != ENOSYS) {
        output->failures |= 1ull << 21;
    }
    if (getenv("CAPSULE_MISSING") != NULL) {
        output->failures |= 1ull << 22;
    }
    output->printed_result = printf("capsule stdio %d", 17);
    if (output->printed_result != 16 || output->printed_length != 16) {
        output->failures |= 1ull << 23;
    }

    const char* decimal = "-12.5tail";
    errno = 0;
    if (to_bits(strtod(decimal, &end)) != 0xc029000000000000ull || end != decimal + 5 || errno) {
        output->failures |= 1ull << 16;
    }
    const char* hexadecimal = "0x1.00000000000008p0!";
    if (to_bits(strtod(hexadecimal, &end)) != 0x3ff0000000000000ull || *end != '!') {
        output->failures |= 1ull << 17;
    }
    const char* subnormal = "0x1p-1074/";
    errno = 0;
    if (to_bits(strtod(subnormal, &end)) != 1 || *end != '/' || errno != ERANGE) {
        output->failures |= 1ull << 18;
    }
    const char* overflow = "1e999999999999999999999x";
    errno = 0;
    if (!isinf(strtod(overflow, &end)) || *end != 'x' || errno != ERANGE) {
        output->failures |= 1ull << 19;
    }
    const char* no_number = "+word";
    errno = 0;
    if (to_bits(strtod(no_number, &end)) != 0 || end != no_number || errno) {
        output->failures |= 1ull << 20;
    }

    errno = 0;
    if (malloc(1) || errno != ENOMEM) {
        output->failures |= 1ull << 8;
    }
    errno = 0;
    volatile size_t invalid_alignment = 3;
    if (memalign(invalid_alignment, 16) || errno != EINVAL) {
        output->failures |= 1ull << 24;
    }
    void* untouched = (void*)1;
    if (posix_memalign(&untouched, 3, 16) != EINVAL || untouched != (void*)1) {
        output->failures |= 1ull << 25;
    }
    unsigned char entropy = 0;
    errno = 0;
    if (getentropy(&entropy, sizeof(entropy)) != -1 || errno != ENOSYS) {
        output->failures |= 1ull << 26;
    }
    errno = 0;
    if (sbrk(1) != (void*)-1 || errno != ENOSYS) {
        output->failures |= 1ull << 27;
    }
    sigset_t mask = {0};
    errno = 0;
    if (sigprocmask(SIG_SETMASK, &mask, 0) != -1 || errno != ENOSYS) {
        output->failures |= 1ull << 28;
    }
    time_t epoch = 0;
    struct tm local;
    if (localtime_r(&epoch, &local) != &local || local.tm_year != 70 || local.tm_mon != 0 || local.tm_mday != 1 || local.tm_hour != 0 || local.tm_min != 0 ||
        local.tm_sec != 0 || local.tm_wday != 4 || local.tm_yday != 0 || local.tm_isdst != 0) {
        output->failures |= 1ull << 29;
    }

    if (atexit(libc_exit_handler)) {
        output->failures |= 1ull << 30;
    }
    exit(37);
}

SEC("syscall")
int libc_test_run(void) {
    libc_test_output.capsule = capsule_call_void(libc_test_body);
    return 0;
}

SEC("syscall")
int libc_test_continue(void) {
    libc_test_output.capsule = capsule_continue_void(libc_test_output.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
