// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <errno.h>
#include <fenv.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule.h"
#include "libc_test.h"

volatile struct libc_test_result libc_test_output SEC(".data.libctest");

static double from_bits(unsigned long long bits) {
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static void libc_test_body(void) {
    struct libc_test_result* output = (struct libc_test_result*)&libc_test_output;
    const long long signed_min = (-9223372036854775807ll - 1ll);
    char truncated[sizeof(output->truncated)];
    char formatted[sizeof(output->formatted)];
    output->truncated_length = snprintf(truncated, sizeof(truncated), "%lld", signed_min);
    output->formatted_length = snprintf(
        formatted, sizeof(formatted), "%hhd/%hd/%ld/%lld/%zu/%jd/%#08x/%.*s/%%", (int)-7, (int)-32000, (long)-9, signed_min, (unsigned long)17, signed_min,
        0x2au, 3, "abcdef"
    );
    memcpy(output->truncated, truncated, sizeof(truncated));
    memcpy(output->formatted, formatted, sizeof(formatted));

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

    errno = 0;
    if (malloc(1) || errno != ENOMEM) {
        output->failures |= 1ull << 8;
    }
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
