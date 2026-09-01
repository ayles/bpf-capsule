// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Native contracts for the algorithms in mathfns.c. The guest suite repeats
// the key cases after bpf-soft-float lowering; keeping this executable
// unprivileged makes numerical regressions visible before a kernel is involved.
#include <math.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static double from_bits(uint64_t bits) {
    union {
        uint64_t bits;
        double value;
    } converted = {bits};
    return converted.value;
}

static uint64_t to_bits(double value) {
    union {
        uint64_t bits;
        double value;
    } converted = {.value = value};
    return converted.bits;
}

static int check(int condition, const char* description) {
    if (!condition) {
        fprintf(stderr, "math contract failed: %s\n", description);
        return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    failures += check(to_bits(sqrt(from_bits(0x0010000000000000ull))) == 0x2000000000000000ull, "sqrt(DBL_MIN)");
    failures += check(nearbyint(0.5) == 0.0 && nearbyint(1.5) == 2.0 && nearbyint(2.5) == 2.0, "nearest-even rounding");
    failures += check(rintf(0.5f) == 0.0f && rintf(1.5f) == 2.0f && rintf(2.5f) == 2.0f && rintf(-1.5f) == -2.0f, "single-precision nearest-even rounding");
    failures += check(to_bits(pow(0.0, -1.0)) == 0x7ff0000000000000ull, "pow(0, -1)");
    double infinity = from_bits(0x7ff0000000000000ull);
    failures += check(pow(1.0, infinity) == 1.0 && pow(-1.0, infinity) == 1.0, "pow unit bases at infinity");
    double diagonal = hypot(1.0e308, 1.0e308);
    failures += check(diagonal > 1.4e308 && diagonal < 1.42e308, "scaled hypot");
    double negative_zero = from_bits(0x8000000000000000ull);
    failures += check(to_bits(fmin(0.0, negative_zero)) == 0x8000000000000000ull, "fmin signed zero");
    failures += check(to_bits(fmax(negative_zero, 0.0)) == 0, "fmax signed zero");
    double negative_large = asinh(-1.0e308);
    failures += check(negative_large < -700.0 && negative_large > -711.0, "large negative asinh");
    double large_acosh = acosh(1.0e200);
    failures += check(large_acosh > 461.0 && large_acosh < 462.0, "large acosh");

    char* end = NULL;
    const char* decimal = "  -12.5tail";
    errno = 0;
    failures += check(to_bits(strtod(decimal, &end)) == UINT64_C(0xc029000000000000) && end == decimal + 7 && errno == 0, "strtod decimal and endptr");
    const char* hexadecimal = "0x1.00000000000008p0!";
    failures += check(to_bits(strtod(hexadecimal, &end)) == UINT64_C(0x3ff0000000000000) && *end == '!', "strtod hexadecimal ties-to-even");
    hexadecimal = "0x1.8p+1!";
    failures += check(to_bits(strtod(hexadecimal, &end)) == UINT64_C(0x4008000000000000) && *end == '!', "strtod hexadecimal scaling");
    const char* subnormal = "0x1p-1074/";
    errno = 0;
    failures += check(to_bits(strtod(subnormal, &end)) == 1 && *end == '/' && errno == 0, "strtod minimum subnormal");
    const char* overflow = "1e999999999999999999999x";
    errno = 0;
    failures += check(isinf(strtod(overflow, &end)) && *end == 'x' && errno == ERANGE, "strtod saturated overflow exponent");
    const char* underflow = "0x1p-999999999999999999999x";
    errno = 0;
    failures += check(to_bits(strtod(underflow, &end)) == 0 && *end == 'x' && errno == ERANGE, "strtod saturated underflow exponent");
    const char* no_number = "  +word";
    errno = 0;
    failures += check(to_bits(strtod(no_number, &end)) == 0 && end == no_number && errno == 0, "strtod no conversion");
    const char* specials = "-INFINITY!";
    failures += check(to_bits(strtod(specials, &end)) == UINT64_C(0xfff0000000000000) && *end == '!', "strtod infinity");
    specials = "nan(payload)!";
    failures += check(isnan(strtod(specials, &end)) && *end == '!', "strtod nan payload");
    return failures ? 1 : 0;
}
