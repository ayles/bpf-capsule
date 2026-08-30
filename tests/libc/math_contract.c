// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Native contracts for the algorithms in mathfns.c. The guest suite repeats
// the key cases after bpf-soft-float lowering; keeping this executable
// unprivileged makes numerical regressions visible before a kernel is involved.
#include <math.h>
#include <stdint.h>
#include <stdio.h>

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
    return failures ? 1 : 0;
}
