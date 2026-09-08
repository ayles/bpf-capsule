// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Exactly this ordinary C code is compiled for both the host and Capsule.
// No compiler-runtime names or knowledge of its implementation belong here.
#include "float_ops.h"
#include <math.h>
#include <string.h>

static uint64_t double_bits(double value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    // NaN payload/sign are unspecified. Every other result, including signed
    // zero and subnormals, must match bit for bit.
    return isnan(value) ? UINT64_C(0x7ff8000000000000) : bits;
}

static uint32_t float_bits(float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return isnan(value) ? UINT32_C(0x7fc00000) : bits;
}

// Exercise ordered and unordered comparison predicates at both widths.
#define COMPARISONS(name, type) \
    static uint32_t name(type a, type b) { \
        int u = !!isunordered(a, b); \
        return (!u) | (u << 1) | ((a == b) << 2) | ((a < b) << 3) | ((a <= b) << 4) | ((a > b) << 5) | ((a >= b) << 6) | ((!u && a != b) << 7) | \
            ((u || a == b) << 8) | ((u || a < b) << 9) | ((u || a <= b) << 10) | ((u || a > b) << 11) | ((u || a >= b) << 12) | ((a != b) << 13); \
    }
COMPARISONS(compare_double, double)
COMPARISONS(compare_float, float)
#undef COMPARISONS

void float_evaluate(struct float_case* test) {
    double a, b;
    float fa, fb;
    memcpy(&a, &test->a, sizeof(a));
    memcpy(&b, &test->b, sizeof(b));
    memcpy(&fa, &test->fa, sizeof(fa));
    memcpy(&fb, &test->fb, sizeof(fb));
    uint64_t integer = test->integer;
    uint64_t* r = test->result;
    r[DADD] = double_bits(a + b);
    r[DSUB] = double_bits(a - b);
    r[DMUL] = double_bits(a * b);
    r[DDIV] = double_bits(a / b);
    r[DREM] = double_bits(fmod(a, b));
    r[DCMP] = compare_double(a, b);
    r[DNEG] = double_bits(-a);
    r[I2D] = double_bits((double)(int64_t)integer);
    r[U2D] = double_bits((double)integer);
    // Only conversions with a representable truncated result are defined C.
    r[D2I] = a >= -0x1p63 && a < 0x1p63 ? (uint64_t)(int64_t)a : 0;
    r[D2U] = a > -1.0 && a < 0x1p64 ? (uint64_t)a : 0;
    r[F2D] = double_bits((double)fa);
    r[D2F] = float_bits((float)a);
    r[FADD] = float_bits(fa + fb);
    r[FSUB] = float_bits(fa - fb);
    r[FMUL] = float_bits(fa * fb);
    r[FDIV] = float_bits(fa / fb);
    r[FREM] = float_bits(fmodf(fa, fb));
    r[FCMP] = compare_float(fa, fb);
    r[FNEG] = float_bits(-fa);
    r[I2F] = float_bits((float)(int64_t)integer);
    r[U2F] = float_bits((float)integer);
    r[F2I] = fa >= -0x1p63f && fa < 0x1p63f ? (uint64_t)(int64_t)fa : 0;
    r[F2U] = fa > -1.0f && fa < 0x1p64f ? (uint64_t)fa : 0;
}
