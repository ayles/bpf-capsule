// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Differential contract for the compiler runtime's soft-float routines: every
// operation is compared bit for bit against the host's IEEE-754 hardware
// (round to nearest, ties to even) over random and boundary inputs. NaN
// results are compared as NaN-ness only; payloads are not part of the
// contract. Build with fp-contract disabled so the reference never fuses.
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;

u64 __bpf_dadd(u64 a, u64 b);
u64 __bpf_dsub(u64 a, u64 b);
u64 __bpf_dmul(u64 a, u64 b);
u64 __bpf_ddiv(u64 a, u64 b);
u64 __bpf_drem(u64 a, u64 b);
int __bpf_dcmp(u64 a, u64 b);
u64 __bpf_dneg(u64 a);
u64 __bpf_i2d(i64 v);
u64 __bpf_u2d(u64 u);
i64 __bpf_d2i(u64 a);
u64 __bpf_d2u(u64 a);
u64 __bpf_f2d(u32 f);
u32 __bpf_d2f(u64 a);
u32 __bpf_fadd(u32 a, u32 b);
u32 __bpf_fsub(u32 a, u32 b);
u32 __bpf_fmul(u32 a, u32 b);
u32 __bpf_fdiv(u32 a, u32 b);
u32 __bpf_frem(u32 a, u32 b);
int __bpf_fcmp(u32 a, u32 b);
u32 __bpf_fneg(u32 a);
u32 __bpf_i2f(i64 v);
u32 __bpf_u2f(u64 v);
i64 __bpf_f2i(u32 f);
u64 __bpf_f2u(u32 f);

static u64 random_state = 0x9e3779b97f4a7c15ull;

static u64 next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static u64 bits_of_double(double value) {
    u64 bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static double double_of_bits(u64 bits) {
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static u32 bits_of_float(float value) {
    u32 bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static float float_of_bits(u32 bits) {
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static const u64 double_specials[] = {
    0x0000000000000000ull, // +0
    0x8000000000000000ull, // -0
    0x3ff0000000000000ull, // 1
    0xbff0000000000000ull, // -1
    0x3fe0000000000000ull, // 0.5
    0xbfe0000000000000ull, // -0.5: defined conversion to unsigned zero
    0x4000000000000000ull, // 2
    0x4008000000000000ull, // 3
    0x3fb999999999999aull, // 0.1
    0x3fd5555555555555ull, // 1/3
    0x400921fb54442d18ull, // pi
    0x0000000000000001ull, // smallest subnormal
    0x000fffffffffffffull, // largest subnormal
    0x0010000000000000ull, // smallest normal
    0x7fefffffffffffffull, // largest finite
    0x7ff0000000000000ull, // +inf
    0xfff0000000000000ull, // -inf
    0x7ff8000000000000ull, // quiet NaN
    0x7ff4000000000000ull, // signalling NaN
    0x4330000000000000ull, // 2^52
    0x4340000000000000ull, // 2^53
    0x43e0000000000000ull, // 2^63
    0x43f0000000000000ull, // 2^64
    0xc3e0000000000000ull, // -2^63
    0x43dfffffffffffffull, // largest double below 2^63
    0x43efffffffffffffull, // largest double below 2^64
    0x3fefffffffffffffull, // largest double below 1
    0x7fe0000000000000ull, // 2^1023
    0x0020000000000000ull, // 2^-1021
};

static const u32 float_specials[] = {
    0x00000000u,
    0x80000000u,
    0x3f800000u,
    0xbf800000u,
    0x3f000000u,
    0xbf000000u, // -0.5: defined conversion to unsigned zero
    0x40000000u,
    0x40400000u,
    0x3dcccccdu,
    0x3eaaaaabu,
    0x40490fdbu,
    0x00000001u,
    0x007fffffu,
    0x00800000u,
    0x7f7fffffu,
    0x7f800000u,
    0xff800000u,
    0x7fc00000u,
    0x7fa00000u,
    0x4b000000u, // 2^23
    0x4b800000u, // 2^24
    0x5f000000u, // 2^63
    0x5f800000u, // 2^64
    0xdf000000u, // -2^63
    0x5effffffu, // largest float below 2^63
    0x5f7fffffu, // largest float below 2^64
    0x3f7fffffu, // largest float below 1
};

static u64 random_double_bits(void) {
    switch (next_random() % 8) {
        case 0:
            return double_specials[next_random() % (sizeof(double_specials) / sizeof(double_specials[0]))];
        case 1: // subnormal
            return (next_random() & 0x800fffffffffffffull);
        case 2: // exponent near one
            return (next_random() & 0x800fffffffffffffull) | ((1013ull + next_random() % 21) << 52);
        case 3: // integer-valued
            return bits_of_double((double)(i64)(next_random() >> (next_random() & 63)));
        case 4: // few significant bits, exact fractions
            return (next_random() & 0x800ff00000000000ull) | ((900ull + next_random() % 250) << 52);
        case 5: // near the top of the range
            return (next_random() & 0x800fffffffffffffull) | ((2030ull + next_random() % 17) << 52);
        case 6: // near the bottom of the normal range
            return (next_random() & 0x800fffffffffffffull) | ((1ull + next_random() % 60) << 52);
        default:
            return next_random();
    }
}

// A second operand with an exponent close to the first: exercises the
// cancellation and alignment paths of add/sub and the small quotients of
// division and remainder.
static u64 nearby_double_bits(u64 a) {
    if (next_random() & 1) {
        return random_double_bits();
    }
    u64 exponent = (a >> 52) & 0x7ff;
    i64 delta = (i64)(next_random() % 7) - 3;
    i64 candidate = (i64)exponent + delta;
    if (candidate < 0) {
        candidate = 0;
    }
    if (candidate > 0x7fe) {
        candidate = 0x7fe;
    }
    u64 mantissa = (next_random() & 1) ? (a & 0x000fffffffffffffull) : (next_random() & 0x000fffffffffffffull);
    return (next_random() << 63) | ((u64)candidate << 52) | mantissa;
}

static u32 random_float_bits(void) {
    switch (next_random() % 7) {
        case 0:
            return float_specials[next_random() % (sizeof(float_specials) / sizeof(float_specials[0]))];
        case 1: // subnormal
            return (u32)next_random() & 0x807fffffu;
        case 2: // exponent near one
            return ((u32)next_random() & 0x807fffffu) | ((117u + (u32)(next_random() % 21)) << 23);
        case 3: // integer-valued
            return bits_of_float((float)(i64)(next_random() >> (next_random() & 63)));
        case 4: // few significant bits
            return ((u32)next_random() & 0x807f0000u) | ((60u + (u32)(next_random() % 130)) << 23);
        case 5: // near the top of the range
            return ((u32)next_random() & 0x807fffffu) | ((240u + (u32)(next_random() % 15)) << 23);
        default:
            return (u32)next_random();
    }
}

static u32 nearby_float_bits(u32 a) {
    if (next_random() & 1) {
        return random_float_bits();
    }
    u32 exponent = (a >> 23) & 0xff;
    i64 candidate = (i64)exponent + (i64)(next_random() % 7) - 3;
    if (candidate < 0) {
        candidate = 0;
    }
    if (candidate > 0xfe) {
        candidate = 0xfe;
    }
    u32 mantissa = (next_random() & 1) ? (a & 0x007fffffu) : ((u32)next_random() & 0x007fffffu);
    return ((u32)next_random() << 31) | ((u32)candidate << 23) | mantissa;
}

static unsigned long failures;

static void report(const char* operation, u64 a, u64 b, u64 got, u64 want) {
    if (++failures <= 16) {
        fprintf(stderr, "%s(%016llx, %016llx): got %016llx, want %016llx\n", operation, a, b, got, want);
    }
}

static void expect_double(const char* operation, u64 a, u64 b, u64 got, double want) {
    u64 want_bits = bits_of_double(want);
    if (isnan(want)) {
        if (!isnan(double_of_bits(got))) {
            report(operation, a, b, got, want_bits);
        }
        return;
    }
    if (got != want_bits) {
        report(operation, a, b, got, want_bits);
    }
}

static void expect_float(const char* operation, u64 a, u64 b, u32 got, float want) {
    u32 want_bits = bits_of_float(want);
    if (isnan(want)) {
        if (!isnan(float_of_bits(got))) {
            report(operation, a, b, got, want_bits);
        }
        return;
    }
    if (got != want_bits) {
        report(operation, a, b, got, want_bits);
    }
}

static void expect_exact(const char* operation, u64 a, u64 b, u64 got, u64 want) {
    if (got != want) {
        report(operation, a, b, got, want);
    }
}

static int reference_compare(double a, double b) {
    if (isnan(a) || isnan(b)) {
        return 2;
    }
    return a < b ? -1 : a == b ? 0 : 1;
}

static void check_double_pair(u64 a, u64 b) {
    double x = double_of_bits(a), y = double_of_bits(b);
    expect_double("dadd", a, b, __bpf_dadd(a, b), x + y);
    expect_double("dsub", a, b, __bpf_dsub(a, b), x - y);
    expect_double("dmul", a, b, __bpf_dmul(a, b), x * y);
    expect_double("ddiv", a, b, __bpf_ddiv(a, b), x / y);
    expect_double("drem", a, b, __bpf_drem(a, b), fmod(x, y));
    expect_exact("dcmp", a, b, (u64)(i64)__bpf_dcmp(a, b), (u64)(i64)reference_compare(x, y));
}

static void check_double_unary(u64 a) {
    double x = double_of_bits(a);
    expect_double("dneg", a, 0, __bpf_dneg(a), -x);
    expect_float("d2f", a, 0, __bpf_d2f(a), (float)x);
    // C requires the truncated value to fit. Do not prescribe NaN/overflow
    // results; [2^63, 2^64) is valid for unsigned, as are fractions in (-1, 0).
    if (x >= -0x1p63 && x < 0x1p63) {
        expect_exact("d2i", a, 0, (u64)__bpf_d2i(a), (u64)(i64)x);
    }
    if (x > -1.0 && x < 0x1p64) {
        expect_exact("d2u", a, 0, __bpf_d2u(a), (u64)x);
    }
}

static void check_float_pair(u32 a, u32 b) {
    float x = float_of_bits(a), y = float_of_bits(b);
    expect_float("fadd", a, b, __bpf_fadd(a, b), x + y);
    expect_float("fsub", a, b, __bpf_fsub(a, b), x - y);
    expect_float("fmul", a, b, __bpf_fmul(a, b), x * y);
    expect_float("fdiv", a, b, __bpf_fdiv(a, b), x / y);
    expect_float("frem", a, b, __bpf_frem(a, b), fmodf(x, y));
    expect_exact("fcmp", a, b, (u64)(i64)__bpf_fcmp(a, b), (u64)(i64)reference_compare(x, y));
}

static void check_float_unary(u32 a) {
    float x = float_of_bits(a);
    expect_float("fneg", a, 0, __bpf_fneg(a), -x);
    expect_double("f2d", a, 0, __bpf_f2d(a), (double)x);
    if (x >= -0x1p63f && x < 0x1p63f) {
        expect_exact("f2i", a, 0, (u64)__bpf_f2i(a), (u64)(i64)x);
    }
    if (x > -1.0f && x < 0x1p64f) {
        expect_exact("f2u", a, 0, __bpf_f2u(a), (u64)x);
    }
}

static void check_integer(u64 u) {
    i64 v = (i64)u;
    expect_double("i2d", u, 0, __bpf_i2d(v), (double)v);
    expect_double("u2d", u, 0, __bpf_u2d(u), (double)u);
    expect_float("i2f", u, 0, __bpf_i2f(v), (float)v);
    expect_float("u2f", u, 0, __bpf_u2f(u), (float)u);
}

int main(int argc, char** argv) {
    // An optional seed lets a failure be reproduced or the coverage widened.
    if (argc > 1) {
        random_state = (u64)strtoull(argv[1], NULL, 0) | 1;
    }
    const size_t double_count = sizeof(double_specials) / sizeof(double_specials[0]);
    const size_t float_count = sizeof(float_specials) / sizeof(float_specials[0]);
    for (size_t i = 0; i < double_count; ++i) {
        check_double_unary(double_specials[i]);
        for (size_t j = 0; j < double_count; ++j) {
            check_double_pair(double_specials[i], double_specials[j]);
        }
    }
    for (size_t i = 0; i < float_count; ++i) {
        check_float_unary(float_specials[i]);
        for (size_t j = 0; j < float_count; ++j) {
            check_float_pair(float_specials[i], float_specials[j]);
        }
    }

    static const u64 integer_edges[] = {
        0,
        1,
        (u64)-1,
        0x7fffffffffffffffull,
        0x8000000000000000ull,
        0x8000000000000001ull,
        0xffffffffffffffffull,
        0x0020000000000000ull,
        0x0020000000000001ull,
        0x001fffffffffffffull,
        0x0000000001000000ull,
        0x0000000001000001ull,
        0x0000000000ffffffull,
        0x0000000002000003ull,
        0xfffffffffe000000ull,
        0x7ffffffffffffc00ull,
        0x7ffffffffffffe00ull,
        0x7fffffffffffff00ull,
        0x00000000ffffffffull,
    };
    for (size_t i = 0; i < sizeof(integer_edges) / sizeof(integer_edges[0]); ++i) {
        check_integer(integer_edges[i]);
    }

    for (int i = 0; i < 400000; ++i) {
        u64 a = random_double_bits();
        check_double_pair(a, nearby_double_bits(a));
        check_double_unary(a);
        u32 f = random_float_bits();
        check_float_pair(f, nearby_float_bits(f));
        check_float_unary(f);
        check_integer(next_random() >> (next_random() & 63));
        check_integer(next_random());
    }

    if (failures) {
        fprintf(stderr, "soft-float contract failed %lu times\n", failures);
        return 1;
    }
    return 0;
}
