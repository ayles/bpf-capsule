// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <stdint.h>
#include <stdio.h>

typedef unsigned __int128 u128;
typedef __int128 i128;

i128 __multi3(i128, i128);
u128 __udivti3(u128, u128);
u128 __umodti3(u128, u128);
i128 __divti3(i128, i128);
i128 __modti3(i128, i128);
int64_t __mulodi4(int64_t, int64_t, int*);

static int check_mul64_wide(uint64_t a, uint64_t b) {
    u128 product = (u128)a * b;
    u128 got = __multi3(a, b);
    if (got == product) {
        return 0;
    }
    fprintf(stderr, "wide multiplication contract failed\n");
    return 1;
}

static int check_unsigned(u128 dividend, u128 divisor) {
    u128 quotient = __udivti3(dividend, divisor);
    u128 remainder = __umodti3(dividend, divisor);
    if (quotient == dividend / divisor && remainder == dividend % divisor && __multi3(dividend, divisor) == dividend * divisor) {
        return 0;
    }
    fprintf(stderr, "int128 unsigned division contract failed\n");
    return 1;
}

static int check_signed(u128 dividend_bits, u128 divisor_bits) {
    i128 dividend = (i128)dividend_bits;
    i128 divisor = (i128)divisor_bits;
    if (divisor == 0 || (dividend_bits == ((u128)1 << 127) && divisor == -1)) {
        return 0;
    }
    i128 quotient = __divti3(dividend, divisor);
    i128 remainder = __modti3(dividend, divisor);
    if (quotient == dividend / divisor && remainder == dividend % divisor) {
        return 0;
    }
    fprintf(stderr, "int128 signed division contract failed\n");
    return 1;
}

static int check_overflow(int64_t a, int64_t b) {
    int overflow;
    int64_t expected;
    int expected_overflow = __builtin_mul_overflow(a, b, &expected);
    int64_t product = __mulodi4(a, b, &overflow);
    if (product == expected && !!overflow == expected_overflow) {
        return 0;
    }
    fprintf(stderr, "signed multiply overflow contract failed\n");
    return 1;
}

static uint64_t random_state = 0x0123456789abcdefull;

static uint64_t next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

int main(void) {
    int failures = 0;
    const int64_t edges[] = {0, 1, -1, 2, -2, INT32_MAX, INT32_MIN, INT64_MAX, INT64_MIN};
    for (unsigned i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        for (unsigned j = 0; j < sizeof(edges) / sizeof(edges[0]); ++j) {
            failures += check_overflow(edges[i], edges[j]);
        }
    }
    failures += check_unsigned(((u128)0xfffffffffffffffeull << 64) | 0xdc8f2ca367a4c16full, ((u128)0x000000000000000cull << 64) | 0x0003ffffffffffffull);
    failures += check_unsigned(((u128)0xffffffffffffffffull << 64) | 0xd65f110a8e27e567ull, ((u128)0x000000000000000cull << 64) | 0x0000003fffffffffull);

    for (int i = 0; i < 50000 && failures == 0; i++) {
        u128 dividend = ((u128)(UINT64_MAX - (next_random() & 3)) << 64) | next_random();
        u128 divisor = ((u128)(1 + next_random() % 65536) << 64) | next_random();
        failures += check_unsigned(dividend, divisor);
        failures += check_signed(((u128)next_random() << 64) | next_random(), ((u128)next_random() << 64) | next_random());
        failures += check_mul64_wide(next_random(), next_random());
        failures += check_overflow(next_random(), next_random());
        // Divisors that fit 64 bits take the two-digit path, including its
        // correction steps; the high dividend word must exercise both sides
        // of the "nhi < dlo" split.
        uint64_t narrow = 1 + (next_random() >> (next_random() & 63));
        failures += check_unsigned(((u128)next_random() << 64) | next_random(), narrow);
        failures += check_unsigned(((u128)(narrow - 1) << 64) | next_random(), narrow);
    }
    return failures ? 1 : 0;
}
