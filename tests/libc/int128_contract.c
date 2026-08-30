// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "bpf_capsule_arithmetic.h"

#include <stdint.h>
#include <stdio.h>

typedef unsigned __int128 u128;
typedef __int128 i128;

struct bpf_u128_pair __bpf_udiv128(unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi);
struct bpf_u128_pair __bpf_urem128(unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi);
struct bpf_u128_pair __bpf_sdiv128(unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi);
struct bpf_u128_pair __bpf_srem128(unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi);

struct bpf_u128_pair __bpf_mul64_wide(unsigned long long a, unsigned long long b) {
    u128 product = (u128)a * b;
    return (struct bpf_u128_pair){(uint64_t)product, (uint64_t)(product >> 64)};
}

static u128 join(struct bpf_u128_pair value) {
    return ((u128)value.hi << 64) | value.lo;
}

static int check_unsigned(u128 dividend, u128 divisor) {
    uint64_t nlo = dividend, nhi = dividend >> 64;
    uint64_t dlo = divisor, dhi = divisor >> 64;
    u128 quotient = join(__bpf_udiv128(nlo, nhi, dlo, dhi));
    u128 remainder = join(__bpf_urem128(nlo, nhi, dlo, dhi));
    if (quotient == dividend / divisor && remainder == dividend % divisor) {
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
    uint64_t nlo = dividend_bits, nhi = dividend_bits >> 64;
    uint64_t dlo = divisor_bits, dhi = divisor_bits >> 64;
    u128 quotient = join(__bpf_sdiv128(nlo, nhi, dlo, dhi));
    u128 remainder = join(__bpf_srem128(nlo, nhi, dlo, dhi));
    if (quotient == (u128)(dividend / divisor) && remainder == (u128)(dividend % divisor)) {
        return 0;
    }
    fprintf(stderr, "int128 signed division contract failed\n");
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
    failures += check_unsigned(((u128)0xfffffffffffffffeull << 64) | 0xdc8f2ca367a4c16full, ((u128)0x000000000000000cull << 64) | 0x0003ffffffffffffull);
    failures += check_unsigned(((u128)0xffffffffffffffffull << 64) | 0xd65f110a8e27e567ull, ((u128)0x000000000000000cull << 64) | 0x0000003fffffffffull);

    for (int i = 0; i < 50000 && failures == 0; i++) {
        u128 dividend = ((u128)(UINT64_MAX - (next_random() & 3)) << 64) | next_random();
        u128 divisor = ((u128)(1 + next_random() % 65536) << 64) | next_random();
        failures += check_unsigned(dividend, divisor);
        failures += check_signed(((u128)next_random() << 64) | next_random(), ((u128)next_random() << 64) | next_random());
    }
    return failures ? 1 : 0;
}
