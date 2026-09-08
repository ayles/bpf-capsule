// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Private C linkage inside the compiler runtime: the 64-bit building blocks
// used by int128.c. Everything defined here is loop-free,
// so a routine built on it can still be proven non-suspendable.
#pragma once

struct bpf_u128_pair {
    unsigned long long lo;
    unsigned long long hi;
};

// 64x64 -> 128 as {lo, hi}, defined in int128.c. bpf-expand-i128 also lowers
// the 64-bit overflow-multiply intrinsics onto the wrappers beside it.
struct bpf_u128_pair __bpf_mul64_wide(unsigned long long a, unsigned long long b);

// Leading zeros of a nonzero 64-bit value: a six-step binary search.
static __attribute__((always_inline)) inline int __bpf_clz64(unsigned long long x) {
    int n = 0;
    if (x <= 0x00000000ffffffffull) {
        n += 32;
        x <<= 32;
    }
    if (x <= 0x0000ffffffffffffull) {
        n += 16;
        x <<= 16;
    }
    if (x <= 0x00ffffffffffffffull) {
        n += 8;
        x <<= 8;
    }
    if (x <= 0x0fffffffffffffffull) {
        n += 4;
        x <<= 4;
    }
    if (x <= 0x3fffffffffffffffull) {
        n += 2;
        x <<= 2;
    }
    if (x <= 0x7fffffffffffffffull) {
        n += 1;
    }
    return n;
}

// 128 / 64 -> 64-bit quotient and remainder for nhi < d and s = clz(d):
// the two-digit step
// of Knuth's Algorithm D over base-2^32 digits, so every intermediate product
// fits in 64 bits. Each digit estimate needs at most two corrections; they
// are spelled as two conditional steps rather than a loop so the function is
// a DAG. Callers supply the normalization shift: soft-float already knows
// it from the significand width, avoiding another branch tree in the verifier.
static __attribute__((always_inline)) inline unsigned long long __bpf_udiv_128_by_64(
    unsigned long long nhi, unsigned long long nlo, unsigned long long d, int s, unsigned long long* rem) {
    if (s) {
        d <<= s;
        nhi = (nhi << s) | (nlo >> (64 - s));
        nlo <<= s;
    }
    unsigned long long dhi = d >> 32;
    unsigned long long dlo = d & 0xffffffffull;
    unsigned long long nlohi = nlo >> 32;
    unsigned long long nlolo = nlo & 0xffffffffull;

    unsigned long long q1 = nhi / dhi;
    unsigned long long r1 = nhi - q1 * dhi;
    if (q1 > 0xffffffffull || q1 * dlo > ((r1 << 32) | nlohi)) {
        q1--;
        r1 += dhi;
        if (r1 <= 0xffffffffull && (q1 > 0xffffffffull || q1 * dlo > ((r1 << 32) | nlohi))) {
            q1--;
            r1 += dhi;
        }
    }
    unsigned long long u21 = (nhi << 32) + nlohi - q1 * d;

    unsigned long long q0 = u21 / dhi;
    unsigned long long r0 = u21 - q0 * dhi;
    if (q0 > 0xffffffffull || q0 * dlo > ((r0 << 32) | nlolo)) {
        q0--;
        r0 += dhi;
        if (r0 <= 0xffffffffull && (q0 > 0xffffffffull || q0 * dlo > ((r0 << 32) | nlolo))) {
            q0--;
            r0 += dhi;
        }
    }
    unsigned long long r = (u21 << 32) + nlolo - q0 * d;
    *rem = r >> s;
    return (q1 << 32) | q0;
}
