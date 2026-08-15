// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// 128-bit unsigned division and remainder for the BPF pipeline, in pure
// 64-bit arithmetic. The backend legalizes every i128 operation by splitting
// EXCEPT mul/div/rem, which become libcalls the kernel cannot host;
// bpf-expand-i128 turns multiply into inline 64-bit schoolbook and routes
// div/rem here.
//
// This is a normalized long division, not shift-subtract: the common cases
// (divisor or dividend fits 64 bits) run in a handful of 64-bit ops, and the
// full 128/128 case is Knuth Algorithm D on two base-2^32 "digits" of divisor
// — at most two correction steps, no 128-iteration loop. Every value in and
// out is a plain i64, so nothing here needs i128 support from the backend.
//
// The pair ABI keeps arguments and result i64: {lo, hi} in, a two-field
// struct out. bpf-expand-i128 accepts either LLVM's sret form or a natural
// aggregate return, and only the pass calls these below the C level.
struct bpf_u128_pair {
    unsigned long long lo, hi;
};

static int u128_ge(unsigned long long alo, unsigned long long ahi, unsigned long long blo, unsigned long long bhi) {
    return ahi > bhi || (ahi == bhi && alo >= blo);
}

// Count leading zeros of a nonzero 64-bit value.
static int clz64(unsigned long long x) {
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

// 128 / 64 -> 128 quotient, 64 remainder, when the divisor fits 64 bits and
// the high dividend word is already < divisor (the classic two-digit step).
// Uses 32-bit sub-digits so every intermediate product stays within 64 bits.
static unsigned long long udiv_128_by_64(unsigned long long nhi, unsigned long long nlo, unsigned long long d, unsigned long long* rem) {
    // Normalize so the divisor's top bit is set.
    int s = clz64(d);
    if (s) {
        d <<= s;
        nhi = (nhi << s) | (nlo >> (64 - s));
        nlo <<= s;
    }
    unsigned long long dhi = d >> 32;
    unsigned long long dlo = d & 0xffffffffull;
    unsigned long long nlohi = nlo >> 32;
    unsigned long long nlolo = nlo & 0xffffffffull;

    // First quotient digit.
    unsigned long long q1 = nhi / dhi;
    unsigned long long r1 = nhi - q1 * dhi;
    while (q1 > 0xffffffffull || q1 * dlo > ((r1 << 32) | nlohi)) {
        q1--;
        r1 += dhi;
        if (r1 > 0xffffffffull) {
            break;
        }
    }
    unsigned long long u21 = (nhi << 32) + nlohi - q1 * d;

    // Second quotient digit.
    unsigned long long q0 = u21 / dhi;
    unsigned long long r0 = u21 - q0 * dhi;
    while (q0 > 0xffffffffull || q0 * dlo > ((r0 << 32) | nlolo)) {
        q0--;
        r0 += dhi;
        if (r0 > 0xffffffffull) {
            break;
        }
    }
    unsigned long long r = ((u21 << 32) + nlolo - q0 * d);
    *rem = r >> s;
    return (q1 << 32) | q0;
}

struct bpf_u128_pair __bpf_udiv128(unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi) {
    struct bpf_u128_pair q = {0, 0};
    if (dhi == 0) {
        if (dlo == 0) {
            return q; // division by zero: defined as 0, must not trap
        }
        if (nhi == 0) {
            q.lo = nlo / dlo; // fits entirely in 64 bits
            return q;
        }
        if (nhi < dlo) {
            unsigned long long rem;
            q.lo = udiv_128_by_64(nhi, nlo, dlo, &rem);
            return q;
        }
        // nhi >= dlo: split into two 128/64 steps across the word boundary.
        unsigned long long rem;
        q.hi = nhi / dlo;
        unsigned long long top = nhi % dlo;
        q.lo = udiv_128_by_64(top, nlo, dlo, &rem);
        return q;
    }
    // Full 128/128. Normalize on the divisor's high word, one trial digit.
    if (u128_ge(nlo, nhi, dlo, dhi) == 0) {
        return q; // dividend < divisor: quotient 0
    }
    int s = clz64(dhi);
    unsigned long long vhi, nlo2, nhi2, nex;
    if (s) {
        vhi = (dhi << s) | (dlo >> (64 - s));
        nex = nhi >> (64 - s);
        nhi2 = (nhi << s) | (nlo >> (64 - s));
        nlo2 = nlo << s;
    } else {
        vhi = dhi;
        nex = 0;
        nhi2 = nhi;
        nlo2 = nlo;
    }
    unsigned long long qhat;
    {
        // qhat = (nex:nhi2) / vhi, capped at 2^64-1.
        unsigned long long rem;
        if (nex >= vhi) {
            qhat = 0xffffffffffffffffull;
        } else if (nex == 0) {
            qhat = nhi2 / vhi;
            (void)rem;
        } else {
            qhat = udiv_128_by_64(nex, nhi2, vhi, &rem);
        }
    }
    // Multiply qhat * divisor (128-bit) and subtract; correct down if too big.
    for (int iter = 0; iter < 2 && qhat; iter++) {
        // p = qhat * (dhi:dlo), low 128 bits.
        unsigned long long p_lo, p_hi;
        {
            unsigned long long a0 = dlo & 0xffffffffull, a1 = dlo >> 32;
            unsigned long long b0 = qhat & 0xffffffffull, b1 = qhat >> 32;
            unsigned long long p00 = a0 * b0, p01 = a0 * b1;
            unsigned long long p10 = a1 * b0, p11 = a1 * b1;
            unsigned long long mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull);
            p_lo = (p00 & 0xffffffffull) | (mid << 32);
            p_hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32) + qhat * dhi;
        }
        if (u128_ge(nlo, nhi, p_lo, p_hi)) {
            break;
        }
        qhat--;
    }
    q.lo = qhat;
    return q;
}

struct bpf_u128_pair __bpf_urem128(unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi) {
    struct bpf_u128_pair r = {0, 0};
    if (dhi == 0) {
        if (dlo == 0) {
            return r;
        }
        if (nhi == 0) {
            r.lo = nlo % dlo;
            return r;
        }
        unsigned long long top = nhi % dlo;
        if (nhi >= dlo) {
            // consume the high word first, then the 128/64 step's remainder
            unsigned long long rem;
            udiv_128_by_64(top, nlo, dlo, &rem);
            r.lo = rem;
            return r;
        }
        unsigned long long rem;
        udiv_128_by_64(nhi, nlo, dlo, &rem);
        r.lo = rem;
        return r;
    }
    if (u128_ge(nlo, nhi, dlo, dhi) == 0) {
        r.lo = nlo;
        r.hi = nhi;
        return r;
    }
    // r = n - q*d, with q from __bpf_udiv128 (single 128-bit digit).
    struct bpf_u128_pair q = __bpf_udiv128(nlo, nhi, dlo, dhi);
    unsigned long long qd_lo, qd_hi;
    {
        unsigned long long a0 = dlo & 0xffffffffull, a1 = dlo >> 32;
        unsigned long long b0 = q.lo & 0xffffffffull, b1 = q.lo >> 32;
        unsigned long long p00 = a0 * b0, p01 = a0 * b1;
        unsigned long long p10 = a1 * b0, p11 = a1 * b1;
        unsigned long long mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull);
        qd_lo = (p00 & 0xffffffffull) | (mid << 32);
        qd_hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32) + q.lo * dhi;
    }
    unsigned long long borrow = nlo < qd_lo;
    r.lo = nlo - qd_lo;
    r.hi = nhi - qd_hi - borrow;
    return r;
}
