// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "bpf_capsule_arithmetic.h"
// 128-bit multiplication, division and remainder for the BPF pipeline, in
// pure 64-bit arithmetic. The backend legalizes every i128 operation by
// splitting EXCEPT mul/div/rem, which become libcalls the kernel cannot host;
// bpf-expand-i128 routes those here.
//
// This is a normalized long division, not shift-subtract: the common cases
// (divisor or dividend fits 64 bits) run in a handful of 64-bit ops, and the
// full 128/128 case is Knuth Algorithm D with one trial digit and at most two
// correction steps. Nothing below contains a loop, so no division site pays
// for a chunked or simulated loop.
//
// The pair ABI keeps arguments and result i64: {lo, hi} in, a two-field
// struct out (bpf_capsule_arithmetic.h). bpf-expand-i128 accepts either LLVM's
// sret form or a natural aggregate return, and only the pass calls these
// below the C level.

// 64x64 -> 128 as {lo, hi}, in 64-bit arithmetic only. Every wide product in
// this file and in softfloat.c goes through here; the overflow-multiply
// intrinsics (TLSF's allocator math is the usual source) do too.
extern inline __attribute__((always_inline)) struct bpf_u128_pair __bpf_mul64_wide(unsigned long long a, unsigned long long b) {
    unsigned long long a0 = a & 0xffffffffull, a1 = a >> 32;
    unsigned long long b0 = b & 0xffffffffull, b1 = b >> 32;
    unsigned long long p00 = a0 * b0, p01 = a0 * b1;
    unsigned long long p10 = a1 * b0, p11 = a1 * b1;
    unsigned long long lo1 = p00 + ((p01 & 0xffffffffull) << 32);
    unsigned long long c1 = lo1 < p00;
    unsigned long long lo2 = lo1 + ((p10 & 0xffffffffull) << 32);
    unsigned long long c2 = lo2 < lo1;
    struct bpf_u128_pair r;
    r.lo = lo2;
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + c1 + c2;
    return r;
}

// {value, overflowed} for the 64-bit overflow-multiply intrinsics.
extern inline __attribute__((always_inline)) struct bpf_u128_pair __bpf_umul64_overflow(unsigned long long a, unsigned long long b) {
    struct bpf_u128_pair p = __bpf_mul64_wide(a, b);
    struct bpf_u128_pair r;
    r.lo = p.lo;
    r.hi = p.hi != 0;
    return r;
}

extern inline __attribute__((always_inline)) struct bpf_u128_pair __bpf_smul64_overflow(unsigned long long a, unsigned long long b) {
    struct bpf_u128_pair p = __bpf_mul64_wide(a, b);
    // Signed high half: adjust the unsigned one, then the product fits iff
    // it equals the sign-extension of the low half.
    unsigned long long shi = p.hi - (((long long)a < 0) ? b : 0) - (((long long)b < 0) ? a : 0);
    struct bpf_u128_pair r;
    r.lo = p.lo;
    r.hi = shi != (unsigned long long)((long long)p.lo >> 63);
    return r;
}

static __attribute__((always_inline)) int u128_ge(unsigned long long alo, unsigned long long ahi, unsigned long long blo, unsigned long long bhi) {
    return ahi > bhi || (ahi == bhi && alo >= blo);
}

// Does qhat * (dhi:dlo) exceed (nhi:nlo)? The product may carry past 128
// bits; that carry alone already answers yes.
static __attribute__((always_inline)) int qhat_too_large(
    unsigned long long qhat, unsigned long long dlo, unsigned long long dhi, unsigned long long nlo, unsigned long long nhi) {
    struct bpf_u128_pair low = __bpf_mul64_wide(qhat, dlo);
    struct bpf_u128_pair high = __bpf_mul64_wide(qhat, dhi);
    unsigned long long p_hi = low.hi + high.lo;
    if (high.hi != 0 || p_hi < low.hi) {
        return 1;
    }
    return !u128_ge(nlo, nhi, low.lo, p_hi);
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
            q.lo = __bpf_udiv_128_by_64(nhi, nlo, dlo, __bpf_clz64(dlo), &rem);
            return q;
        }
        // nhi >= dlo: split into two 128/64 steps across the word boundary.
        unsigned long long rem;
        q.hi = nhi / dlo;
        unsigned long long top = nhi % dlo;
        q.lo = __bpf_udiv_128_by_64(top, nlo, dlo, __bpf_clz64(dlo), &rem);
        return q;
    }
    // Full 128/128. Normalize on the divisor's high word, one trial digit.
    if (u128_ge(nlo, nhi, dlo, dhi) == 0) {
        return q; // dividend < divisor: quotient 0
    }
    int s = __bpf_clz64(dhi);
    unsigned long long vhi, nhi2, nex;
    if (s) {
        vhi = (dhi << s) | (dlo >> (64 - s));
        nex = nhi >> (64 - s);
        nhi2 = (nhi << s) | (nlo >> (64 - s));
    } else {
        vhi = dhi;
        nex = 0;
        nhi2 = nhi;
    }
    unsigned long long qhat;
    {
        // qhat = (nex:nhi2) / vhi, capped at 2^64-1.
        if (nex >= vhi) {
            qhat = 0xffffffffffffffffull;
        } else if (nex == 0) {
            qhat = nhi2 / vhi;
        } else {
            unsigned long long rem;
            qhat = __bpf_udiv_128_by_64(nex, nhi2, vhi, 0, &rem);
        }
    }
    // The estimate is at most two too large (Knuth, Theorem B): two
    // conditional corrections, no loop.
    if (qhat && qhat_too_large(qhat, dlo, dhi, nlo, nhi)) {
        qhat--;
    }
    if (qhat && qhat_too_large(qhat, dlo, dhi, nlo, nhi)) {
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
            __bpf_udiv_128_by_64(top, nlo, dlo, __bpf_clz64(dlo), &rem);
            r.lo = rem;
            return r;
        }
        unsigned long long rem;
        __bpf_udiv_128_by_64(nhi, nlo, dlo, __bpf_clz64(dlo), &rem);
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
    struct bpf_u128_pair qd = __bpf_mul64_wide(q.lo, dlo);
    unsigned long long qd_hi = qd.hi + q.lo * dhi;
    unsigned long long borrow = nlo < qd.lo;
    r.lo = nlo - qd.lo;
    r.hi = nhi - qd_hi - borrow;
    return r;
}

// ---------------------------------------------------------------------------
// The remaining i128 arithmetic bpf-expand-i128 routes here instead of
// emitting IR expansions: 128-bit multiply and the signed division/remainder
// fixups. always_inline: after the whole-program link, -O2 folds these into
// their call sites exactly as the old IR expansions did — a constant operand
// still folds to shifts, and no subprogram survives for the verifier to
// re-walk. The unsigned udiv/urem above deliberately stay real calls: their
// bodies are verified once instead of at every division site.
// ---------------------------------------------------------------------------

extern inline __attribute__((always_inline)) struct bpf_u128_pair __bpf_mul128(
    unsigned long long alo, unsigned long long ahi, unsigned long long blo, unsigned long long bhi) {
    struct bpf_u128_pair r = __bpf_mul64_wide(alo, blo);
    r.hi += alo * bhi + ahi * blo;
    return r;
}

static __attribute__((always_inline)) struct bpf_u128_pair bpf_u128_negate(unsigned long long lo, unsigned long long hi) {
    struct bpf_u128_pair r;
    r.lo = 0 - lo;
    r.hi = 0 - hi - (lo != 0);
    return r;
}

// Quotient flips when the operand signs differ; remainder takes the
// dividend's sign. The fixups inline; the unsigned division stays a call.
extern inline __attribute__((always_inline)) struct bpf_u128_pair __bpf_sdiv128(
    unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi) {
    int negN = (long long)nhi < 0;
    int negD = (long long)dhi < 0;
    struct bpf_u128_pair n = negN ? bpf_u128_negate(nlo, nhi) : (struct bpf_u128_pair){nlo, nhi};
    struct bpf_u128_pair d = negD ? bpf_u128_negate(dlo, dhi) : (struct bpf_u128_pair){dlo, dhi};
    struct bpf_u128_pair q = __bpf_udiv128(n.lo, n.hi, d.lo, d.hi);
    return negN != negD ? bpf_u128_negate(q.lo, q.hi) : q;
}

extern inline __attribute__((always_inline)) struct bpf_u128_pair __bpf_srem128(
    unsigned long long nlo, unsigned long long nhi, unsigned long long dlo, unsigned long long dhi) {
    int negN = (long long)nhi < 0;
    int negD = (long long)dhi < 0;
    struct bpf_u128_pair n = negN ? bpf_u128_negate(nlo, nhi) : (struct bpf_u128_pair){nlo, nhi};
    struct bpf_u128_pair d = negD ? bpf_u128_negate(dlo, dhi) : (struct bpf_u128_pair){dlo, dhi};
    struct bpf_u128_pair r = __bpf_urem128(n.lo, n.hi, d.lo, d.hi);
    return negN ? bpf_u128_negate(r.lo, r.hi) : r;
}
