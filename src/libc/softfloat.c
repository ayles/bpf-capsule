// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// IEEE-754 double arithmetic in integers, for a machine with no floating
// point at all.
//
// Values travel as their bit patterns in 64-bit integers; bpf-soft-float
// rewrites every floating-point operation in the program into a call to one
// of these. Each routine implements round-to-nearest-even and can be tested
// differentially against the same operation compiled for hardware.
//
// Add, subtract and multiply have direct binary32 implementations. Widening
// to binary64 first is exact, but needlessly pays for two conversions and the
// much wider significand arithmetic at every operation. The less frequent
// single-precision operations still share the binary64 implementation below;
// divide can therefore double-round and differ from hardware by one ulp.

#include "bpf_capsule.h"

typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;

#define EXP_BITS 0x7ffull
#define MAN_BITS 52
#define MAN_MASK ((1ull << MAN_BITS) - 1)
#define HIDDEN (1ull << MAN_BITS)

#define F_EXP_BITS 0xffu
#define F_MAN_BITS 23
#define F_MAN_MASK ((1u << F_MAN_BITS) - 1)
#define F_HIDDEN (1u << F_MAN_BITS)

// Leading-zero count without a loop or data-dependent CFG.  Saturate all bits
// below the most-significant one, then popcount the saturated word with SWAR;
// 64 - popcount is clz (and naturally returns 64 for zero).  A six-branch
// binary-search version looks cheaper, but two calls produce up to 64 verifier
// states.  Carrying all of them through division's 56 iterations exhausts the
// one-million-insn analysis limit even when the division body is branchless.
static __attribute__((always_inline)) int __bpf_nlz64(u64 x) {
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x -= (x >> 1) & 0x5555555555555555ull;
    x = (x & 0x3333333333333333ull) + ((x >> 2) & 0x3333333333333333ull);
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0full;
    x += x >> 8;
    x += x >> 16;
    x += x >> 32;
    return 64 - (int)(x & 0x7f);
}

static __attribute__((always_inline)) u64 __bpf_d_make(u64 sign, i64 exp, u64 man) {
    if (exp >= 0x7ff) {
        return (sign << 63) | (EXP_BITS << MAN_BITS); // overflow
    }
    if (exp <= 0) { // subnormal
        if (exp < -60) {
            return sign << 63;
        }
        u64 sticky = (man & ((1ull << (1 - exp)) - 1)) != 0;
        man >>= (1 - exp);
        man |= sticky;
        exp = 0;
    }
    return (sign << 63) | ((u64)exp << MAN_BITS) | (man & MAN_MASK);
}

// Round a 55-bit significand (52 value bits plus guard, round and sticky in
// the low three) to nearest, ties to even.
static __attribute__((always_inline)) void __bpf_d_round(u64* man, i64* exp) {
    u64 low = *man & 7;
    *man >>= 3;
    if (low > 4 || (low == 4 && (*man & 1))) {
        (*man)++;
        if (*man > MAN_MASK + HIDDEN) {
            *man >>= 1;
            (*exp)++;
        }
    }
}

// Assemble a result from a significand whose leading bit sits at position 55
// (52 value bits plus guard, round and sticky). Underflow has to denormalize
// *before* rounding, or the rounding decision is made at the wrong bit and
// the answer differs from hardware by one unit in the last place.
static __attribute__((always_inline)) u64 __bpf_d_pack(u64 sign, i64 exp, u64 man) {
    if (exp <= 0) {
        i64 sh = 1 - exp;
        if (sh > 62) {
            return sign << 63;
        }
        u64 sticky = (man & ((1ull << sh) - 1)) != 0;
        man = (man >> sh) | sticky;
        exp = 0;
    }
    __bpf_d_round(&man, &exp);
    if (man & HIDDEN) {
        man &= MAN_MASK;
        if (!exp) {
            exp = 1;
        }
    }
    if (!(man | (u64)exp)) {
        return sign << 63;
    }
    if (exp >= 0x7ff) {
        return (sign << 63) | (EXP_BITS << MAN_BITS);
    }
    return (sign << 63) | ((u64)exp << MAN_BITS) | (man & MAN_MASK);
}

static __attribute__((always_inline)) int __bpf_d_isnan(u64 x) {
    return ((x >> MAN_BITS) & EXP_BITS) == EXP_BITS && (x & MAN_MASK);
}
static __attribute__((always_inline)) int __bpf_d_isinf(u64 x) {
    return ((x >> MAN_BITS) & EXP_BITS) == EXP_BITS && !(x & MAN_MASK);
}

// Assemble a binary32 value from a significand with its leading bit at bit 26
// (23 value bits plus guard, round and sticky).  Keeping the intermediate in
// u64 makes every variable shift defined even for a large exponent gap.
static __attribute__((always_inline)) u32 __bpf_f_pack(u32 sign, i64 exp, u64 man) {
    if (exp <= 0) {
        i64 sh = 1 - exp;
        if (sh > 63) {
            return sign << 31;
        }
        u64 sticky = (man & ((1ull << sh) - 1)) != 0;
        man = (man >> sh) | sticky;
        exp = 0;
    }

    u64 low = man & 7;
    man >>= 3;
    if (low > 4 || (low == 4 && (man & 1))) {
        man++;
        if (man > F_MAN_MASK + F_HIDDEN) {
            man >>= 1;
            exp++;
        }
    }

    if (man & F_HIDDEN) {
        man &= F_MAN_MASK;
        if (!exp) {
            exp = 1;
        }
    } else {
        exp = 0;
    }
    if (exp >= F_EXP_BITS) {
        return (sign << 31) | (F_EXP_BITS << F_MAN_BITS);
    }
    return (sign << 31) | ((u32)exp << F_MAN_BITS) | (u32)man;
}

static __attribute__((always_inline)) int __bpf_f_isnan(u32 x) {
    return ((x >> F_MAN_BITS) & F_EXP_BITS) == F_EXP_BITS && (x & F_MAN_MASK);
}

static __attribute__((always_inline)) int __bpf_f_isinf(u32 x) {
    return ((x >> F_MAN_BITS) & F_EXP_BITS) == F_EXP_BITS && !(x & F_MAN_MASK);
}

__attribute__((noinline)) u64 __bpf_dadd(u64 a, u64 b) {
    if (__bpf_d_isnan(a)) {
        return a | (1ull << 51);
    }
    if (__bpf_d_isnan(b)) {
        return b | (1ull << 51);
    }

    u64 sa = a >> 63, sb = b >> 63;
    i64 ea = (i64)((a >> MAN_BITS) & EXP_BITS), eb = (i64)((b >> MAN_BITS) & EXP_BITS);
    u64 ma = a & MAN_MASK, mb = b & MAN_MASK;

    if (__bpf_d_isinf(a)) {
        return (__bpf_d_isinf(b) && sa != sb) ? 0x7ff8000000000000ull : a;
    }
    if (__bpf_d_isinf(b)) {
        return b;
    }
    if (!ea && !ma) {
        return (!eb && !mb) ? (a & b) : b; // +-0 + x
    }
    if (!eb && !mb) {
        return a;
    }

    // Normalise: subnormals have exponent 1 with no hidden bit.
    if (ea) {
        ma |= HIDDEN;
    } else {
        ea = 1;
    }
    if (eb) {
        mb |= HIDDEN;
    } else {
        eb = 1;
    }

    // Three extra low bits carry guard, round and sticky through the shift.
    ma <<= 3;
    mb <<= 3;
    if (ea < eb) {
        i64 t = ea;
        ea = eb;
        eb = t;
        u64 tm = ma;
        ma = mb;
        mb = tm;
        u64 ts = sa;
        sa = sb;
        sb = ts;
    }
    i64 shift = ea - eb;
    if (shift > 63) {
        mb = 1;
    } else if (shift) {
        u64 sticky = (mb & ((1ull << shift) - 1)) != 0;
        mb = (mb >> shift) | sticky;
    }

    u64 sign = sa, man;
    if (sa == sb) {
        man = ma + mb;
        if (man >> (MAN_BITS + 4)) { // carried out
            u64 sticky = man & 1;
            man = (man >> 1) | sticky;
            ea++;
        }
    } else {
        if (ma >= mb) {
            man = ma - mb;
        } else {
            man = mb - ma;
            sign = sb;
        }
        if (!man) {
            return 0; // exact cancellation
        }
        {
            int sh = __bpf_nlz64(man) - 8; // bit 55 is the target
            if (sh > (int)(ea - 1)) {
                sh = (int)(ea - 1);
            }
            if (sh > 0) {
                man <<= sh;
                ea -= sh;
            }
        }
    }
    return __bpf_d_pack(sign, ea, man);
}

__attribute__((always_inline)) u64 __bpf_dneg(u64 a) {
    return a ^ (1ull << 63);
}
u64 __bpf_dsub(u64 a, u64 b) {
    return __bpf_dadd(a, __bpf_dneg(b));
}

// 64x64 -> 128 multiply, in halves.
static __attribute__((always_inline)) void __bpf_mul64(u64 a, u64 b, u64* hi, u64* lo) {
    u64 al = a & 0xffffffffull, ah = a >> 32;
    u64 bl = b & 0xffffffffull, bh = b >> 32;
    u64 ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    u64 mid = (ll >> 32) + (lh & 0xffffffffull) + (hl & 0xffffffffull);
    *lo = (ll & 0xffffffffull) | (mid << 32);
    *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

__attribute__((noinline)) u64 __bpf_dmul(u64 a, u64 b) {
    if (__bpf_d_isnan(a)) {
        return a | (1ull << 51);
    }
    if (__bpf_d_isnan(b)) {
        return b | (1ull << 51);
    }
    u64 sign = (a >> 63) ^ (b >> 63);
    i64 ea = (i64)((a >> MAN_BITS) & EXP_BITS), eb = (i64)((b >> MAN_BITS) & EXP_BITS);
    u64 ma = a & MAN_MASK, mb = b & MAN_MASK;

    int azero = !ea && !ma, bzero = !eb && !mb;
    if (__bpf_d_isinf(a)) {
        return (bzero) ? 0x7ff8000000000000ull : (sign << 63) | (EXP_BITS << MAN_BITS);
    }
    if (__bpf_d_isinf(b)) {
        return (azero) ? 0x7ff8000000000000ull : (sign << 63) | (EXP_BITS << MAN_BITS);
    }
    if (azero || bzero) {
        return sign << 63;
    }

    if (ea) {
        ma |= HIDDEN;
    } else {
        ea = 1;
    }
    if (eb) {
        mb |= HIDDEN;
    } else {
        eb = 1;
    }
    {
        int sh = __bpf_nlz64(ma) - 11;
        ma <<= sh;
        ea -= sh;
    }
    {
        int sh = __bpf_nlz64(mb) - 11;
        mb <<= sh;
        eb -= sh;
    }

    u64 hi, lo;
    __bpf_mul64(ma, mb, &hi, &lo);
    // Two 53-bit significands give a product of 105 or 106 bits. Either way
    // it has to arrive with its leading bit at position 55, so that the three
    // low bits are the guard, round and sticky the rounding step expects.
    i64 exp = ea + eb - 1023;
    u64 man, sticky;
    if (hi >> 41) { // 106 bits: leading bit at 105
        man = (hi << 14) | (lo >> 50);
        sticky = (lo & ((1ull << 50) - 1)) != 0;
        exp++;
    } else { // 105 bits: leading bit at 104
        man = (hi << 15) | (lo >> 49);
        sticky = (lo & ((1ull << 49) - 1)) != 0;
    }
    man |= sticky;
    return __bpf_d_pack(sign, exp, man);
}

__attribute__((noinline)) u64 __bpf_ddiv(u64 a, u64 b) {
    if (__bpf_d_isnan(a)) {
        return a | (1ull << 51);
    }
    if (__bpf_d_isnan(b)) {
        return b | (1ull << 51);
    }
    u64 sign = (a >> 63) ^ (b >> 63);
    i64 ea = (i64)((a >> MAN_BITS) & EXP_BITS), eb = (i64)((b >> MAN_BITS) & EXP_BITS);
    u64 ma = a & MAN_MASK, mb = b & MAN_MASK;
    int azero = !ea && !ma, bzero = !eb && !mb;

    if (__bpf_d_isinf(a)) {
        return __bpf_d_isinf(b) ? 0x7ff8000000000000ull : (sign << 63) | (EXP_BITS << MAN_BITS);
    }
    if (__bpf_d_isinf(b)) {
        return sign << 63;
    }
    if (bzero) {
        return azero ? 0x7ff8000000000000ull : (sign << 63) | (EXP_BITS << MAN_BITS);
    }
    if (azero) {
        return sign << 63;
    }

    if (ea) {
        ma |= HIDDEN;
    } else {
        ea = 1;
    }
    if (eb) {
        mb |= HIDDEN;
    } else {
        eb = 1;
    }
    {
        int sh = __bpf_nlz64(ma) - 11;
        ma <<= sh;
        ea -= sh;
    }
    {
        int sh = __bpf_nlz64(mb) - 11;
        mb <<= sh;
        eb -= sh;
    }

    // Long division producing 56 quotient bits.
    i64 exp = ea - eb + 1023;
    u64 rem = ma, quo = 0;
    // Really branchless unsigned subtract.  Writing `rem >= mb` looks like a
    // mask in LLVM IR, but BPF has no condition-code/cmov instruction and its
    // backend lowers the materialized comparison back to a branch.  That
    // forks verifier state on every one of the 56 iterations and exhausts the
    // million-insn analysis budget.  The top bit of this standard borrow
    // identity gives the same all-zero/all-one mask using integer operations
    // only, so the JIT and verifier both see one path through the loop.
    for (int i = 0; i < MAN_BITS + 4; i++) {
        quo <<= 1;
        u64 diff = rem - mb;
        u64 borrow = ((~rem & mb) | (~(rem ^ mb) & diff)) >> 63;
        u64 ge = borrow - 1; // all ones when rem >= mb
        rem -= mb & ge;
        quo |= 1u & ge;
        rem <<= 1;
    }
    quo |= (rem != 0); // sticky
    if (quo >> (MAN_BITS + 4)) {
        u64 s = quo & 1;
        quo = (quo >> 1) | s;
        exp++;
    } else {
        int sh = __bpf_nlz64(quo) - 8;
        if (sh > (int)(exp - 1)) {
            sh = (int)(exp - 1);
        }
        if (sh > 0) {
            quo <<= sh;
            exp -= sh;
        }
    }
    return __bpf_d_pack(sign, exp, quo);
}

// -1 less, 0 equal, 1 greater, 2 unordered. Keep this out of line: inlining
// the comparison body has reproduced a post-Stackify optimizer miscompile in
// the Rust workload on both instruction tiers.
__attribute__((noinline)) int __bpf_dcmp(u64 a, u64 b) {
    if (__bpf_d_isnan(a) || __bpf_d_isnan(b)) {
        return 2;
    }
    if (!(a << 1) && !(b << 1)) {
        return 0; // +0 == -0
    }
    if (a == b) {
        return 0;
    }
    int na = (int)(a >> 63), nb = (int)(b >> 63);
    if (na != nb) {
        return na ? -1 : 1;
    }
    // Same sign: the bit patterns order like magnitudes.
    int gt = a > b;
    if (na) {
        gt = !gt;
    }
    return gt ? 1 : -1;
}

CAPSULE_NOSUSPEND u64 __bpf_i2d(i64 v) {
    if (!v) {
        return 0;
    }
    u64 sign = 0;
    u64 u = (u64)v;
    if (v < 0) {
        sign = 1;
        // Negate in the unsigned domain so INT64_MIN is defined.
        u = 0 - u;
    }
    i64 exp = 1023 + 63;
    {
        int sh = __bpf_nlz64(u);
        u <<= sh;
        exp -= sh;
    }
    u64 man = u >> 8; // 56 bits: 53 + guard bits
    u64 sticky = (u & 0xff) != 0;
    man |= sticky;
    return __bpf_d_pack(sign, exp, man);
}

CAPSULE_NOSUSPEND u64 __bpf_u2d(u64 u) {
    if (!u) {
        return 0;
    }
    i64 exp = 1023 + 63;
    {
        int sh = __bpf_nlz64(u);
        u <<= sh;
        exp -= sh;
    }
    u64 man = u >> 8, sticky = (u & 0xff) != 0;
    man |= sticky;
    return __bpf_d_pack(0, exp, man);
}

CAPSULE_NOSUSPEND i64 __bpf_d2i(u64 a) {
    i64 exp = (i64)((a >> MAN_BITS) & EXP_BITS) - 1023;
    if (__bpf_d_isnan(a) || exp < 0) {
        return 0;
    }
    if (exp > 62) {
        return (a >> 63) ? (i64)0x8000000000000000ull : 0x7fffffffffffffffll;
    }
    u64 man = (a & MAN_MASK) | HIDDEN;
    i64 v = exp >= MAN_BITS ? (i64)(man << (exp - MAN_BITS)) : (i64)(man >> (MAN_BITS - exp));
    return (a >> 63) ? -v : v;
}

CAPSULE_NOSUSPEND u64 __bpf_d2u(u64 a) {
    if (a >> 63) {
        return 0;
    }
    return (u64)__bpf_d2i(a);
}

// Singles: widen, operate, narrow.
__attribute__((noinline)) u64 __bpf_f2d(u32 f) {
    u64 sign = f >> 31;
    i64 exp = (f >> 23) & 0xff;
    u64 man = f & 0x7fffff;
    if (exp == 0xff) {
        return (sign << 63) | (EXP_BITS << MAN_BITS) | (man ? (man << 29) : 0);
    }
    if (!exp) {
        if (!man) {
            return sign << 63;
        }
        exp = 1;
        {
            int sh = __bpf_nlz64(man) - 40; // bit 23 within a 64-bit word
            man <<= sh;
            exp -= sh;
        }
        man &= 0x7fffff;
    }
    return (sign << 63) | ((u64)(exp - 127 + 1023) << MAN_BITS) | (man << 29);
}

__attribute__((noinline)) u32 __bpf_d2f(u64 a) {
    u64 sign = a >> 63;
    i64 exp = (i64)((a >> MAN_BITS) & EXP_BITS);
    u64 man = a & MAN_MASK;
    if (exp == 0x7ff) {
        return (u32)((sign << 31) | (0xffu << 23) | (man ? 0x400000 : 0));
    }
    if (!exp && !man) {
        return (u32)(sign << 31);
    }
    exp = exp - 1023 + 127;
    // 24 significant bits plus guard/round/sticky.
    u64 m = (man | HIDDEN) >> (MAN_BITS - 23 - 3);
    u64 sticky = (man & ((1ull << (MAN_BITS - 23 - 3)) - 1)) != 0;
    m |= sticky;
    if (exp <= 0) {
        if (exp < -25) {
            return (u32)(sign << 31);
        }
        u64 s = (m & ((1ull << (1 - exp)) - 1)) != 0;
        m = (m >> (1 - exp)) | s;
        exp = 0;
    }
    u64 low = m & 7;
    m >>= 3;
    if (low > 4 || (low == 4 && (m & 1))) {
        m++;
        if (m >> 24) {
            m >>= 1;
            exp++;
        }
    }
    if (exp >= 0xff) {
        return (u32)((sign << 31) | (0xffu << 23));
    }
    if (m & (1u << 23)) {
        m &= 0x7fffff;
    } else {
        exp = 0;
    }
    return (u32)((sign << 31) | ((u64)exp << 23) | m);
}

__attribute__((noinline)) u32 __bpf_fadd(u32 a, u32 b) {
    if (__bpf_f_isnan(a)) {
        return (a & 0x80000000u) | 0x7fc00000u;
    }
    if (__bpf_f_isnan(b)) {
        return (b & 0x80000000u) | 0x7fc00000u;
    }

    u32 sa = a >> 31, sb = b >> 31;
    i64 ea = (a >> F_MAN_BITS) & F_EXP_BITS;
    i64 eb = (b >> F_MAN_BITS) & F_EXP_BITS;
    u64 ma = a & F_MAN_MASK, mb = b & F_MAN_MASK;

    if (__bpf_f_isinf(a)) {
        return (__bpf_f_isinf(b) && sa != sb) ? 0x7fc00000u : a;
    }
    if (__bpf_f_isinf(b)) {
        return b;
    }
    if (!ea && !ma) {
        return (!eb && !mb) ? (a & b) : b;
    }
    if (!eb && !mb) {
        return a;
    }

    if (ea) {
        ma |= F_HIDDEN;
    } else {
        ea = 1;
    }
    if (eb) {
        mb |= F_HIDDEN;
    } else {
        eb = 1;
    }
    ma <<= 3;
    mb <<= 3;
    if (ea < eb) {
        i64 te = ea;
        ea = eb;
        eb = te;
        u64 tm = ma;
        ma = mb;
        mb = tm;
        u32 ts = sa;
        sa = sb;
        sb = ts;
    }

    i64 shift = ea - eb;
    if (shift > 63) {
        mb = 1;
    } else if (shift) {
        u64 sticky = (mb & ((1ull << shift) - 1)) != 0;
        mb = (mb >> shift) | sticky;
    }

    u32 sign = sa;
    u64 man;
    if (sa == sb) {
        man = ma + mb;
        if (man >> (F_MAN_BITS + 4)) {
            u64 sticky = man & 1;
            man = (man >> 1) | sticky;
            ea++;
        }
    } else {
        if (ma >= mb) {
            man = ma - mb;
        } else {
            man = mb - ma;
            sign = sb;
        }
        if (!man) {
            return 0;
        }
        {
            int sh = __bpf_nlz64(man) - 37; // bit 26 is the target
            if (sh > (int)(ea - 1)) {
                sh = (int)(ea - 1);
            }
            if (sh > 0) {
                man <<= sh;
                ea -= sh;
            }
        }
    }
    return __bpf_f_pack(sign, ea, man);
}

__attribute__((always_inline)) u32 __bpf_fneg(u32 a) {
    return a ^ 0x80000000u;
}
u32 __bpf_fsub(u32 a, u32 b) {
    return __bpf_fadd(a, __bpf_fneg(b));
}

__attribute__((noinline)) u32 __bpf_fmul(u32 a, u32 b) {
    if (__bpf_f_isnan(a)) {
        return (a & 0x80000000u) | 0x7fc00000u;
    }
    if (__bpf_f_isnan(b)) {
        return (b & 0x80000000u) | 0x7fc00000u;
    }

    u32 sign = (a >> 31) ^ (b >> 31);
    i64 ea = (a >> F_MAN_BITS) & F_EXP_BITS;
    i64 eb = (b >> F_MAN_BITS) & F_EXP_BITS;
    u64 ma = a & F_MAN_MASK, mb = b & F_MAN_MASK;
    int azero = !ea && !ma, bzero = !eb && !mb;

    if (__bpf_f_isinf(a)) {
        return bzero ? 0x7fc00000u : (sign << 31) | (F_EXP_BITS << F_MAN_BITS);
    }
    if (__bpf_f_isinf(b)) {
        return azero ? 0x7fc00000u : (sign << 31) | (F_EXP_BITS << F_MAN_BITS);
    }
    if (azero || bzero) {
        return sign << 31;
    }

    if (ea) {
        ma |= F_HIDDEN;
    } else {
        ea = 1;
    }
    if (eb) {
        mb |= F_HIDDEN;
    } else {
        eb = 1;
    }
    {
        int sh = __bpf_nlz64(ma) - 40;
        ma <<= sh;
        ea -= sh;
    }
    {
        int sh = __bpf_nlz64(mb) - 40;
        mb <<= sh;
        eb -= sh;
    }

    u64 product = ma * mb;
    i64 exp = ea + eb - 127;
    u64 man;
    if (product >> 47) {
        man = product >> 21;
        man |= (product & ((1ull << 21) - 1)) != 0;
        exp++;
    } else {
        man = product >> 20;
        man |= (product & ((1ull << 20) - 1)) != 0;
    }
    return __bpf_f_pack(sign, exp, man);
}

__attribute__((noinline)) u32 __bpf_fdiv(u32 a, u32 b) {
    return __bpf_d2f(__bpf_ddiv(__bpf_f2d(a), __bpf_f2d(b)));
}
// This boundary is independently load-bearing for the same reason as dcmp.
__attribute__((noinline)) int __bpf_fcmp(u32 a, u32 b) {
    return __bpf_dcmp(__bpf_f2d(a), __bpf_f2d(b));
}
u32 __bpf_i2f(i64 v) {
    return __bpf_d2f(__bpf_i2d(v));
}
u32 __bpf_u2f(u64 v) {
    return __bpf_d2f(__bpf_u2d(v));
}
i64 __bpf_f2i(u32 f) {
    return __bpf_d2i(__bpf_f2d(f));
}
u64 __bpf_f2u(u32 f) {
    return __bpf_d2u(__bpf_f2d(f));
}

// Remainder, for the frem the C '%' on doubles turns into.
__attribute__((noinline)) u64 __bpf_drem(u64 a, u64 b) {
    if (__bpf_d_isnan(a) || __bpf_d_isnan(b) || __bpf_d_isinf(a) || !(b << 1)) {
        return 0x7ff8000000000000ull;
    }
    if (__bpf_d_isinf(b) || !(a << 1)) {
        return a;
    }
    u64 q = __bpf_ddiv(a, b);
    i64 iq = __bpf_d2i(q); // truncate toward zero
    return __bpf_dsub(a, __bpf_dmul(__bpf_i2d(iq), b));
}
__attribute__((noinline)) u32 __bpf_frem(u32 a, u32 b) {
    return __bpf_d2f(__bpf_drem(__bpf_f2d(a), __bpf_f2d(b)));
}
