// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// These declarations set inlining and native scalar boundaries without
// changing upstream implementations. Capsule proves nosuspend bodies.
#pragma once

#include <stdint.h>

// Wide multiplication is a handful of limb operations, not a suspension.
__attribute__((always_inline)) __int128 __multi3(__int128, __int128);
__attribute__((always_inline)) static __int128 __mulddi3(uint64_t, uint64_t);

// Wide division stays managed: BPF returns only r0, not an i128 pair;
// __udivmodti4 and __mulodi4 also have output pointers that our global scalar
// nosuspend ABI cannot accept. compiler-rt's division loops pay managed
// dispatches; the integer mix measured ~5%/10% slower on arena/fixed than the
// former loop-free helpers. Revisit with a real wide-integer workload.

#define CAPSULE_BUILTIN __attribute__((annotate("capsule.nosuspend"), noinline))

// Subtraction and negation stay inlineable: upstream implements them as a
// sign-bit XOR plus addition, or just XOR. Equality aliases __le[sd]f2 below.

CAPSULE_BUILTIN double __adddf3(double, double);
CAPSULE_BUILTIN double __muldf3(double, double);
CAPSULE_BUILTIN double __divdf3(double, double);
CAPSULE_BUILTIN float __addsf3(float, float);
CAPSULE_BUILTIN float __mulsf3(float, float);
CAPSULE_BUILTIN float __divsf3(float, float);

// compiler-rt uses C long for comparison results on the BPF LP64 ABI.
CAPSULE_BUILTIN long __ledf2(double, double);
CAPSULE_BUILTIN long __gedf2(double, double);
CAPSULE_BUILTIN long __unorddf2(double, double);
CAPSULE_BUILTIN long __lesf2(float, float);
CAPSULE_BUILTIN long __gesf2(float, float);
CAPSULE_BUILTIN long __unordsf2(float, float);

CAPSULE_BUILTIN double __floatdidf(int64_t);
CAPSULE_BUILTIN double __floatundidf(uint64_t);
CAPSULE_BUILTIN float __floatdisf(int64_t);
CAPSULE_BUILTIN float __floatundisf(uint64_t);
CAPSULE_BUILTIN int64_t __fixdfdi(double);
CAPSULE_BUILTIN uint64_t __fixunsdfdi(double);
CAPSULE_BUILTIN int64_t __fixsfdi(float);
CAPSULE_BUILTIN uint64_t __fixunssfdi(float);
CAPSULE_BUILTIN double __extendsfdf2(float);
CAPSULE_BUILTIN float __truncdfsf2(double);

#undef CAPSULE_BUILTIN
