// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// These declarations select native scalar subprograms without changing the
// upstream implementations. Capsule proves each body cannot suspend.
#pragma once

#include <stdint.h>

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
