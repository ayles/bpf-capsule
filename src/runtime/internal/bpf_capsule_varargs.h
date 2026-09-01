// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

// Clang lowers an aggregate va_arg to `va_arg ptr` before the Capsule
// whole-program pipeline sees it, losing the aggregate's size and alignment.
// Keep that type-directed information in a private compiler marker instead.
// Stackify replaces the marker with an ordinary cursor alignment/advance;
// no call survives into the BPF object.
#include <stdarg.h>

#if defined(__BPF__)
#ifdef __cplusplus
extern "C" {
#endif
void* __bpf_capsule_va_arg(void* list, unsigned long size, unsigned long alignment);
#ifdef __cplusplus
}
#endif

#undef va_arg
#define va_arg(list, type) (*(type*)__bpf_capsule_va_arg(&(list), sizeof(type), __alignof__(type)))
#endif
