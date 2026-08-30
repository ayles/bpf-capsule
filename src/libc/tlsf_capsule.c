// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Freestanding build of the vanilla upstream allocator vendored in
// thirdparty/tlsf/, whose sources are byte-identical to mattconte/tlsf at commit
// deff9ab509341f264addbd3c8ada533678591905; every Capsule adaptation lives
// here instead of patching them:
//
//   - assert is a no-op: the runtime supplies and validates the pool, and
//     a failed allocator invariant must not become a verifier-visible
//     trap path in every program.
//   - printf is a no-op: upstream prints pool-argument diagnostics and
//     inspection-helper output, and this build has no process stdout;
//     allocator operations must stay independent of fiber-local stdio.
//
// The libc headers are included first so the stubs cannot mangle their
// declarations; the upstream #includes then reduce to include guards.
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef assert
#define assert(x) ((void)0)
#undef printf
#define printf(...) ((void)0)

#include "tlsf.c"
