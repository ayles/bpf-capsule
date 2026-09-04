// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Capsule build of mattconte/tlsf at commit
// deff9ab509341f264addbd3c8ada533678591905. The SDK fetches and installs the
// unmodified upstream sources; every Capsule adaptation lives here:
//
//   - assert is a no-op: the runtime supplies and validates the pool, and
//     a failed allocator invariant must not become a verifier-visible
//     trap path in every program.
//   - printf is a no-op: upstream prints pool-argument diagnostics and
//     inspection-helper output, and this build has no process stdout;
//     allocator operations must stay independent of fiber-local stdio.
//
// NDEBUG selects the standard no-op assert implementation. Include stdio
// before replacing printf so the declaration itself remains intact.
#define NDEBUG 1
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef printf
#define printf(...) ((void)0)

#include "tlsf.c"
