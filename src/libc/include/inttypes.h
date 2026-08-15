// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The width-specific printf/scanf macros, without the host's version, which
// assumes a C library this environment does not have.
#pragma once
#include <stdint.h>
#define PRId32 "d"
#define PRIu32 "u"
#define PRIx32 "x"
#define PRId64 "lld"
#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRIX64 "llX"
#define PRId8 "d"
#define PRIu8 "u"
#define PRIdPTR "ld"
#define PRIuPTR "lu"
#define PRIxPTR "lx"
#define SCNd32 "d"
#define SCNd64 "lld"
