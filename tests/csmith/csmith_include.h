// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdint.h>
// Csmith's minimal runtime is freestanding, deterministic, and exposes its
// checksum as ordinary data. Include a generated case once, then remove the
// integer-type macros before including Linux or libc headers.
#define CSMITH_MINIMAL 1
#define NO_PRINTF 1
#define NOT_PRINT_CHECKSUM 1
#define printf(...) 0
#define main csmith_generated_main
#include "csmith_case.c"
#undef main
#undef printf
#undef int8_t
#undef uint8_t
#undef int16_t
#undef uint16_t
#undef int32_t
#undef uint32_t
#undef int64_t
#undef uint64_t
