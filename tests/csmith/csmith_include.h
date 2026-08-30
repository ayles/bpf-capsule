// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

// Csmith's minimal runtime is freestanding and deterministic. Include the
// generated translation unit once, rename its entry, then remove the type
// macros before Linux, libbpf, or libc headers are parsed.
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
