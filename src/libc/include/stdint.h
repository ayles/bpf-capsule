// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef long intptr_t;
typedef unsigned long uintptr_t;
#define INT8_MIN (-128)
#define INT8_MAX 127
#define INT32_MAX 2147483647
#define UINT32_MAX 4294967295u
#define INT16_MIN (-32768)
#define INT16_MAX 32767
#define INT32_MIN (-2147483647 - 1)
#define INT64_MIN (-9223372036854775807LL - 1)
#define INT64_MAX 9223372036854775807LL
#define UINT8_MAX 255
#define UINT16_MAX 65535
#define UINT64_MAX 18446744073709551615ULL
#define SIZE_MAX 18446744073709551615ULL
// An undefined limit macro is 0 inside #if, which silently flips feature
// selection: QuickJS chose 32-bit NAN boxing on this 64-bit target because
// INTPTR_MAX was missing, and the tag bits it left in the upper pointer half
// broke every pointer comparison. Keep every limit for every type we typedef.
#define INTPTR_MIN (-9223372036854775807L - 1)
#define INTPTR_MAX 9223372036854775807L
#define UINTPTR_MAX 18446744073709551615UL
#define PTRDIFF_MIN (-9223372036854775807L - 1)
#define PTRDIFF_MAX 9223372036854775807L
#define INTMAX_MIN (-9223372036854775807LL - 1)
#define INTMAX_MAX 9223372036854775807LL
#define UINTMAX_MAX 18446744073709551615ULL
typedef long long intmax_t;
typedef unsigned long long uintmax_t;
#define INT64_C(v) v##LL
#define UINT64_C(v) v##ULL
#define INT32_C(v) v
#define UINT32_C(v) v##U
