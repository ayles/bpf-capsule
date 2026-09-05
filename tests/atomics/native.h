// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

struct atomic_runtime_values {
    unsigned int word;
    unsigned int padding;
    uint64_t doubleword;
};

struct atomic_managed_result {
    unsigned int writer_status;
    unsigned int reader_status;
    int64_t writer_code;
    int64_t reader_code;
    uint64_t writer_failures;
    uint64_t reader_failures;
    unsigned int rmw_status;
    int64_t rmw_code;
    uint64_t rmw_failures;
    unsigned int counter_status;
    int64_t counter_code;
    uint64_t counter_value;
    uint64_t overflow_address;
    unsigned int overflow_status;
    int64_t overflow_code;
    uint64_t overflow_failures;
};

#define ATOMIC_RUNTIME_INITIAL_WORD 17u
#define ATOMIC_RUNTIME_INITIAL_DOUBLEWORD 1001ull

#define ATOMIC_MANAGED_BYTE_A 0x5au
#define ATOMIC_MANAGED_BYTE_B 0xa5u
#define ATOMIC_MANAGED_HALF_A 0x55aau
#define ATOMIC_MANAGED_HALF_B 0xaa55u
#define ATOMIC_MANAGED_WORD_A 0x5555aaaau
#define ATOMIC_MANAGED_WORD_B 0xaaaa5555u
#define ATOMIC_MANAGED_DOUBLEWORD_A 0x55555555aaaaaaaaull
#define ATOMIC_MANAGED_DOUBLEWORD_B 0xaaaaaaaa55555555ull
