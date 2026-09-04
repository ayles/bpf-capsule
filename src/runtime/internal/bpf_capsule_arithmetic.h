// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Private C linkage between the Capsule runtime and compiler-runtime int128.c.
#pragma once

struct bpf_u128_pair {
    unsigned long long lo;
    unsigned long long hi;
};

struct bpf_u128_pair __bpf_mul64_wide(unsigned long long a, unsigned long long b);
