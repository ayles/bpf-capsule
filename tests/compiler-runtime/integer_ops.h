// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
#include <stdint.h>

enum { INTEGER_RESULT_WORDS = 14 };
struct integer_case {
    uint64_t a[2], b[2];
    uint64_t result[INTEGER_RESULT_WORDS];
};

// The same ordinary operations run through Capsule and the host compiler.
static void integer_evaluate(struct integer_case* c) {
    typedef unsigned __int128 u128;
    typedef __int128 i128;
    u128 a = ((u128)c->a[1] << 64) | c->a[0];
    u128 b = ((u128)c->b[1] << 64) | c->b[0];
    u128 values[5] = {a * b, 0, 0, 0, 0};
    if (b != 0) {
        values[1] = a / b;
        values[2] = a % b;
        // Division by zero and MIN / -1 have no C result to compare.
        if (a != ((u128)1 << 127) || (i128)b != -1) {
            values[3] = (i128)a / (i128)b;
            values[4] = (i128)a % (i128)b;
        }
    }
    for (unsigned i = 0; i < 5; ++i) {
        c->result[2 * i] = values[i];
        c->result[2 * i + 1] = values[i] >> 64;
    }
    uint64_t unsigned_product;
    int64_t signed_product;
    c->result[11] = __builtin_mul_overflow(c->a[0], c->b[0], &unsigned_product);
    c->result[13] = __builtin_mul_overflow((int64_t)c->a[0], (int64_t)c->b[0], &signed_product);
    c->result[10] = unsigned_product;
    c->result[12] = signed_product;
}
