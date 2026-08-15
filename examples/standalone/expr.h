// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Integer expression evaluator: the workload of the standalone example.
//
//   expr   := term (('+' | '-') term)*
//   term   := factor (('*' | '/' | '%') factor)*
//   factor := NUMBER | '-' factor | '(' expr ')'
//
// Plain freestanding C with no BPF awareness. The same translation unit is
// compiled through BPF Capsule for the kernel and natively for the host, and
// the host requires bit-for-bit equal results from both.
#pragma once

#include <stdint.h>

// Evaluates `len` bytes of `src`. Returns 0 and writes the result to
// *value_out on success; returns non-zero and writes the offset of the first
// offending byte to *error_at on a malformed input, division by zero, or
// nesting past the evaluator's own depth cap.
int expr_eval(const char* src, unsigned long len, int64_t* value_out, unsigned long* error_at);
