// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// No stack to jump over: the real one is abandoned by design, and the
// software one is walked by the runtime. Programs override their own
// error handling (Lua does this through LUAI_TRY/LUAI_THROW).
#pragma once
typedef int jmp_buf[1];
int setjmp(jmp_buf b);
__attribute__((noreturn)) void longjmp(jmp_buf b, int v);
#define _setjmp setjmp
#define _longjmp longjmp
