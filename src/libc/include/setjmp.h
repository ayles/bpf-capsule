// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

// Opaque saved {pc, sp, fp, result-slot} software-machine state.
typedef unsigned long long jmp_buf[4];
int __bpf_capsule_setjmp(jmp_buf) __attribute__((returns_twice));
void __bpf_capsule_longjmp(jmp_buf, int) __attribute__((noreturn));
#define setjmp(env) __bpf_capsule_setjmp(env)
#define longjmp(env, value) __bpf_capsule_longjmp(env, value)
#define _setjmp(env) setjmp(env)
#define _longjmp(env, value) longjmp(env, value)
