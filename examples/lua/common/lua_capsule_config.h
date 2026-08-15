// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Force-included into stock Lua 5.4. Lua deliberately leaves these platform
// hooks open in luaconf.h/ldo.c, so Capsule does not patch the upstream tree.
#pragma once

void lua_capsule_write(const char* text, unsigned long length);
void lua_capsule_throw(void* state, int status) __attribute__((noreturn));

#define lua_writestring(s, l) lua_capsule_write((s), (l))
#define lua_writeline() lua_capsule_write("\n", 1)
#define lua_writestringerror(s, p) ((void)0)

// Capsule does not yet virtualize setjmp/longjmp. Execute Lua's protected body
// normally; an attempted throw records the Lua message and aborts the managed
// call. The VM that was being mutated must never be reused after that abort.
#define luai_jmpbuf int
#define LUAI_THROW(L, c) lua_capsule_throw((L), (c)->status)
#define LUAI_TRY(L, c, action) \
    do { \
        action; \
    } while (0)
