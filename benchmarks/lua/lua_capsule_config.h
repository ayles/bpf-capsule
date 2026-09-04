// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Force-included platform hooks for the stock Lua sources.
#pragma once

// Work around clang 23's BPF debug-info crash on the parenthesized variadic
// declarations in Lua's headers by declaring their plain forms first.
struct lua_State;
extern const char* lua_pushfstring(struct lua_State* L, const char* fmt, ...);
extern int lua_gc(struct lua_State* L, int what, ...);
extern int luaL_error(struct lua_State* L, const char* fmt, ...);

void lua_capsule_write(const char* text, unsigned long length);

#define lua_writestring(s, l) lua_capsule_write((s), (l))
#define lua_writeline() lua_capsule_write("\n", 1)
#define lua_writestringerror(s, p) ((void)0)
