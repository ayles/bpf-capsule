// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Force-included into stock Lua. Lua deliberately leaves these platform
// hooks open in luaconf.h/ldo.c, so Capsule does not patch the upstream tree.
#pragma once

// clang 23 crashes emitting BPF debug info for an extern variadic function
// whose first declaration is parenthesized, as lua.h and lauxlib.h write
// them: CGDebugInfo::getOrCreateFunctionType does not look through the type
// sugar, records no parameters, and the BPF extern-declaration path then
// indexes past the empty list. Declaring the three plainly first sidesteps
// it; drop these once the SDK's clang carries the fix.
struct lua_State;
extern const char* lua_pushfstring(struct lua_State* L, const char* fmt, ...);
extern int lua_gc(struct lua_State* L, int what, ...);
extern int luaL_error(struct lua_State* L, const char* fmt, ...);

#include <stddef.h>

void lua_capsule_write(const char* text, size_t length);

#define lua_writestring(s, l) lua_capsule_write((s), (l))
#define lua_writeline() lua_capsule_write("\n", 1)
#define lua_writestringerror(s, p) ((void)0)
