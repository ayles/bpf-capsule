// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Force-included into stock Lua. Lua deliberately leaves these platform
// hooks open in luaconf.h/ldo.c, so Capsule does not patch the upstream tree.
#pragma once

void lua_capsule_write(const char* text, unsigned long length);

#define lua_writestring(s, l) lua_capsule_write((s), (l))
#define lua_writeline() lua_capsule_write("\n", 1)
#define lua_writestringerror(s, p) ((void)0)
