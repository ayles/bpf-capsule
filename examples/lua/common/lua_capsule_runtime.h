// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "lua.h"

// Shared stock-Lua mechanics. Each embedding supplies only its output sinks
// and any state bookkeeping required when Lua aborts.
lua_State* lua_capsule_newstate(void* owner);
void* lua_capsule_owner(lua_State* state);

void lua_capsule_write(const char* text, unsigned long length);
void lua_capsule_error(lua_State* state, int status, const char* message, unsigned long length);
