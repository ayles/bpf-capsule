// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <string.h>

#include "lua.h"

void lua_capsule_error(lua_State* state, const char* message, unsigned long length);

static void lua_capsule_report_error(lua_State* state) {
    const char* message = state ? lua_tostring(state, -1) : 0;
    if (!message) {
        message = "Lua execution failed";
    }
    lua_capsule_error(state, message, (unsigned long)strlen(message));
}
