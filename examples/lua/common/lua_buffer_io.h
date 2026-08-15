// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// io.read over a fully staged stdin buffer. Shared verbatim by the Capsule
// guest and the --native interpreter run so both see identical bytes.
#pragma once

#include "lua.h"
#include "lauxlib.h"

struct lua_buffer_input {
    const char* data;
    unsigned long size;
    unsigned long cursor;
};

static int lua_buffer_read_one(lua_State* state, struct lua_buffer_input* input, const char* format) {
    if (format[0] == '*') {
        ++format; // Lua 5.1 spelling
    }
    if (format[0] == 'a') {
        lua_pushlstring(state, input->data + input->cursor, input->size - input->cursor);
        input->cursor = input->size;
        return 1;
    }
    if (format[0] != 'l' && format[0] != 'L') {
        // Not luaL_error: a varargs extern under -g crashes the BPF clang
        // front end (clang 22 debug-info bug), and this header compiles into
        // the guest.
        lua_pushliteral(state, "unsupported io.read format");
        return lua_error(state);
    }
    if (input->cursor >= input->size) {
        lua_pushnil(state);
        return 1;
    }
    unsigned long line_end = input->cursor;
    while (line_end < input->size && input->data[line_end] != '\n') {
        ++line_end;
    }
    unsigned long kept = format[0] == 'L' && line_end < input->size ? line_end + 1 : line_end;
    lua_pushlstring(state, input->data + input->cursor, kept - input->cursor);
    input->cursor = line_end < input->size ? line_end + 1 : line_end;
    return 1;
}

// lua_CFunction body: one result per requested format, default "l".
static int lua_buffer_read(lua_State* state, struct lua_buffer_input* input) {
    int count = lua_gettop(state);
    if (!count) {
        return lua_buffer_read_one(state, input, "l");
    }
    for (int index = 1; index <= count; ++index) {
        lua_buffer_read_one(state, input, luaL_checkstring(state, index));
    }
    return count;
}
