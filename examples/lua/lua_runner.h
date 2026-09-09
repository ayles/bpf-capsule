// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The script runner shared by the Capsule guest and the native comparison
// build: stock Lua reading batch stdin from a buffer and writing stdout and
// its error message into buffers. Both builds include this file once; only
// where the buffers live differs.
#pragma once

#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "lua_runner_ctrl.h"

static struct lua_buffer* lua_runner_output;
static struct lua_buffer* lua_runner_error;

static struct {
    const char* data;
    size_t size;
    size_t cursor;
} lua_runner_input;

// Sizes keep counting past the capacity so the host can report truncation.
static void lua_runner_append(struct lua_buffer* buffer, const char* text, size_t length) {
    size_t begin = buffer->size;
    size_t copied = begin < buffer->capacity ? buffer->capacity - begin : 0;
    if (copied > length) {
        copied = length;
    }
    if (copied) {
        memcpy(buffer->address + begin, text, copied);
    }
    buffer->size = length > SIZE_MAX - begin ? SIZE_MAX : begin + length;
}

// lua_writestring and lua_writeline from lua_capsule_config.h land here.
void lua_capsule_write(const char* text, size_t length) {
    lua_runner_append(lua_runner_output, text, length);
}

static int lua_runner_read_one(lua_State* state, const char* format) {
    if (format[0] == '*') {
        ++format; // Lua 5.1 spelling
    }
    if (format[0] == 'a') {
        lua_pushlstring(state, lua_runner_input.data + lua_runner_input.cursor, lua_runner_input.size - lua_runner_input.cursor);
        lua_runner_input.cursor = lua_runner_input.size;
        return 1;
    }
    if (format[0] != 'l' && format[0] != 'L') {
        // Avoid the varargs luaL_error path in the BPF frontend.
        lua_pushliteral(state, "unsupported io.read format");
        return lua_error(state);
    }
    if (lua_runner_input.cursor >= lua_runner_input.size) {
        lua_pushnil(state);
        return 1;
    }
    size_t line_end = lua_runner_input.cursor;
    while (line_end < lua_runner_input.size && lua_runner_input.data[line_end] != '\n') {
        ++line_end;
    }
    size_t kept = format[0] == 'L' && line_end < lua_runner_input.size ? line_end + 1 : line_end;
    lua_pushlstring(state, lua_runner_input.data + lua_runner_input.cursor, kept - lua_runner_input.cursor);
    lua_runner_input.cursor = line_end < lua_runner_input.size ? line_end + 1 : line_end;
    return 1;
}

// lua_CFunction body: one result per requested format, default "l".
static int lua_runner_read(lua_State* state) {
    int count = lua_gettop(state);
    if (!count) {
        return lua_runner_read_one(state, "l");
    }
    for (int index = 1; index <= count; ++index) {
        lua_runner_read_one(state, luaL_checkstring(state, index));
    }
    return count;
}

// Runs the script. Returns 0, or 1 with the message in the error buffer.
static int lua_runner_run(const struct lua_buffer* script, const struct lua_buffer* input, struct lua_buffer* output, struct lua_buffer* error) {
    lua_runner_output = output;
    lua_runner_error = error;
    output->size = 0;
    error->size = 0;
    lua_runner_input.data = input->address;
    lua_runner_input.size = input->size;
    lua_runner_input.cursor = 0;

    lua_State* state = luaL_newstate();
    if (!state) {
        static const char message[] = "cannot create Lua state";
        lua_runner_append(error, message, sizeof(message) - 1);
        return 1;
    }
    luaL_openlibs(state);
    // Batch stdin replaces the io library's descriptor plumbing.
    lua_getglobal(state, "io");
    if (!lua_istable(state, -1)) {
        lua_pop(state, 1);
        lua_newtable(state);
        lua_pushvalue(state, -1);
        lua_setglobal(state, "io");
    }
    lua_pushcfunction(state, lua_runner_read);
    lua_setfield(state, -2, "read");
    lua_pop(state, 1);
    int status = luaL_loadbuffer(state, script->address, script->size, "script.lua");
    if (!status) {
        status = lua_pcall(state, 0, 0, 0);
    }
    if (status) {
        const char* message = lua_tostring(state, -1);
        if (!message) {
            message = "Lua execution failed";
        }
        lua_runner_append(error, message, strlen(message));
    }
    lua_close(state);
    return status ? 1 : 0;
}
