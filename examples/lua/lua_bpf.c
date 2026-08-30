// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run one userspace-staged script with stock Lua: batch stdin in, stdout and
// a Lua error message out through Capsule memory.
// There are no packet APIs or per-CPU structures here; lua-xdp owns those.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#include "bpf_capsule.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lua_runner_ctrl.h"

struct lua_runner_ctrl lua_runner_control SEC(".data.lua_runner");

struct lua_buffer_input {
    const char* data;
    unsigned long size;
    unsigned long cursor;
};

static struct lua_buffer_input lua_input;

static int lua_buffer_read_one(lua_State* state, const char* format) {
    if (format[0] == '*') {
        ++format; // Lua 5.1 spelling
    }
    if (format[0] == 'a') {
        lua_pushlstring(state, lua_input.data + lua_input.cursor, lua_input.size - lua_input.cursor);
        lua_input.cursor = lua_input.size;
        return 1;
    }
    if (format[0] != 'l' && format[0] != 'L') {
        // Avoid the varargs luaL_error path in the BPF frontend.
        lua_pushliteral(state, "unsupported io.read format");
        return lua_error(state);
    }
    if (lua_input.cursor >= lua_input.size) {
        lua_pushnil(state);
        return 1;
    }
    unsigned long line_end = lua_input.cursor;
    while (line_end < lua_input.size && lua_input.data[line_end] != '\n') {
        ++line_end;
    }
    unsigned long kept = format[0] == 'L' && line_end < lua_input.size ? line_end + 1 : line_end;
    lua_pushlstring(state, lua_input.data + lua_input.cursor, kept - lua_input.cursor);
    lua_input.cursor = line_end < lua_input.size ? line_end + 1 : line_end;
    return 1;
}

// lua_CFunction body: one result per requested format, default "l".
static int lua_read(lua_State* state) {
    int count = lua_gettop(state);
    if (!count) {
        return lua_buffer_read_one(state, "l");
    }
    for (int index = 1; index <= count; ++index) {
        lua_buffer_read_one(state, luaL_checkstring(state, index));
    }
    return count;
}

// Sizes keep counting past the capacity so the host can report truncation.
static size_t lua_append(char* buffer, size_t capacity, size_t begin, const char* text, size_t length) {
    size_t copied = begin < capacity ? capacity - begin : 0;
    if (copied > length) {
        copied = length;
    }
    if (copied) {
        memcpy(buffer + begin, text, copied);
    }
    return length > SIZE_MAX - begin ? SIZE_MAX : begin + length;
}

void lua_capsule_write(const char* text, unsigned long length) {
    lua_runner_control.output.size =
        lua_append(lua_runner_control.output.address, lua_runner_control.output.capacity, lua_runner_control.output.size, text, length);
}

static void lua_report_error(lua_State* state) {
    const char* message = lua_tostring(state, -1);
    if (!message) {
        message = "Lua execution failed";
    }
    unsigned long length = (unsigned long)strlen(message);
    lua_runner_control.error.size =
        lua_append(lua_runner_control.error.address, lua_runner_control.error.capacity, lua_runner_control.error.size, message, length);
}

static void lua_run_body(void) {
    lua_runner_control.output.size = 0;
    lua_runner_control.error.size = 0;
    if (!lua_runner_control.script.address || lua_runner_control.script.size > lua_runner_control.script.capacity || !lua_runner_control.input.address ||
        lua_runner_control.input.size > lua_runner_control.input.capacity || !lua_runner_control.output.address || !lua_runner_control.output.capacity ||
        !lua_runner_control.error.address || !lua_runner_control.error.capacity) {
        capsule_exit(1);
    }
    lua_input.data = lua_runner_control.input.address;
    lua_input.size = lua_runner_control.input.size;
    lua_input.cursor = 0;

    lua_State* state = luaL_newstate();
    if (!state) {
        static const char message[] = "cannot create Lua state";
        lua_runner_control.error.size = lua_append(lua_runner_control.error.address, lua_runner_control.error.capacity, 0, message, sizeof(message) - 1);
        capsule_exit(1);
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
    lua_pushcfunction(state, lua_read);
    lua_setfield(state, -2, "read");
    lua_pop(state, 1);
    int status = luaL_loadbuffer(state, lua_runner_control.script.address, lua_runner_control.script.size, "bpf.lua");
    if (!status) {
        status = lua_pcall(state, 0, 0, 0);
    }
    if (status) {
        lua_report_error(state);
        lua_close(state);
        capsule_exit(1);
    }
    lua_close(state);
}

SEC("syscall")
int lua_run(void) {
    lua_runner_control.capsule = capsule_call_void(lua_run_body);
    return 0;
}

SEC("syscall")
int lua_drain(void) {
    lua_runner_control.capsule = capsule_continue_void(lua_runner_control.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
