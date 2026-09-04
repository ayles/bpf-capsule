// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Stock Lua benchmark runner: one staged script with empty stdin and buffered
// output, entirely inside Capsule memory.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lua_runner_ctrl.h"

struct lua_runner_ctrl lua_runner_control SEC(".data.lua_runner");

static char lua_script_buf[256 << 10];
static char lua_output_buf[1 << 20];
static char lua_error_buf[64 << 10];

static void lua_prepare_body(void) {
    lua_runner_control.script.address = lua_script_buf;
    lua_runner_control.script.capacity = sizeof(lua_script_buf);
    lua_runner_control.output.address = lua_output_buf;
    lua_runner_control.output.capacity = sizeof(lua_output_buf);
    lua_runner_control.error.address = lua_error_buf;
    lua_runner_control.error.capacity = sizeof(lua_error_buf);
}

static uint64_t lua_append(char* buffer, uint64_t capacity, uint64_t begin, const char* text, unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        if (begin + index < capacity) {
            buffer[begin + index] = text[index];
        }
    }
    return begin + length;
}

void lua_capsule_write(const char* text, unsigned long length) {
    lua_runner_control.output.size = lua_append(lua_output_buf, sizeof(lua_output_buf), lua_runner_control.output.size, text, length);
}

static void lua_report_error(lua_State* state) {
    const char* message = state ? lua_tostring(state, -1) : 0;
    if (!message) {
        message = "Lua execution failed";
    }
    lua_runner_control.error.size = lua_append(lua_error_buf, sizeof(lua_error_buf), lua_runner_control.error.size, message, (unsigned long)strlen(message));
}

static int lua_read(lua_State* state) {
    const char* format = lua_gettop(state) ? luaL_checkstring(state, 1) : "l";
    if (format[0] == '*') {
        ++format;
    }
    if (format[0] == 'a') {
        lua_pushliteral(state, "");
    } else if (format[0] == 'l' || format[0] == 'L') {
        lua_pushnil(state);
    } else {
        lua_pushliteral(state, "unsupported io.read format");
        return lua_error(state);
    }
    return 1;
}

static void lua_run_body(void) {
    lua_runner_control.output.size = 0;
    lua_runner_control.error.size = 0;

    lua_State* state = luaL_newstate();
    if (!state) {
        static const char message[] = "cannot create Lua state";
        lua_runner_control.error.size = lua_append(lua_error_buf, sizeof(lua_error_buf), 0, message, sizeof(message) - 1);
        capsule_exit(1);
    }
    luaL_openlibs(state);
    lua_getglobal(state, "io");
    lua_pushcfunction(state, lua_read);
    lua_setfield(state, -2, "read");
    lua_pop(state, 1);
    int status = luaL_loadbuffer(state, lua_script_buf, (unsigned long)lua_runner_control.script.size, "benchmark.lua");
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
int lua_prepare(void) {
    lua_runner_control.capsule = capsule_call_void(lua_prepare_body);
    return 0;
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
