// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run one userspace-staged script with stock Lua: batch stdin in, stdout and
// a Lua error message out, all through guest-owned buffers in Capsule memory.
// There are no packet APIs or per-CPU structures here; lua-xdp owns those.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lua_buffer_io.h"
#include "lua_capsule_runtime.h"
#include "lua_runner_ctrl.h"

struct lua_runner_ctrl lua_runner_control SEC(".data.lua_runner");

// Ordinary unsectioned storage: Capsule picks the kernel representation and
// keeps the zero-filled bytes out of the object image.
static char lua_script_buf[256 << 10];
static char lua_input_buf[256 << 10];
static char lua_output_buf[1 << 20];
static char lua_error_buf[64 << 10];

static struct lua_buffer_input lua_input;

static void lua_prepare_body(void) {
    lua_runner_control.script.address = (uint64_t)(void*)lua_script_buf;
    lua_runner_control.script.capacity = sizeof(lua_script_buf);
    lua_runner_control.input.address = (uint64_t)(void*)lua_input_buf;
    lua_runner_control.input.capacity = sizeof(lua_input_buf);
    lua_runner_control.output.address = (uint64_t)(void*)lua_output_buf;
    lua_runner_control.output.capacity = sizeof(lua_output_buf);
    lua_runner_control.error.address = (uint64_t)(void*)lua_error_buf;
    lua_runner_control.error.capacity = sizeof(lua_error_buf);
}

// Sizes keep counting past the capacity so the host can report truncation.
// The new size comes back as a value: a pointer into the sectioned control
// map must not cross the managed call boundary.
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

void lua_capsule_error(lua_State* state, int status, const char* message, unsigned long length) {
    (void)state;
    (void)status;
    lua_runner_control.error.size = lua_append(lua_error_buf, sizeof(lua_error_buf), lua_runner_control.error.size, message, length);
}

static int lua_read(lua_State* state) {
    return lua_buffer_read(state, &lua_input);
}

static void lua_run_body(void) {
    lua_runner_control.output.size = 0;
    lua_runner_control.error.size = 0;
    lua_input.data = lua_input_buf;
    lua_input.size = (unsigned long)lua_runner_control.input.size;
    lua_input.cursor = 0;

    lua_State* state = lua_capsule_newstate(0);
    if (!state) {
        lua_capsule_error(0, 0, "cannot create Lua state", 23);
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
    // With Capsule's terminating Lua throw hook, either call succeeds or the
    // managed invocation exits after recording the Lua message.
    (void)luaL_loadbuffer(state, lua_script_buf, (unsigned long)lua_runner_control.script.size, "bpf.lua");
    (void)lua_pcall(state, 0, 0, 0);
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
