// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run one userspace-staged script with stock Lua: batch stdin in, stdout and
// a Lua error message out through Capsule memory. The runner itself is shared
// with the native comparison build (lua_runner.h).
// There are no packet APIs or per-CPU structures here; lua-xdp owns those.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "lua_runner.h"

struct lua_runner_ctrl lua_runner_control SEC(".data.lua_runner");

// The runner works on copies of the buffer descriptors in Capsule memory; only
// the resulting sizes go back to the control block.
static struct lua_buffer lua_script_buffer;
static struct lua_buffer lua_input_buffer;
static struct lua_buffer lua_output_buffer;
static struct lua_buffer lua_error_buffer;

static void lua_run_body(void) {
    lua_runner_control.output.size = 0;
    lua_runner_control.error.size = 0;
    if (!lua_runner_control.script.address || lua_runner_control.script.size > lua_runner_control.script.capacity || !lua_runner_control.input.address ||
        lua_runner_control.input.size > lua_runner_control.input.capacity || !lua_runner_control.output.address || !lua_runner_control.output.capacity ||
        !lua_runner_control.error.address || !lua_runner_control.error.capacity) {
        capsule_exit(1);
    }
    lua_script_buffer = lua_runner_control.script;
    lua_input_buffer = lua_runner_control.input;
    lua_output_buffer = lua_runner_control.output;
    lua_error_buffer = lua_runner_control.error;
    int failed = lua_runner_run(&lua_script_buffer, &lua_input_buffer, &lua_output_buffer, &lua_error_buffer);
    lua_runner_control.output.size = lua_output_buffer.size;
    lua_runner_control.error.size = lua_error_buffer.size;
    if (failed) {
        capsule_exit(1);
    }
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
