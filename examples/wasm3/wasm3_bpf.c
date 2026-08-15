// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// WebAssembly in the kernel — wasm3, unmodified, running a zlib module through
// the same pipeline. wasm3 is built with float opcodes disabled; this workload
// exercises its parser, compiler, interpreter dispatch and linear memory.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "wasm3.h"
#include "m3_env.h"
#include "wasm3_ctrl.h"

struct wasm3_bpf_ctrl w3ctrl SEC(".data.w3ctrl");

// wasm3 allocates its runtime from the C allocator; freestanding.c serves it
// out of the configured Capsule heap.
#define W3_STACK_BYTES (256 * 1024)

#include "zlib_wasm_module.h"

static int wasm_global_offset(IM3Module module, const char* name, uint32_t* offset) {
    IM3Global global = m3_FindGlobal(module, name);
    if (!global) {
        return 0;
    }
    M3TaggedValue value = {0};
    M3Result result = m3_GetGlobal(global, &value);
    if (result || value.type != c_m3Type_i32) {
        return 0;
    }
    *offset = value.value.i32;
    return 1;
}

static void wasm3_zlib_body(void) {
    w3ctrl.stage = WASM3_STAGE_NOT_STARTED;
    w3ctrl.zlib_status = 0;
    w3ctrl.zlib_output_size = 0;
    w3ctrl.zlib_adler = 0;

    if (w3ctrl.input_address > (uint32_t)-1 || !w3ctrl.input_size || w3ctrl.input_size > WASM_ZLIB_GUEST_INPUT_CAPACITY) {
        return;
    }
    uint8_t* input = capsule_memory_pointer(uint8_t, w3ctrl.input_address);
    uint32_t input_size = (uint32_t)w3ctrl.input_size;

    IM3Environment env = m3_NewEnvironment();
    if (!env) {
        return;
    }
    w3ctrl.stage = WASM3_STAGE_ENVIRONMENT_READY;
    IM3Runtime runtime = m3_NewRuntime(env, W3_STACK_BYTES, 0);
    if (!runtime) {
        return;
    }
    w3ctrl.stage = WASM3_STAGE_RUNTIME_READY;

    IM3Module module = 0;
    M3Result result = m3_ParseModule(env, &module, zlib_wasm_module, zlib_wasm_module_len);
    if (result) {
        return;
    }
    result = m3_LoadModule(runtime, module);
    if (result) {
        return;
    }
    w3ctrl.stage = WASM3_STAGE_MODULE_READY;

    uint32_t input_offset = 0, control_offset = 0;
    if (!wasm_global_offset(module, "guest_zin", &input_offset) || !wasm_global_offset(module, "guest_zctrl", &control_offset)) {
        return;
    }
    uint32_t memory_size = 0;
    uint8_t* memory = m3_GetMemory(runtime, &memory_size, 0);
    if (!memory || input_offset > memory_size || input_size > memory_size - input_offset || control_offset > memory_size ||
        sizeof(struct wasm_zlib_control) > memory_size - control_offset) {
        return;
    }

    memcpy(memory + input_offset, input, input_size);
    uint64_t guest_input_size = input_size;
    memcpy(memory + control_offset, &guest_input_size, sizeof(guest_input_size));
    w3ctrl.stage = WASM3_STAGE_INPUT_READY;

    IM3Function function = 0;
    result = m3_FindFunction(&function, runtime, "guest_zlib_run");
    if (result || !function) {
        return;
    }
    result = m3_CallArgv(function, 0, 0);
    if (result) {
        return;
    }

    struct wasm_zlib_control guest = {0};
    memcpy(&guest, memory + control_offset, sizeof(guest));
    w3ctrl.zlib_status = guest.status;
    w3ctrl.zlib_output_size = guest.output_len;
    w3ctrl.zlib_adler = guest.adler;
    w3ctrl.stage = WASM3_STAGE_COMPLETE;
}

SEC("syscall")
int wasm3_zlib_run() {
    w3ctrl.capsule = capsule_call_void(wasm3_zlib_body);
    return 0;
}

SEC("syscall")
int wasm3_drain() {
    w3ctrl.capsule = capsule_continue_void(w3ctrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
