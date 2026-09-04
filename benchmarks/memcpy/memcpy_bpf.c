// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "memcpy.h"

#include <string.h>

volatile struct memcpy_state memcpy_state SEC(".data.memcpy");

static unsigned char source[MEMCPY_MAX_BYTES];
static unsigned char destination[MEMCPY_MAX_BYTES];

static uint64_t managed_memcpy(void) {
    size_t bytes = memcpy_state.bytes;
    if (bytes > sizeof(source)) {
        bytes = sizeof(source);
    }
    if (!bytes) {
        return 0;
    }
    source[0] = 0x12;
    source[bytes - 1] = 0x34;
    destination[0] = 0;
    destination[bytes - 1] = 0;
    memcpy(destination, source, bytes);
    return ((uint64_t)destination[0] << 8) | destination[bytes - 1];
}

SEC("syscall")
int memcpy_run(void) {
    memcpy_state.capsule = capsule_call((uint64_t*)&memcpy_state.result, managed_memcpy);
    return 0;
}

char _license[] SEC("license") = "GPL";
