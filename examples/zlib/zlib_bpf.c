// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Stock zlib inflate in the kernel.
//
// The host deflates a buffer with its own zlib, writes it directly into a
// heap reservation, and the kernel inflates it with stock zlib sources
// compiled through the BPF Capsule pipeline.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <limits.h>

#include "bpf_capsule.h"

#include "zlib.h"
#include "zlib_ctrl.h"

struct zlib_bpf_ctrl zctrl SEC(".data.zctrl");

struct bump_allocator {
    unsigned char* base;
    size_t used;
};

// Capsule pointers are full user virtual addresses; validate only what
// zlib's uInt lengths require and that the span does not wrap.
static int valid_u32_range(const void* pointer, size_t size) {
    uintptr_t address = (uintptr_t)pointer;
    return pointer && size <= UINT_MAX && address <= UINTPTR_MAX - size;
}

static voidpf zalloc_bump(voidpf opaque, uInt items, uInt size) {
    struct bump_allocator* allocator = opaque;
    size_t bytes = (size_t)items * size;
    size_t aligned = (bytes + 7u) & ~(size_t)7u;
    size_t capacity = ZLIB_WORKSPACE_BYTES;
    if (allocator->used > capacity || aligned > capacity - allocator->used) {
        return 0;
    }
    unsigned char* address = allocator->base + allocator->used;
    allocator->used += aligned;
    return address;
}
static void zfree_noop(voidpf opaque, voidpf addr) {
    (void)opaque;
    (void)addr;
}

SEC("syscall")
int zlib_drain(void) {
    zctrl.capsule = capsule_continue_void(zctrl.capsule.continuation);
    return 0;
}

static void zlib_run_body(void) {
    zctrl.status = Z_STREAM_ERROR;
    zctrl.output_size = 0;
    if (!zctrl.input_size || !valid_u32_range(zctrl.input, zctrl.input_size) || !zctrl.output_capacity ||
        !valid_u32_range(zctrl.output, zctrl.output_capacity) || !valid_u32_range(zctrl.workspace, ZLIB_WORKSPACE_BYTES)) {
        return;
    }

    struct bump_allocator allocator = {.base = zctrl.workspace};
    z_stream s = {0};
    s.opaque = &allocator;
    s.zalloc = zalloc_bump;
    s.zfree = zfree_noop;
    s.next_in = zctrl.input;
    s.avail_in = (uInt)zctrl.input_size;
    s.next_out = zctrl.output;
    s.avail_out = (uInt)zctrl.output_capacity;
    int r = inflateInit(&s);
    if (r == Z_OK) {
        r = inflate(&s, Z_FINISH);
    }
    zctrl.status = r;
    zctrl.output_size = s.total_out;
    if (s.state) {
        (void)inflateEnd(&s);
    }
}

SEC("syscall")
int zlib_run(void) {
    zctrl.capsule = capsule_call_void(zlib_run_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
