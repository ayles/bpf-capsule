// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// zlib inflate in the kernel — the toolchain's second program.
//
// The host deflates a buffer with its own zlib, writes it directly into a
// heap reservation, and the kernel inflates it with stock zlib sources
// compiled through the BPF Capsule pipeline.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "zlib.h"
#include "zlib_ctrl.h"

struct zlib_bpf_ctrl zctrl SEC(".data.zctrl");

static unsigned long workspace_used;

static int valid_u32_range(uint64_t address, uint64_t size) {
    return address <= (uInt)-1 && size <= (uInt)-1 && address + size <= 1ull << 32;
}

static voidpf zalloc_bump(voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    unsigned long bytes = (unsigned long)items * size;
    if ((items && bytes / items != size) || bytes > ~0ul - 7ul) {
        return 0;
    }
    unsigned long aligned = (bytes + 7ul) & ~7ul;
    unsigned long capacity = (unsigned long)zctrl.workspace_capacity;
    if (workspace_used > capacity || aligned > capacity - workspace_used) {
        return 0;
    }
    unsigned int address = (unsigned int)zctrl.workspace_address + (unsigned int)workspace_used;
    workspace_used += aligned;
    return (voidpf)(unsigned long)address;
}
static void zfree_noop(voidpf opaque, voidpf addr) {
    (void)opaque;
    (void)addr;
}

SEC("syscall")
int zlib_drain() {
    zctrl.capsule = capsule_continue_void(zctrl.capsule.continuation);
    return 0;
}

static void zlib_run_body(void) {
    zctrl.status = (uint64_t)(int64_t)Z_STREAM_ERROR;
    zctrl.output_size = 0;
    zctrl.adler = 0;
    if (!zctrl.input_size || !valid_u32_range(zctrl.input_address, zctrl.input_size) || !zctrl.output_capacity ||
        !valid_u32_range(zctrl.output_address, zctrl.output_capacity) || !zctrl.workspace_capacity ||
        !valid_u32_range(zctrl.workspace_address, zctrl.workspace_capacity)) {
        return;
    }

    workspace_used = 0;
    z_stream s = {0};
    s.zalloc = zalloc_bump;
    s.zfree = zfree_noop;
    s.next_in = capsule_memory_pointer(Bytef, zctrl.input_address);
    s.avail_in = (uInt)zctrl.input_size;
    s.next_out = capsule_memory_pointer(Bytef, zctrl.output_address);
    s.avail_out = (uInt)zctrl.output_capacity;
    int r = inflateInit2(&s, 15);
    if (r == Z_OK) {
        r = inflate(&s, Z_FINISH);
    }
    zctrl.status = (uint64_t)(int64_t)r;
    zctrl.output_size = s.total_out;
    // inflate() has already run stock zlib's checksum over every produced
    // byte.  Recomputing it here put a second full 2 MiB Adler pass inside the
    // BPF timing while the matched native uncompress() performed only the
    // normal one, making the compiler appear roughly 25% slower than it was.
    zctrl.adler = s.adler;
}

SEC("syscall")
int zlib_run() {
    zctrl.capsule = capsule_call_void(zlib_run_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
