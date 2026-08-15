// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdint.h>
#include <stddef.h>

#include "wasm3_ctrl.h"
/* Source of the generated wasm32 module in zlib_wasm_module.h: this file is
 * only the freestanding entry shim; the inflate implementation is unmodified
 * zlib. See the rebuild recipe in zlib_wasm_module.h. */
#include "zlib.h"

typedef uint64_t guest_u64;

#define GUEST_INPUT_CAPACITY (128u << 10)
#define GUEST_OUTPUT_CAPACITY (256u << 10)
#define GUEST_HEAP_CAPACITY (512u << 10)

struct guest_zlib_control {
    guest_u64 input_length;
    guest_u64 status;
    guest_u64 output_length;
    guest_u64 checksum;
};

_Static_assert(sizeof(struct guest_zlib_control) == sizeof(struct wasm_zlib_control), "wasm3 control size drift");
_Static_assert(offsetof(struct guest_zlib_control, input_length) == offsetof(struct wasm_zlib_control, input_len), "wasm3 input length offset drift");
_Static_assert(offsetof(struct guest_zlib_control, status) == offsetof(struct wasm_zlib_control, status), "wasm3 status offset drift");
_Static_assert(offsetof(struct guest_zlib_control, output_length) == offsetof(struct wasm_zlib_control, output_len), "wasm3 output length offset drift");
_Static_assert(offsetof(struct guest_zlib_control, checksum) == offsetof(struct wasm_zlib_control, adler), "wasm3 checksum offset drift");

struct guest_zlib_control guest_zctrl;
unsigned char guest_zin[GUEST_INPUT_CAPACITY];
unsigned char guest_zout[GUEST_OUTPUT_CAPACITY];
static unsigned char guest_zheap[GUEST_HEAP_CAPACITY];
static unsigned long guest_zheap_used;

void* memset(void* destination, int value, unsigned long length) {
    unsigned char* out = destination;
    for (unsigned long i = 0; i < length; ++i) {
        out[i] = (unsigned char)value;
    }
    return destination;
}

void* memcpy(void* destination, const void* source, unsigned long length) {
    unsigned char* out = destination;
    const unsigned char* in = source;
    for (unsigned long i = 0; i < length; ++i) {
        out[i] = in[i];
    }
    return destination;
}

int memcmp(const void* left, const void* right, unsigned long length) {
    const unsigned char* a = left;
    const unsigned char* b = right;
    for (unsigned long i = 0; i < length; ++i) {
        if (a[i] != b[i]) {
            return (int)a[i] - (int)b[i];
        }
    }
    return 0;
}

static voidpf guest_zalloc(voidpf opaque, uInt items, uInt size) {
    unsigned long bytes = (unsigned long)items * size;
    unsigned long aligned = (bytes + 7u) & ~7u;
    if (aligned < bytes || guest_zheap_used > sizeof(guest_zheap) - aligned) {
        return Z_NULL;
    }
    voidpf result = guest_zheap + guest_zheap_used;
    guest_zheap_used += aligned;
    return result;
}

static void guest_zfree(voidpf opaque, voidpf address) {
    (void)opaque;
    (void)address;
}

/* The loader starts execution at this symbol and exposes all globals through
 * the guest virtual address space. */
__attribute__((used)) int guest_zlib_run(void) {
    guest_zheap_used = 0;
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.zalloc = guest_zalloc;
    stream.zfree = guest_zfree;
    stream.next_in = guest_zin;
    stream.avail_in = (uInt)guest_zctrl.input_length;
    stream.next_out = guest_zout;
    stream.avail_out = sizeof(guest_zout);

    int result = inflateInit2(&stream, 15);
    if (result == Z_OK) {
        result = inflate(&stream, Z_FINISH);
    }
    guest_zctrl.status = (guest_u64)(int64_t)result;
    guest_zctrl.output_length = stream.total_out;
    guest_zctrl.checksum = stream.adler;
    return result;
}
