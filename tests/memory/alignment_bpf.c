// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdatomic.h>
#include "bpf_capsule.h"
#include "memory_test.h"

volatile struct alignment_control alignment_control SEC(".data.align");

// Preserve the source access width and its promised alignment independently.
#define ACCESS(bits, alignment) \
    case bits * 16 + alignment: { \
        struct __attribute__((packed, aligned(alignment))) word { \
            uint##bits##_t value; \
        }; \
        volatile struct word* p = (void*)alignment_control.address; \
        alignment_control.observed = p->value; \
        p->value = alignment_control.value; \
        break; \
    }

static void check_alignment(void) {
    switch (alignment_control.mode) {
        ACCESS(16, 1)
        ACCESS(16, 2)
        ACCESS(32, 1)
        ACCESS(32, 2)
        ACCESS(32, 4)
        ACCESS(64, 1)
        ACCESS(64, 2)
        ACCESS(64, 4)
        ACCESS(64, 8)
#ifdef BPF_CAPSULE_TEST_MANAGED_RMW
        case 0: {
            // The crossing store touches only the first four bytes of the
            // next region. It must not restore a stale shadow over counter.
            struct __attribute__((packed, aligned(4))) pair {
                uint64_t data;
                _Atomic uint32_t counter;
            };
            volatile struct pair* p = (void*)alignment_control.address;
            atomic_fetch_add(&p->counter, 1);
            p->data = alignment_control.value;
            alignment_control.counter = atomic_load(&p->counter);
            break;
        }
#endif
    }
}

SEC("syscall")
int alignment_run(void) {
    alignment_control.result = capsule_call_void(check_alignment);
    return 0;
}

char _license[] SEC("license") = "GPL";
