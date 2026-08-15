// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "verifier_pointer_test.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct verifier_pointer_map_value);
} vpointer_values SEC(".maps");

volatile struct verifier_pointer_result verifier_pointer_output SEC(".data.vpointer");

struct scalar_pair {
    uint64_t value;
    uint64_t inverse;
};

static __attribute__((noinline)) struct scalar_pair scalar_transform(uint64_t value) {
    uint64_t transformed = value * 3 + 1;
    return (struct scalar_pair){transformed, ~transformed};
}

static struct verifier_pointer_value verifier_pointer_body(struct xdp_md* context, uint64_t replacement) {
    struct scalar_pair ingress = scalar_transform(context->ingress_ifindex);
    struct scalar_pair queue = scalar_transform(context->rx_queue_index);
    const unsigned int key = 0;
    struct verifier_pointer_map_value* value = bpf_map_lookup_elem(&vpointer_values, &key);
    if (!value) {
        return (struct verifier_pointer_value){.guard = 0xbad};
    }

    // The helper result and its GEPs remain verifier-native. They are consumed
    // before this physical region can return to the Capsule trampoline.
    struct verifier_pointer_value result = {
        .previous = value->value,
        .guard = value->guard,
        // Scalar ctx fields lose verifier-pointer provenance as soon as they
        // are loaded. Keep two calls so scalar_transform remains a real
        // managed call and proves those values may cross that boundary.
        .context_scalar = ingress.value + queue.value + (ingress.inverse == ~ingress.value) + (queue.inverse == ~queue.value),
    };
    value->value = replacement;
    result.observed = value->value;
    return result;
}

SEC("xdp")
int verifier_pointer_run(struct xdp_md* context) {
    verifier_pointer_output.capsule = capsule_call(&verifier_pointer_output.value, verifier_pointer_body, context, 0x1122334455667788ull);
    if (verifier_pointer_output.capsule.status == CAPSULE_PENDING) {
        struct capsule_result reset = capsule_reset(verifier_pointer_output.capsule.continuation);
        if (reset.status != CAPSULE_OK) {
            verifier_pointer_output.capsule = reset;
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
