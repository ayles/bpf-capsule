// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "verifier_pointer_test.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: verifier_pointer_test_host OBJECT\n");
        return 2;
    }

    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    if (!object || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load verifier-pointer object\n");
        return 1;
    }

    const unsigned int key = 0;
    const struct verifier_pointer_map_value initial = {
        .value = 0x1020304050607080ull,
        .guard = 0xa1b2c3d4e5f60718ull,
    };
    struct verifier_pointer_map_value final = {0};
    struct bpf_map* values = bpf_object__find_map_by_name(object, "vpointer_values");
    struct bpf_map* output_map = bpf_object__find_map_by_name(object, ".data.vpointer");
    size_t output_size = 0;
    volatile struct verifier_pointer_result* output = output_map ? bpf_map__initial_value(output_map, &output_size) : NULL;
    struct bpf_program* program = bpf_object__find_program_by_name(object, "verifier_pointer_run");
    const unsigned char packet[64] = {0};
    // Linux 5.15 requires a supplied XDP context's data_end to match the
    // packet length. Keep device fields zero: naming loopback asks the old
    // test-run path for a registered XDP RX queue, which loopback does not
    // provide and is unrelated to the pointer-lifetime contract under test.
    struct xdp_md context = {.data_end = sizeof(packet)};
    struct bpf_test_run_opts options = {
        .sz = sizeof(options),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .ctx_in = &context,
        .ctx_size_in = sizeof(context),
    };
    unsigned int ingress_ifindex = if_nametoindex("lo");

    if (!values || !output || output_size < sizeof(*output) || !program) {
        fprintf(
            stderr, "missing verifier-pointer interface: values=%p output=%p size=%zu/%zu program=%p\n", (void*)values, (void*)output, output_size,
            sizeof(*output), (void*)program
        );
    }

    int update_error = values ? bpf_map_update_elem(bpf_map__fd(values), &key, &initial, BPF_ANY) : -1;
    int run_error = !update_error && program ? capsule_test_run(bpf_program__fd(program), &options) : -1;
    int run_errno = errno;
    int lookup_error = values ? bpf_map_lookup_elem(bpf_map__fd(values), &key, &final) : -1;
    int pass = ingress_ifindex && values && output && output_size >= sizeof(*output) && program && !update_error && !run_error && !lookup_error &&
        output->capsule.status == CAPSULE_OK && !output->capsule.code && output->value.previous == initial.value &&
        output->value.observed == 0x1122334455667788ull && output->value.guard == initial.guard && output->value.context_scalar == ingress_ifindex * 3 + 4 &&
        final.value == output->value.observed && final.guard == initial.guard;

    if (!pass && output) {
        fprintf(
            stderr,
            "verifier pointer update=%d run=%d (%s) lookup=%d status=%u code=%lld previous=%llx observed=%llx guard=%llx context=%llu "
            "final=%llx/%llx\n",
            update_error, run_error, strerror(run_errno), lookup_error, output->capsule.status, (long long)output->capsule.code, output->value.previous,
            output->value.observed, output->value.guard, output->value.context_scalar, final.value, final.guard
        );
    }
    printf(pass ? "VERIFIER-POINTER-PASS\n" : "VERIFIER-POINTER-FAIL\n");
    bpf_object__close(object);
    return pass ? 0 : 1;
}
