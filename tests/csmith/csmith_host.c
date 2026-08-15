// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "csmith_include.h"

#include <bpf/libbpf.h>
#include <stdio.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "csmith_case.h"
#include "csmith.skel.h"

static uint64_t native_checksum(void) {
    crc32_context = 0;
    (void)csmith_generated_main();
    return crc32_context;
}

int main(void) {
    uint64_t expected = native_checksum();
    struct csmith_test* skeleton = csmith_test__open();
    if (!skeleton || capsule_test_load_skeleton(skeleton->skeleton) || bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "could not load csmith test object\n");
        csmith_test__destroy(skeleton);
        return 1;
    }

    size_t size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(skeleton->obj, ".data.csmith");
    volatile struct csmith_test_result* result = map ? bpf_map__initial_value(map, &size) : NULL;
    struct bpf_program* entry = bpf_object__find_program_by_name(skeleton->obj, "csmith_run");
    struct bpf_program* continuation = bpf_object__find_program_by_name(skeleton->obj, "csmith_continue");
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    int error = !result || size < sizeof(*result) || !entry || !continuation || capsule_test_run(bpf_program__fd(entry), &options);
    unsigned int drains = 0;
    while (!error && result->capsule.status == CAPSULE_PENDING && drains < 1024) {
        ++drains;
        error = capsule_test_run(bpf_program__fd(continuation), &options);
    }

    int pass = !error && result->capsule.status == CAPSULE_OK && !result->capsule.code && result->checksum == expected;
    fprintf(stderr, "csmith checksum: native=%llx capsule=%llx drains=%u\n", expected, result ? result->checksum : 0, drains);
    fprintf(stderr, "invocations: 1 entry + %u drains\n", drains);
    printf(pass ? "CSMITH-PASS\n" : "CSMITH-FAIL\n");
    csmith_test__destroy(skeleton);
    return pass ? 0 : 1;
}
