// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <stdio.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "rehash_test.h"

static int run(struct bpf_program* program) {
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    return program ? capsule_test_run(bpf_program__fd(program), &options) : -1;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: rehash_test_host OBJECT\n");
        return 2;
    }
    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    if (!object || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load rehash test object\n");
        bpf_object__close(object);
        return 1;
    }

    size_t size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(object, ".data.rehash");
    volatile struct rehash_test_result* result = map ? bpf_map__initial_value(map, &size) : NULL;
    struct bpf_program* entry = bpf_object__find_program_by_name(object, "rehash_test_run");
    struct bpf_program* continuation = bpf_object__find_program_by_name(object, "rehash_test_continue");
    int error = !result || size < sizeof(*result) || run(entry);
    unsigned int drains = 0;
    while (!error && result->capsule.status == CAPSULE_PENDING && drains++ < 1024) {
        error = run(continuation);
    }

    int pass = !error && result->capsule.status == CAPSULE_OK && !result->capsule.code && !result->failures && result->old_size == 1 && result->new_size == 2 &&
        result->calls == 2 && result->grew == 2 && result->poison_calls == 2;
    printf(pass ? "REHASH-PASS\n" : "REHASH-FAIL\n");
    if (!pass && result) {
        fprintf(
            stderr, "syscall=%d status=%u code=%lld continuation=%llu drains=%u failures=%llx old=%u new=%u calls=%u grew=%u poison=%u\n", error,
            result->capsule.status, (long long)result->capsule.code, (unsigned long long)result->capsule.continuation, drains, result->failures,
            result->old_size, result->new_size, result->calls, result->grew, result->poison_calls
        );
    }
    bpf_object__close(object);
    return pass ? 0 : 1;
}
