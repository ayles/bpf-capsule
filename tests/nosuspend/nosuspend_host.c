// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <stdio.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "nosuspend_test.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: nosuspend_test_host OBJECT\n");
        return 2;
    }
    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    if (!object || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load nosuspend contract object\n");
        return 1;
    }
    size_t size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(object, ".data.nsresult");
    volatile struct nosuspend_result* result = map ? bpf_map__initial_value(map, &size) : NULL;
    struct bpf_program* program = bpf_object__find_program_by_name(object, "nosuspend_run");
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    int error = !result || !program ? -1 : capsule_test_run(bpf_program__fd(program), &options);
    uint64_t expected = (7ull * 17 + 3) ^ 0x5a5a;
    expected += 11;
    int pass = !error && result->status == CAPSULE_OK && !result->code && result->value == expected;
    printf(pass ? "NOSUSPEND-PASS\n" : "NOSUSPEND-FAIL\n");
    if (!pass && result) {
        fprintf(stderr, "status=%u code=%lld value=%llx expected=%llx\n", result->status, (long long)result->code, result->value, expected);
    }
    bpf_object__close(object);
    return pass ? 0 : 1;
}
