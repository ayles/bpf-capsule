// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>

#include "bpf_capsule_host.h"
#include "libc_test.h"
#include "../support/capsule_test.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: libc_test_host OBJECT\n");
        return 2;
    }
    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    struct bpf_capsule_config config = {.fiber_count = 1};
    if (!object || bpf_capsule_configure(object, config) || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load libc test object\n");
        bpf_object__close(object);
        return 1;
    }

    size_t size = 0;
    volatile struct libc_test_result* result = capsule_test_global(object, "libc_test_output", &size);
    struct bpf_program* entry = bpf_object__find_program_by_name(object, "libc_test_run");
    struct bpf_program* continuation = bpf_object__find_program_by_name(object, "libc_test_continue");
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long entries = 0;
    unsigned long drains = 0;
    int error = !result || size < sizeof(*result) || !entry || !continuation ||
        capsule_test_drive(bpf_program__fd(entry), bpf_program__fd(continuation), &options, 100000, &entries, &drains, result ? &result->capsule : NULL);

    const char* expected = "-7/-32000/-9/-9223372036854775808/17/-9223372036854775808/0x00002a/abc/%";
    int pass = !error && !result->failures && result->capsule.status == CAPSULE_OK && result->truncated_length == 20 &&
        !strcmp((const char*)result->truncated, "-922") && result->formatted_length == (int)strlen(expected) &&
        !strcmp((const char*)result->formatted, expected) && result->parsed_max == ~0ull && result->parsed_overflow == ~0ull &&
        result->parsed_negative == ~0ull && result->parsed_min == (-9223372036854775807l - 1l) && result->overflow_errno == ERANGE;

    printf(pass ? "LIBC-PASS\n" : "LIBC-FAIL\n");
    if (!pass && result) {
        fprintf(
            stderr, "error=%d status=%u code=%lld failures=%llx truncated=%d:'%s' formatted=%d:'%s' parsed=%llu/%llu/%llu/%ld errno=%u\n", error,
            result->capsule.status, (long long)result->capsule.code, result->failures, result->truncated_length, result->truncated, result->formatted_length,
            result->formatted, result->parsed_max, result->parsed_overflow, result->parsed_negative, result->parsed_min, result->overflow_errno
        );
    }
    bpf_object__close(object);
    return pass ? 0 : 1;
}
