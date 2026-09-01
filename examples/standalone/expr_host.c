// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Minimal libbpf host for the recursive expression evaluator.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "expr_ctrl.h"
#include "expr.skel.h"

enum {
    EXPR_INPUT_MAX = 4096,
    EXPR_HEAP_BYTES = 1u << 20,
};

static int read_max_drains(unsigned long* result) {
    const char* text = getenv("BPF_CAPSULE_MAX_DRAINS");
    *result = 0;
    if (!text || !*text) {
        return 0;
    }
    char* end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (text[0] < '0' || text[0] > '9' || errno || !end || *end) {
        fprintf(stderr, "BPF_CAPSULE_MAX_DRAINS must be a non-negative integer\n");
        return -1;
    }
    *result = value;
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: expr [EXPRESSION]\n");
        return 1;
    }
    unsigned long max_drains = 0;
    if (read_max_drains(&max_drains)) {
        return 1;
    }

    char expression[EXPR_INPUT_MAX];
    size_t length = 0;
    if (argc == 2) {
        length = strlen(argv[1]);
        if (!length || length > sizeof(expression)) {
            fprintf(stderr, "expression must be 1..%zu bytes\n", sizeof(expression));
            return 1;
        }
        memcpy(expression, argv[1], length);
    } else {
        enum { DEPTH = 64 };
        char* out = expression;
        for (int i = 0; i < DEPTH; ++i) {
            *out++ = '(';
            *out++ = '1';
            *out++ = '+';
        }
        *out++ = '1';
        for (int i = 0; i < DEPTH; ++i) {
            *out++ = ')';
        }
        length = (size_t)(out - expression);
    }

    int result = 1;
    struct expr* skeleton = expr__open();
    struct bpf_capsule capsule = {0};
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    size_t reserved_bytes = (length + 15u) & ~(size_t)15u;
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = reserved_bytes + EXPR_HEAP_BYTES,
                .reserved_bytes = length,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        goto cleanup;
    }

    volatile struct expr_bpf_ctrl* control = &skeleton->data_ectrl->ectrl;
    control->input = bpf_capsule_memory_reserved_start(&capsule);
    control->input_size = length;
    if (bpf_capsule_memcpy(&capsule, control->input, expression, length)) {
        fprintf(stderr, "cannot stage expression: %s\n", strerror(errno));
        goto cleanup;
    }

    int run_fd = bpf_program__fd(skeleton->progs.expr_run);
    int drain_fd = bpf_program__fd(skeleton->progs.expr_drain);
    if (run_fd < 0 || drain_fd < 0) {
        fprintf(stderr, "BPF object is missing an expression program\n");
        goto cleanup;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    if (bpf_prog_test_run_opts(run_fd, &options)) {
        perror("run");
        goto cleanup;
    }
    unsigned long drains = 0;
    while (control->capsule.status == CAPSULE_PENDING) {
        if (drains == max_drains) {
            fprintf(stderr, "computation is still pending after %lu drains; set BPF_CAPSULE_MAX_DRAINS to permit more\n", drains);
            goto cleanup;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            perror("drain");
            goto cleanup;
        }
        drains++;
    }
    if (control->capsule.status != CAPSULE_OK) {
        if (control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
            fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
        } else if (control->capsule.status == CAPSULE_EXITED) {
            fprintf(stderr, "capsule exited with code %lld\n", (long long)control->capsule.code);
        } else {
            fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        }
        goto cleanup;
    }
    if (control->parse_error) {
        fprintf(stderr, "parse error at byte %zu\n", control->error_at);
        goto cleanup;
    }

    printf("%lld\n", (long long)control->value);
    fprintf(stderr, "continuation drains: %lu\n", drains);
    result = 0;

cleanup:
    if (skeleton) {
        (void)bpf_capsule_release(&capsule);
        expr__destroy(skeleton);
    }
    return result;
}
