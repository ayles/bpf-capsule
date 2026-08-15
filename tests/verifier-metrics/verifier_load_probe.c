// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Suite-only loader for verifier-complexity evidence. Public examples keep
// their ordinary libbpf lifecycle; this process loads a second copy solely
// with BPF_LOG_STATS enabled and prints the kernel's verifier summaries.
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef BPF_LOG_STATS
#define BPF_LOG_STATS (1u << 2)
#endif

#define LOG_BYTES (64u << 10)

static void release_logs(struct bpf_object* object, int print) {
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        size_t size = 0;
        const char* log = bpf_program__log_buf(program, &size);
        if (print && log && size && *log) {
            size_t length = strnlen(log, size);
            fprintf(stderr, "verifier stats [%s]: %.*s", bpf_program__name(program), (int)length, log);
            if (length && log[length - 1] != '\n') {
                fputc('\n', stderr);
            }
        }
        if (log) {
            (void)bpf_program__set_log_level(program, 0);
            bpf_program__set_log_buf(program, NULL, 0);
            free((void*)log);
        }
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: verifier_load_probe OBJECT\n");
        return 2;
    }

    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    long open_error = libbpf_get_error(object);
    if (open_error) {
        fprintf(stderr, "cannot open %s: %s\n", argv[1], strerror((int)-open_error));
        return 1;
    }

    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        char* log = calloc(1, LOG_BYTES);
        int error = log ? bpf_program__set_log_buf(program, log, LOG_BYTES) : -ENOMEM;
        if (!error) {
            error = bpf_program__set_log_level(program, BPF_LOG_STATS);
        }
        if (error) {
            fprintf(stderr, "cannot configure verifier log for %s: %s\n", bpf_program__name(program), strerror(error < 0 ? -error : error));
            free(log);
            release_logs(object, 0);
            bpf_object__close(object);
            return 1;
        }
    }

    struct timespec begin;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    int error = bpf_object__load(object);
    clock_gettime(CLOCK_MONOTONIC, &end);
    release_logs(object, 1);
    if (error) {
        fprintf(stderr, "cannot load %s: %s\n", argv[1], strerror(error < 0 ? -error : error));
        bpf_object__close(object);
        return 1;
    }
    double seconds = (end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1e9;
    fprintf(stderr, "verified+loaded in %.3f s\n", seconds);
    bpf_object__close(object);
    puts("VERIFIER-METRICS-PASS");
    return 0;
}
