// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Test-suite helpers for driving syscall-model Capsule programs. This header
// is NOT installed and is not part of the public host API: applications run
// their programs with plain libbpf (bpf_prog_test_run_opts) and branch on
// capsule_result.status directly. The proof suite keeps these wrappers so the
// regression can count entries and drains uniformly and classify terminal
// states through errno.
#pragma once

#include "bpf_capsule_abi.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Resolve one named BPF global from object BTF. The proof suite loads some
// objects raw (bpf_object__open_file, no generated skeleton), so it cannot
// use the typed section fields application hosts get from bpftool; this
// stock-libbpf walk is test plumbing, not Capsule API.
static inline void* capsule_test_global(struct bpf_object* object, const char* name, size_t* size) {
    if (!object || !name || !*name) {
        errno = EINVAL;
        return NULL;
    }
    const struct btf* btf = bpf_object__btf(object);
    int variable_id = btf ? btf__find_by_name_kind(btf, name, BTF_KIND_VAR) : -1;
    if (variable_id < 0) {
        errno = ENOENT;
        return NULL;
    }

    for (uint32_t type_id = 1; type_id < btf__type_cnt(btf); ++type_id) {
        const struct btf_type* type = btf__type_by_id(btf, type_id);
        if (!type || !btf_is_datasec(type)) {
            continue;
        }
        const struct btf_var_secinfo* variables = btf_var_secinfos(type);
        for (uint32_t index = 0; index < btf_vlen(type); ++index) {
            if (variables[index].type != (uint32_t)variable_id) {
                continue;
            }
            const char* section = btf__name_by_offset(btf, type->name_off);
            struct bpf_map* map = section ? bpf_object__find_map_by_name(object, section) : NULL;
            size_t map_size = 0;
            uint8_t* base = map ? bpf_map__initial_value(map, &map_size) : NULL;
            if (!base || variables[index].offset > map_size || variables[index].size > map_size - variables[index].offset) {
                errno = EFAULT;
                return NULL;
            }
            if (size) {
                *size = variables[index].size;
            }
            return base + variables[index].offset;
        }
    }

    errno = ENOENT;
    return NULL;
}

// Suite-owned load instrumentation. The library never prints or reads
// environment variables, but the regression harness wants one uniform
// "verified+loaded" line (its LOAD metric) and, on request, the kernel's
// verifier statistics (its verifier_processed_insns metric). Both stay
// opt-in through BPF_CAPSULE_LOAD_TIMING / BPF_CAPSULE_VERIFIER_STATS so an
// interactive run stays quiet.
static inline int __capsule_test_env(const char* name) {
    const char* enabled = getenv(name);
    return enabled && *enabled && strcmp(enabled, "0");
}

static inline void __capsule_test_release_verifier_stats(struct bpf_object* object, int print) {
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

static inline int __capsule_test_configure_verifier_stats(struct bpf_object* object) {
    if (!__capsule_test_env("BPF_CAPSULE_VERIFIER_STATS")) {
        return 0;
    }
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        char* log = calloc(1, 64u * 1024u);
        int error = log ? bpf_program__set_log_buf(program, log, 64u * 1024u) : -1;
        // BPF_LOG_STATS is bit 2 of attr.log_level. It is intentionally not
        // part of the UAPI header bundled by every supported libbpf release.
        if (!error) {
            error = bpf_program__set_log_level(program, 1u << 2);
        }
        if (error) {
            free(log);
            __capsule_test_release_verifier_stats(object, 0);
            errno = error < 0 ? -error : error;
            return -1;
        }
    }
    return 1;
}

// Load through the ordinary libbpf skeleton call, timed, with the optional
// verifier-stats record. Hosts still run bpf_capsule_configure() before and
// bpf_capsule_finish_initialization() after: this wrapper owns only the
// suite metrics around the load itself.
static inline int capsule_test_load_skeleton(struct bpf_object_skeleton* skeleton) {
    if (!skeleton || !skeleton->obj) {
        errno = EINVAL;
        return -1;
    }
    int verifier_stats = __capsule_test_configure_verifier_stats(*skeleton->obj);
    if (verifier_stats < 0) {
        return -1;
    }
    struct timespec begin, end;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    int error = bpf_object__load_skeleton(skeleton);
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (verifier_stats) {
        __capsule_test_release_verifier_stats(*skeleton->obj, 1);
    }
    if (__capsule_test_env("BPF_CAPSULE_LOAD_TIMING")) {
        double seconds = (end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1e9;
        fprintf(stderr, "verified+loaded in %.3f s\n", seconds);
    }
    return error;
}

static inline int capsule_test_load_object(struct bpf_object* object) {
    if (!object) {
        errno = EINVAL;
        return -1;
    }
    int verifier_stats = __capsule_test_configure_verifier_stats(object);
    if (verifier_stats < 0) {
        return -1;
    }
    struct timespec begin, end;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    int error = bpf_object__load(object);
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (verifier_stats) {
        __capsule_test_release_verifier_stats(object, 1);
    }
    if (__capsule_test_env("BPF_CAPSULE_LOAD_TIMING")) {
        double seconds = (end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1e9;
        fprintf(stderr, "verified+loaded in %.3f s\n", seconds);
    }
    return error;
}

// BPF_PROG_TEST_RUN has two error channels: the syscall result and the
// program's own return value. Compiler-generated entry prologues use a
// negative return for failures such as arena allocation, so ignoring retval
// can turn a failed invocation into plausible zero-filled test output.
static inline int capsule_test_run(int program_fd, struct bpf_test_run_opts* options) {
    if (!options) {
        errno = EINVAL;
        return -1;
    }
    int error = bpf_prog_test_run_opts(program_fd, options);
    if (!error && (int)options->retval < 0) {
        errno = -(int)options->retval;
        return -1;
    }
    return error;
}

// Run one entry and follow budget-driven continuations until completion. The
// result must point into an mmaped control section updated by both entry and
// drain. Return zero when the computation returned (CAPSULE_OK) or exited
// with a guest status (CAPSULE_EXITED, code >= 0); callers branch on status
// and code. CAPSULE_EXITED with a negative framework code sets errno to
// ECANCELED while preserving the structured code in result. CAPSULE_YIELD
// sets EINPROGRESS because application interaction is required; an unknown
// status sets EPROTO. Invocation failures preserve the errno set by
// capsule_test_run(), and the finite drain cap sets ETIMEDOUT. The
// entries/drains counters accumulate across calls.
static inline int capsule_test_drive(
    int entry_fd, int drain_fd, struct bpf_test_run_opts* options, unsigned long max_drains, unsigned long* entries, unsigned long* drains,
    volatile const struct capsule_result* result
) {
    if (!options || !result) {
        errno = EINVAL;
        return -1;
    }
    int error = capsule_test_run(entry_fd, options);
    if (entries) {
        (*entries)++;
    }
    if (error) {
        return -1;
    }
    for (unsigned long iteration = 0;; iteration++) {
        struct capsule_result current = {
            .code = result->code,
            .status = result->status,
            .continuation = result->continuation,
        };
        if (current.status == CAPSULE_OK) {
            return 0;
        }
        if (current.status == CAPSULE_EXITED) {
            if (current.code < 0) {
                errno = ECANCELED;
                return -1;
            }
            return 0;
        }
        if (current.status == CAPSULE_YIELD) {
            errno = EINPROGRESS;
            return -1;
        }
        if (current.status != CAPSULE_PENDING) {
            errno = EPROTO;
            return -1;
        }
        if (iteration >= max_drains) {
            errno = ETIMEDOUT;
            return -1;
        }
        error = capsule_test_run(drain_fd, options);
        if (drains) {
            (*drains)++;
        }
        if (error) {
            return -1;
        }
    }
}
