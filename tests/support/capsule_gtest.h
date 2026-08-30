// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Shared helpers for the gtest suites. Everything runs in-process through
// libbpf; no test spawns a subprocess. Suites that load BPF objects need
// privilege: run `sudo ctest` (or the suite binaries directly under sudo).
#pragma once

#include "bpf_capsule_types.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include <gtest/gtest.h>

// Loading BPF objects requires CAP_BPF/CAP_SYS_ADMIN; euid==0 is the simple
// sufficient check. GTEST_SKIP keeps an unprivileged run honest instead of
// red.
#define CAPSULE_REQUIRE_BPF_PRIVILEGE() \
    do { \
        if (geteuid() != 0) { \
            GTEST_SKIP() << "loading BPF objects needs root; run ctest under sudo"; \
        } \
    } while (0)

// Resolve one named BPF global from object BTF, for objects whose section
// fields the generated skeleton does not type (unsectioned/renamed globals).
static inline void* capsule_test_global(struct bpf_object* object, const char* name, size_t* size) {
    if (!object || !name || !*name) {
        errno = EINVAL;
        return nullptr;
    }
    const struct btf* btf = bpf_object__btf(object);
    int variable_id = btf ? btf__find_by_name_kind(btf, name, BTF_KIND_VAR) : -1;
    if (variable_id < 0) {
        errno = ENOENT;
        return nullptr;
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
            struct bpf_map* map = section ? bpf_object__find_map_by_name(object, section) : nullptr;
            size_t map_size = 0;
            uint8_t* base = map ? (uint8_t*)bpf_map__initial_value(map, &map_size) : nullptr;
            if (!base || variables[index].offset > map_size || variables[index].size > map_size - variables[index].offset) {
                errno = EFAULT;
                return nullptr;
            }
            if (size) {
                *size = variables[index].size;
            }
            return base + variables[index].offset;
        }
    }
    errno = ENOENT;
    return nullptr;
}

// BPF_PROG_TEST_RUN has two error channels: the syscall result and the
// program's own return value. Generated entry prologues report failures such
// as arena allocation through a negative retval.
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

static inline int capsule_test_run_program(struct bpf_object* object, const char* name) {
    struct bpf_program* program = bpf_object__find_program_by_name(object, name);
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    return program ? capsule_test_run(bpf_program__fd(program), &options) : -1;
}

// Run one entry and follow budget-driven continuations until completion.
// Returns zero when the computation returned (CAPSULE_OK) or exited with a
// guest status (CAPSULE_EXITED, code >= 0). CAPSULE_EXITED with a negative
// framework code sets ECANCELED; CAPSULE_YIELD sets EINPROGRESS; an unknown
// status sets EPROTO; the drain cap sets ETIMEDOUT.
static inline int capsule_test_drive(int entry_fd, int drain_fd, struct bpf_test_run_opts* options, unsigned long max_drains, unsigned long* entries,
    unsigned long* drains, volatile const struct capsule_result* result) {
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
        struct capsule_result current = {};
        current.code = result->code;
        current.status = result->status;
        current.continuation = result->continuation;
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
