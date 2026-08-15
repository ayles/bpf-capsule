// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "lua_xdp_loader.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule_host.h"
#include "lua_xdp_ctrl.h"

static char* read_script(const char* path, size_t* size) {
    FILE* file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) {
        if (file) {
            fclose(file);
        }
        return 0;
    }
    long length = ftell(file);
    if (length < 0 || (unsigned long)length >= LUA_XDP_SCRIPT_CAPACITY || fseek(file, 0, SEEK_SET)) {
        fclose(file);
        errno = E2BIG;
        return 0;
    }
    char* source = malloc((size_t)length + 1);
    if (!source || fread(source, 1, (size_t)length, file) != (size_t)length) {
        free(source);
        fclose(file);
        return 0;
    }
    fclose(file);
    source[length] = 0;
    *size = (size_t)length;
    return source;
}

int lua_xdp_configure(struct bpf_object* object) {
    int count = libbpf_num_possible_cpus();
    if (count < 1) {
        errno = count < 0 ? -count : EINVAL;
        return -1;
    }
    uint64_t heap_bytes = (4ull << 20) + (uint64_t)count * (256ull << 10);
    return bpf_capsule_configure(
        object,
        (struct bpf_capsule_config){
            .fiber_count = (unsigned int)count,
            .heap_bytes = heap_bytes,
            .reserved_bytes = LUA_XDP_SCRIPT_CAPACITY,
        }
    );
}

static int initialize_states(struct bpf_object* object, volatile struct lua_xdp_ctrl* control) {
    struct bpf_program* initialize = bpf_object__find_program_by_name(object, "lua_xdp_initialize");
    struct bpf_program* drain = bpf_object__find_program_by_name(object, "lua_xdp_initialize_drain");
    if (!initialize || !drain) {
        errno = ENOENT;
        return -1;
    }

    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long drains = 0;
    int error = bpf_prog_test_run_opts(bpf_program__fd(initialize), &options);
    while (!error && control->initialization.status == CAPSULE_PENDING) {
        if (drains == 2000000) {
            fprintf(stderr, "gave up after %lu drains: computation still pending\n", drains);
            errno = ETIMEDOUT;
            error = -1;
            break;
        }
        error = bpf_prog_test_run_opts(bpf_program__fd(drain), &options);
        if (!error) {
            drains++;
        }
    }
    if (error || control->initialization.status != CAPSULE_OK) {
        if (control->initialization.status == CAPSULE_EXITED) {
            if (control->initialization.code < 0) {
                if (!error) {
                    // Keep the external errno-style contract for terminal statuses.
                    errno = ECANCELED;
                }
                fprintf(
                    stderr, "Lua XDP initialization failed: capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->initialization.code),
                    (long long)control->initialization.code
                );
            } else {
                fprintf(stderr, "Lua XDP initialization exited with code %lld\n", (long long)control->initialization.code);
            }
            return -1;
        }
        if (!error) {
            // Keep the external errno-style contract for terminal statuses.
            errno = control->initialization.status == CAPSULE_YIELD ? EINPROGRESS : EPROTO;
        }
        fprintf(stderr, "Lua XDP initialization failed: %s; capsule status=%s\n", strerror(errno), bpf_capsule_status_string(control->initialization.status));
        return -1;
    }
    return 0;
}

int lua_xdp_load_script(struct bpf_object* object, volatile struct lua_xdp_ctrl* control, const char* path) {
    size_t source_size = 0;
    char* source = read_script(path, &source_size);
    if (!source || !control) {
        free(source);
        return -1;
    }
    struct bpf_capsule_memory memory;
    if (bpf_capsule_memory(object, &memory)) {
        free(source);
        return -1;
    }

    control->script_address = bpf_capsule_memory_reserved_start(&memory);
    if (bpf_capsule_memory_write(&memory, control->script_address, source, source_size + 1)) {
        free(source);
        return -1;
    }
    free(source);

    control->script_size = source_size;
    return initialize_states(object, control);
}
