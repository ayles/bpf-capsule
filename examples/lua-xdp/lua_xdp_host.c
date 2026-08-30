// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Attach the Lua packet observer to one interface and print its audit events.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "lua_xdp_ctrl.h"
#include "lua_xdp.skel.h"

static char* read_script(const char* path, size_t* size) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END)) {
        int saved_errno = errno;
        fclose(file);
        errno = saved_errno;
        return NULL;
    }
    long length = ftell(file);
    if (length <= 0) {
        int saved_errno = length < 0 ? errno : EINVAL;
        fclose(file);
        errno = saved_errno;
        return NULL;
    }
    if (fseek(file, 0, SEEK_SET)) {
        int saved_errno = errno;
        fclose(file);
        errno = saved_errno;
        return NULL;
    }
    char* source = malloc((size_t)length);
    if (!source) {
        fclose(file);
        return NULL;
    }
    if (fread(source, 1, (size_t)length, file) != (size_t)length) {
        int saved_errno = ferror(file) && errno ? errno : EIO;
        free(source);
        fclose(file);
        errno = saved_errno;
        return NULL;
    }
    fclose(file);
    *size = (size_t)length;
    return source;
}

static int configure_capsule(struct bpf_capsule* capsule, struct bpf_object* object, size_t script_size) {
    int count = libbpf_num_possible_cpus();
    if (count < 1) {
        errno = count < 0 ? -count : EINVAL;
        return -1;
    }
    return bpf_capsule_configure(capsule, object,
        (struct bpf_capsule_config){
            .fiber_count = (unsigned int)count,
            .heap_bytes = (4ull << 20) + (uint64_t)count * (256ull << 10),
            .reserved_bytes = script_size,
        });
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
            errno = ETIMEDOUT;
            return -1;
        }
        error = bpf_prog_test_run_opts(bpf_program__fd(drain), &options);
        ++drains;
    }
    if (error) {
        return -1;
    }
    if (control->initialization.status == CAPSULE_OK) {
        return 0;
    }
    if (control->initialization.status == CAPSULE_EXITED && control->initialization.code < 0) {
        fprintf(
            stderr, "Lua initialization stopped: %s (%lld)\n", bpf_capsule_error_string(control->initialization.code), (long long)control->initialization.code);
        errno = ECANCELED;
    } else {
        errno = control->initialization.status == CAPSULE_YIELD ? EINPROGRESS : EPROTO;
    }
    return -1;
}

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int print_event(void* context, void* data, size_t size) {
    (void)context;
    fwrite(data, 1, size, stdout);
    fflush(stdout);
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: lua-xdp OBSERVER INTERFACE\n");
        return 2;
    }

    const char* interface = argv[2];
    unsigned int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "unknown interface: %s\n", interface);
        return 1;
    }

    size_t source_size = 0;
    char* source = read_script(argv[1], &source_size);
    if (!source) {
        fprintf(stderr, "cannot read Lua observer: %s\n", strerror(errno));
        return 1;
    }

    int result = 1;
    int poll_error = 0;
    struct lua_xdp* skeleton = lua_xdp__open();
    struct bpf_capsule capsule = {0};
    struct ring_buffer* ring = NULL;
    struct bpf_link* link = NULL;
    struct bpf_object* object = skeleton ? skeleton->obj : NULL;
    if (!object) {
        fprintf(stderr, "cannot open Lua XDP object\n");
        goto cleanup;
    }
    volatile struct lua_xdp_ctrl* control = &skeleton->data_lua_xdp->lua_xdp_control;

    if (configure_capsule(&capsule, object, source_size) || bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "cannot configure/load Lua XDP observer: %s\n", strerror(errno));
        goto cleanup;
    }

    struct bpf_program* program = bpf_object__find_program_by_name(object, "lua_xdp_observe");
    struct bpf_map* events = bpf_object__find_map_by_name(object, "lua_xdp_events");
    if (!program || !events) {
        errno = ENOENT;
        fprintf(stderr, "cannot find Lua XDP programs and maps\n");
        goto cleanup;
    }
    control->script = bpf_capsule_memory_reserved_start(&capsule);
    control->script_size = source_size;
    if (bpf_capsule_memcpy(&capsule, control->script, source, source_size) || initialize_states(object, control)) {
        fprintf(stderr, "cannot stage Lua XDP observer: %s\n", strerror(errno));
        goto cleanup;
    }
    free(source);
    source = NULL;

    ring = ring_buffer__new(bpf_map__fd(events), print_event, NULL, NULL);
    if (!ring) {
        fprintf(stderr, "cannot open Lua XDP event ring: %s\n", strerror(errno));
        goto cleanup;
    }
    long ring_error = libbpf_get_error(ring);
    if (ring_error) {
        ring = NULL;
        fprintf(stderr, "cannot open Lua XDP event ring: %s\n", strerror((int)-ring_error));
        goto cleanup;
    }

    // A BPF link owns the attachment. Closing it on normal exit, crash or
    // terminal loss detaches the observer, and attach refuses to replace an
    // existing XDP program.
    link = bpf_program__attach_xdp(program, ifindex);
    if (!link) {
        fprintf(stderr, "cannot attach passive XDP observer to %s: %s\n", interface, strerror(errno));
        goto cleanup;
    }
    long link_error = libbpf_get_error(link);
    if (link_error) {
        link = NULL;
        fprintf(stderr, "cannot attach passive XDP observer to %s: %s\n", interface, strerror((int)-link_error));
        goto cleanup;
    }

    struct sigaction action = {.sa_handler = request_stop};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    fprintf(stderr, "observing live traffic on %s; Ctrl-C detaches\n", interface);

    while (!stop_requested) {
        poll_error = ring_buffer__poll(ring, 250);
        if (poll_error < 0 && poll_error != -EINTR) {
            fprintf(stderr, "ring-buffer poll failed: %s\n", strerror(-poll_error));
            break;
        }
    }

    result = poll_error < 0 && poll_error != -EINTR;

cleanup:
    if (link) {
        bpf_link__destroy(link);
    }
    if (ring) {
        ring_buffer__free(ring);
    }
    free(source);
    (void)bpf_capsule_release(&capsule);
    lua_xdp__destroy(skeleton);
    return result;
}
