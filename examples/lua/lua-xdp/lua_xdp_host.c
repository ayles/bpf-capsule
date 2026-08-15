// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Attach the Lua packet observer to one interface and print its audit events.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "lua_xdp_ctrl.h"
#include "lua_xdp_loader.h"
#include "lua_xdp.skel.h"

static const char* default_interface(char name[IFNAMSIZ]) {
    FILE* routes = fopen("/proc/net/route", "r");
    if (!routes) {
        return NULL;
    }

    char line[512];
    int best_metric = 0x7fffffff;
    name[0] = 0;
    (void)fgets(line, sizeof(line), routes);
    while (fgets(line, sizeof(line), routes)) {
        char candidate[IFNAMSIZ];
        unsigned long destination;
        unsigned long gateway;
        unsigned long mask;
        unsigned int flags;
        int refcnt;
        int use;
        int metric;
        int mtu;
        int window;
        int irtt;
        int fields = sscanf(
            line, "%15s %lx %lx %x %d %d %d %lx %d %d %d", candidate, &destination, &gateway, &flags, &refcnt, &use, &metric, &mask, &mtu, &window, &irtt
        );
        if (fields == 11 && destination == 0 && (flags & RTF_UP) && metric < best_metric) {
            strncpy(name, candidate, IFNAMSIZ - 1);
            name[IFNAMSIZ - 1] = 0;
            best_metric = metric;
        }
    }
    fclose(routes);
    return name[0] ? name : NULL;
}

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int print_event(void* context, void* data, size_t size) {
    (void)context;
    if (size) {
        fwrite(data, 1, size, stdout);
        if (((const unsigned char*)data)[size - 1] != '\n') {
            fputc('\n', stdout);
        }
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: lua-xdp OBSERVER [INTERFACE]\n");
        return 2;
    }

    char detected[IFNAMSIZ];
    const char* interface = argc == 3 ? argv[2] : default_interface(detected);
    if (!interface) {
        fprintf(stderr, "cannot find a default-route interface; specify one\n");
        return 1;
    }
    unsigned int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "unknown interface: %s\n", interface);
        return 1;
    }

    struct lua_xdp* skeleton = lua_xdp__open();
    struct bpf_object* object = skeleton ? skeleton->obj : NULL;
    if (!object) {
        fprintf(stderr, "cannot open Lua XDP object\n");
        return 1;
    }
    volatile struct lua_xdp_ctrl* control = &skeleton->data_lua_xdp->lua_xdp_control;

    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        const char* name = bpf_program__name(program);
        bpf_program__set_autoload(
            program,
            !strcmp(name, "lua_xdp_observe") || !strcmp(name, "lua_xdp_initialize") || !strcmp(name, "lua_xdp_initialize_drain") ||
                !strcmp(name, "bpf_capsule_init")
        );
    }
    if (lua_xdp_configure(object) || bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "cannot configure/load Lua XDP observer: %s\n", strerror(errno));
        lua_xdp__destroy(skeleton);
        return 1;
    }

    program = bpf_object__find_program_by_name(object, "lua_xdp_observe");
    struct bpf_map* events = bpf_object__find_map_by_name(object, "lua_xdp_events");
    if (!program || !events || lua_xdp_load_script(object, control, argv[1])) {
        fprintf(stderr, "cannot stage Lua XDP observer: %s\n", strerror(errno));
        lua_xdp__destroy(skeleton);
        return 1;
    }

    struct ring_buffer* ring = ring_buffer__new(bpf_map__fd(events), print_event, NULL, NULL);
    if (!ring || libbpf_get_error(ring)) {
        fprintf(stderr, "cannot open Lua XDP event ring\n");
        ring_buffer__free(ring);
        lua_xdp__destroy(skeleton);
        return 1;
    }

    // Kernel-side BPF runtime accounting: with stats enabled, the kernel
    // accumulates the observer's real execution time and invocation count in
    // run_time_ns and run_cnt — its own per-packet nanoseconds, not wall time.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);

    // A BPF link owns the attachment. Closing it on normal exit, crash or
    // terminal loss detaches the observer, and attach refuses to replace an
    // existing XDP program.
    struct bpf_link* link = bpf_program__attach_xdp(program, ifindex);
    long link_error = libbpf_get_error(link);
    if (link_error) {
        fprintf(stderr, "cannot attach passive XDP observer to %s: %s\n", interface, strerror((int)-link_error));
        ring_buffer__free(ring);
        lua_xdp__destroy(skeleton);
        return 1;
    }

    struct sigaction action = {.sa_handler = request_stop};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    fprintf(stderr, "observing live traffic on %s; Ctrl-C detaches\n", interface);

    int error = 0;
    while (!stop_requested) {
        error = ring_buffer__poll(ring, 250);
        if (error < 0 && error != -EINTR) {
            fprintf(stderr, "ring-buffer poll failed: %s\n", strerror(-error));
            break;
        }
    }

    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    if (stats_fd >= 0 && !bpf_prog_get_info_by_fd(bpf_program__fd(program), &info, &info_length) && info.run_cnt) {
        fprintf(
            stderr, "kernel execution: avg %llu ns per packet over %llu packets\n", (unsigned long long)(info.run_time_ns / info.run_cnt),
            (unsigned long long)info.run_cnt
        );
    }
    if (stats_fd >= 0) {
        close(stats_fd);
    }

    bpf_link__destroy(link);
    ring_buffer__free(ring);
    lua_xdp__destroy(skeleton);
    return error < 0 && error != -EINTR;
}
