// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "../../tests/support/capsule_test.h"
#include "lua_xdp_ctrl.h"
#include "lua_xdp_loader.h"
#include "lua_xdp.skel.h"

#define SAMPLE_PACKET_BYTES 54u

static const unsigned char sample_packet[SAMPLE_PACKET_BYTES] = {
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x08,
    0x00,
    0x45,
    0x00,
    0x00,
    0x28,
    0x12,
    0x34,
    0x40,
    0x00,
    0x40,
    0x06,
    0x00,
    0x00,
    0xc0,
    0x00,
    0x02,
    0x01,
    0xc6,
    0x33,
    0x64,
    0x02,
    0xc9,
    0x3b,
    0x01,
    0xbb,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xfa,
    0xf0,
    0x00,
    0x00,
    0x00,
    0x00,
};

static int pin_first_allowed_cpu(void) {
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed)) {
        return -1;
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &allowed)) {
            cpu_set_t selected;
            CPU_ZERO(&selected);
            CPU_SET(cpu, &selected);
            return sched_setaffinity(0, sizeof(selected), &selected) ? -1 : cpu;
        }
    }
    errno = ENODEV;
    return -1;
}

static int read_percpu_exchange(struct bpf_map* map, unsigned int cpu, struct lua_exchange* result) {
    size_t value_size = bpf_map__value_size(map);
    size_t stride = (value_size + 7u) & ~(size_t)7u;
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count < 1 || cpu >= (unsigned int)cpu_count || value_size != sizeof(*result)) {
        return -1;
    }
    void* values = malloc(stride * (size_t)cpu_count);
    unsigned int key = 0;
    int error = !values ? -1 : bpf_map_lookup_elem(bpf_map__fd(map), &key, values);
    if (!error) {
        memcpy(result, (char*)values + cpu * stride, sizeof(*result));
    }
    free(values);
    return error;
}

static int compare_unsigned(const void* left, const void* right) {
    unsigned int a = *(const unsigned int*)left;
    unsigned int b = *(const unsigned int*)right;
    return (a > b) - (a < b);
}

static int measure_packet(int program_fd, unsigned int repeat, unsigned int* duration, unsigned int* action) {
    unsigned char output[SAMPLE_PACKET_BYTES] = {0};
    struct bpf_test_run_opts options = {
        .sz = sizeof(options),
        .data_in = sample_packet,
        .data_size_in = sizeof(sample_packet),
        .data_out = output,
        .data_size_out = sizeof(output),
        .repeat = repeat,
    };
    if (bpf_prog_test_run_opts(program_fd, &options)) {
        return -1;
    }
    *duration = options.duration;
    *action = options.retval;
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: lua_xdp_benchmark POLICY [REPEATS]\n");
        return 2;
    }
    unsigned long parsed_repeat = argc == 3 ? strtoul(argv[2], NULL, 10) : 100;
    if (!parsed_repeat || parsed_repeat > 1000000) {
        fprintf(stderr, "repeat count must be in [1, 1000000]\n");
        return 2;
    }
    unsigned int repeat = (unsigned int)parsed_repeat;

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
            !strcmp(name, "lua_xdp_test") || !strcmp(name, "lua_xdp_baseline") || !strcmp(name, "lua_xdp_initialize") ||
                !strcmp(name, "lua_xdp_initialize_drain") || !strcmp(name, "bpf_capsule_init")
        );
    }
    if (lua_xdp_configure(object) || capsule_test_load_skeleton(skeleton->skeleton) || bpf_capsule_finish_initialization(skeleton->obj) ||
        lua_xdp_load_script(object, control, argv[1])) {
        fprintf(stderr, "cannot load or initialize Lua XDP benchmark\n");
        lua_xdp__destroy(skeleton);
        return 1;
    }

    int cpu = pin_first_allowed_cpu();
    if (cpu < 0) {
        fprintf(stderr, "cannot pin Lua XDP benchmark thread\n");
        lua_xdp__destroy(skeleton);
        return 1;
    }

    struct bpf_program* policy = bpf_object__find_program_by_name(object, "lua_xdp_test");
    struct bpf_program* baseline = bpf_object__find_program_by_name(object, "lua_xdp_baseline");
    struct bpf_map* exchange_map = bpf_object__find_map_by_name(object, "lua_exchange_by_cpu");
    if (!policy || !baseline || !exchange_map) {
        fprintf(stderr, "Lua XDP benchmark programs are missing\n");
        lua_xdp__destroy(skeleton);
        return 1;
    }

    unsigned int cold;
    unsigned int warm;
    unsigned int action;
    if (measure_packet(bpf_program__fd(policy), 1, &cold, &action) || action != XDP_PASS || measure_packet(bpf_program__fd(policy), 1, &warm, &action) ||
        action != XDP_PASS) {
        fprintf(stderr, "Lua XDP benchmark warm-up failed\n");
        lua_xdp__destroy(skeleton);
        return 1;
    }

    enum { SAMPLE_COUNT = 21 };
    unsigned int policy_samples[SAMPLE_COUNT];
    unsigned int baseline_samples[SAMPLE_COUNT];
    unsigned int baseline_repeat = repeat < 10000 ? 10000 : repeat;
    for (unsigned int sample = 0; sample < SAMPLE_COUNT; ++sample) {
        if (measure_packet(bpf_program__fd(policy), repeat, &policy_samples[sample], &action) || action != XDP_PASS ||
            measure_packet(bpf_program__fd(baseline), baseline_repeat, &baseline_samples[sample], &action) || action != XDP_PASS) {
            fprintf(stderr, "Lua XDP benchmark sample failed\n");
            lua_xdp__destroy(skeleton);
            return 1;
        }
    }
    qsort(policy_samples, SAMPLE_COUNT, sizeof(*policy_samples), compare_unsigned);
    qsort(baseline_samples, SAMPLE_COUNT, sizeof(*baseline_samples), compare_unsigned);

    struct lua_exchange exchange;
    if (read_percpu_exchange(exchange_map, (unsigned int)cpu, &exchange) || exchange.test.value.state_initializations != 1) {
        fprintf(stderr, "Lua state was not reused: initializations=%llu\n", exchange.test.value.state_initializations);
        lua_xdp__destroy(skeleton);
        return 1;
    }

    unsigned int policy_median = policy_samples[SAMPLE_COUNT / 2];
    unsigned int policy_p95 = policy_samples[19];
    unsigned int baseline_median = baseline_samples[SAMPLE_COUNT / 2];
    unsigned int net = policy_median > baseline_median ? policy_median - baseline_median : 0;
    printf("Lua XDP packet benchmark (%u repeats/sample, %d samples)\n", repeat, SAMPLE_COUNT);
    printf("first policy after initialization: %.3f ms\n", cold / 1e6);
    printf("steady policy: median %.3f ms, p95 %.3f ms\n", policy_median / 1e6, policy_p95 / 1e6);
    printf("matched XDP_PASS baseline: %.6f ms\n", baseline_median / 1e6);
    printf("net Lua inspection: %.3f ms, %.0f packets/s/core\n", net / 1e6, net ? 1e9 / net : 0.0);
    printf("Lua state initializations: %llu\n", exchange.test.value.state_initializations);
    lua_xdp__destroy(skeleton);
    return 0;
}
