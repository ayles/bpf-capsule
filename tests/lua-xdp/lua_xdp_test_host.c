// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
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

static int pin_current_thread(unsigned int cpu) {
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    return pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
}

static int first_allowed_cpu(void) {
    cpu_set_t affinity;
    if (sched_getaffinity(0, sizeof(affinity), &affinity)) {
        return -1;
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &affinity)) {
            return cpu;
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
        errno = E2BIG;
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

static int run_packet(
    int program_fd, const void* packet, size_t length, unsigned int expected_action, unsigned int cpu, struct lua_xdp_test_result* result,
    struct bpf_map* result_map
) {
    unsigned char output[LUA_XDP_PACKET_CAPACITY + 1] = {0};
    struct bpf_test_run_opts options = {
        .sz = sizeof(options),
        .data_in = packet,
        .data_size_in = length,
        .data_out = output,
        .data_size_out = sizeof(output),
        .repeat = 1,
    };
    int affinity_error = pin_current_thread(cpu);
    if (affinity_error) {
        errno = affinity_error;
        perror("pin XDP test thread");
        return -1;
    }
    struct lua_exchange exchange;
    if (bpf_prog_test_run_opts(program_fd, &options) || read_percpu_exchange(result_map, cpu, &exchange)) {
        perror("XDP test run");
        return -1;
    }
    *result = exchange.test;
    fprintf(
        stderr,
        "xdp action=%u expected=%u decision=%llu "
        "capsule-status=%u capsule-code=%lld continuation=%llu "
        "input=%zu output=%u duration=%uns state-inits=%llu\n",
        options.retval, expected_action, result->value.decision, result->capsule.status, (long long)result->capsule.code,
        (unsigned long long)result->capsule.continuation, length, options.data_size_out, options.duration, result->value.state_initializations
    );
    return options.retval == expected_action && result->capsule.status == CAPSULE_OK && !result->capsule.code ? 0 : -1;
}

static int run_observer_packet(
    int program_fd, const void* packet, size_t length, const char* expected, unsigned int cpu, struct lua_xdp_test_result* result, struct bpf_map* result_map,
    struct bpf_map* output_map
) {
    if (run_packet(program_fd, packet, length, XDP_PASS, cpu, result, result_map)) {
        return -1;
    }

    struct lua_exchange exchange;
    if (read_percpu_exchange(output_map, cpu, &exchange)) {
        return -1;
    }
    fprintf(stderr, "test audit copy: %s", exchange.output.bytes);
    return result->value.decision != 1 || strcmp(exchange.output.bytes, expected) ? -1 : 0;
}

static int load_text_script(struct bpf_object* object, volatile struct lua_xdp_ctrl* control, const char* source) {
    char path[] = "/tmp/bpf-capsule-lua-xdp.XXXXXX";
    int descriptor = mkstemp(path);
    if (descriptor < 0) {
        return -1;
    }
    size_t remaining = strlen(source);
    const char* cursor = source;
    while (remaining) {
        ssize_t written = write(descriptor, cursor, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            int saved_errno = errno;
            close(descriptor);
            unlink(path);
            errno = saved_errno ? saved_errno : EIO;
            return -1;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    if (close(descriptor)) {
        int saved_errno = errno;
        unlink(path);
        errno = saved_errno;
        return -1;
    }
    int error = lua_xdp_load_script(object, control, path);
    int saved_errno = errno;
    unlink(path);
    errno = saved_errno;
    return error;
}

static int run_error_packet(int program_fd, const void* packet, size_t length, unsigned int cpu, const char* expected_error, struct bpf_map* result_map) {
    unsigned char output[LUA_XDP_PACKET_CAPACITY + 1] = {0};
    struct bpf_test_run_opts options = {
        .sz = sizeof(options),
        .data_in = packet,
        .data_size_in = length,
        .data_out = output,
        .data_size_out = sizeof(output),
        .repeat = 1,
    };
    int affinity_error = pin_current_thread(cpu);
    if (affinity_error) {
        errno = affinity_error;
        return -1;
    }
    struct lua_exchange exchange;
    if (bpf_prog_test_run_opts(program_fd, &options) || read_percpu_exchange(result_map, cpu, &exchange)) {
        return -1;
    }
    size_t error_size = exchange.error_size < LUA_XDP_OUTPUT_CAPACITY ? (size_t)exchange.error_size : LUA_XDP_OUTPUT_CAPACITY;
    // A Lua script error is the adapter's own failure, not the framework's:
    // by convention the Lua adapter exits 1 after recording the message, so
    // the caller observes CAPSULE_EXITED with the guest exit status 1.
    int pass = options.retval == XDP_ABORTED && exchange.test.capsule.status == CAPSULE_EXITED && exchange.test.capsule.code == 1 &&
        memmem(exchange.error.bytes, error_size, expected_error, strlen(expected_error));
    fprintf(
        stderr, "xdp error: action=%u capsule-status=%s capsule-code=%s (%lld) text=%.*s\n", options.retval,
        bpf_capsule_status_string(exchange.test.capsule.status), bpf_capsule_error_string(exchange.test.capsule.code), (long long)exchange.test.capsule.code,
        (int)error_size, exchange.error.bytes
    );
    return pass ? 0 : -1;
}

struct concurrent_start {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int started;
};

struct concurrent_worker {
    struct concurrent_start* start;
    int program_fd;
    unsigned int cpu;
    unsigned int expected_action;
    unsigned char packet[SAMPLE_PACKET_BYTES];
    int error;
};

static void* run_concurrent_worker(void* opaque) {
    struct concurrent_worker* worker = opaque;
    if (pin_current_thread(worker->cpu)) {
        worker->error = 1;
        return NULL;
    }
    pthread_mutex_lock(&worker->start->mutex);
    while (!worker->start->started) {
        pthread_cond_wait(&worker->start->condition, &worker->start->mutex);
    }
    pthread_mutex_unlock(&worker->start->mutex);

    enum { ITERATIONS = 32 };
    for (unsigned int iteration = 0; iteration < ITERATIONS; ++iteration) {
        unsigned char output[SAMPLE_PACKET_BYTES] = {0};
        struct bpf_test_run_opts options = {
            .sz = sizeof(options),
            .data_in = worker->packet,
            .data_size_in = sizeof(worker->packet),
            .data_out = output,
            .data_size_out = sizeof(output),
            .repeat = 1,
        };
        if (bpf_prog_test_run_opts(worker->program_fd, &options) || options.retval != worker->expected_action) {
            worker->error = 1;
        }
    }
    return NULL;
}

static int run_concurrent_packets(int program_fd, const cpu_set_t* allowed) {
    unsigned int cpus[8];
    unsigned int worker_count = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE && worker_count < 8; ++cpu) {
        if (CPU_ISSET(cpu, allowed)) {
            cpus[worker_count++] = (unsigned int)cpu;
        }
    }
    if (worker_count < 2) {
        fprintf(stderr, "Lua XDP concurrency: skipped on a single-CPU host\n");
        return 0;
    }

    struct concurrent_start start = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .condition = PTHREAD_COND_INITIALIZER,
    };
    pthread_t threads[8];
    struct concurrent_worker workers[8];
    unsigned int created = 0;
    for (; created < worker_count; ++created) {
        workers[created] = (struct concurrent_worker){
            .start = &start,
            .program_fd = program_fd,
            .cpu = cpus[created],
            .expected_action = created & 1u ? XDP_DROP : XDP_PASS,
        };
        memcpy(workers[created].packet, sample_packet, sizeof(sample_packet));
        if (workers[created].expected_action == XDP_DROP) {
            workers[created].packet[36] = 0;
            workers[created].packet[37] = 0x50;
        }
        int error = pthread_create(&threads[created], NULL, run_concurrent_worker, &workers[created]);
        if (error) {
            fprintf(stderr, "cannot create Lua XDP worker: %s\n", strerror(error));
            break;
        }
    }

    pthread_mutex_lock(&start.mutex);
    start.started = 1;
    pthread_cond_broadcast(&start.condition);
    pthread_mutex_unlock(&start.mutex);

    int failed = created != worker_count;
    for (unsigned int worker = 0; worker < created; ++worker) {
        if (pthread_join(threads[worker], NULL) || workers[worker].error) {
            failed = 1;
        }
    }
    pthread_cond_destroy(&start.condition);
    pthread_mutex_destroy(&start.mutex);
    fprintf(stderr, "Lua XDP concurrency: %u CPUs x 32 packets %s\n", created, failed ? "FAIL" : "PASS");
    return failed ? -1 : 0;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: lua_xdp_test POLICY OBSERVER\n");
        return 2;
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
            !strcmp(name, "lua_xdp_test") || !strcmp(name, "lua_xdp_initialize") || !strcmp(name, "lua_xdp_initialize_drain") ||
                !strcmp(name, "bpf_capsule_init")
        );
    }
    if (lua_xdp_configure(object) || capsule_test_load_skeleton(skeleton->skeleton) || bpf_capsule_finish_initialization(skeleton->obj) ||
        lua_xdp_load_script(object, control, argv[1])) {
        fprintf(stderr, "cannot load or initialize Lua XDP test\n");
        lua_xdp__destroy(skeleton);
        return 1;
    }

    program = bpf_object__find_program_by_name(object, "lua_xdp_test");
    struct bpf_map* exchange_map = bpf_object__find_map_by_name(object, "lua_exchange_by_cpu");
    if (!program || !exchange_map) {
        fprintf(stderr, "Lua XDP test program is missing\n");
        lua_xdp__destroy(skeleton);
        return 1;
    }

    unsigned char drop_packet[SAMPLE_PACKET_BYTES];
    memcpy(drop_packet, sample_packet, sizeof(drop_packet));
    drop_packet[36] = 0;
    drop_packet[37] = 0x50;

    cpu_set_t allowed;
    int selected_cpu = first_allowed_cpu();
    if (sched_getaffinity(0, sizeof(allowed), &allowed) || selected_cpu < 0) {
        fprintf(stderr, "cannot select an allowed CPU for XDP test-run\n");
        lua_xdp__destroy(skeleton);
        return 1;
    }
    unsigned int cpu = (unsigned int)selected_cpu;
    struct lua_xdp_test_result result;
    int program_fd = bpf_program__fd(program);
    int pass = !run_packet(program_fd, sample_packet, sizeof(sample_packet), XDP_PASS, cpu, &result, exchange_map) && result.value.decision == 1 &&
        result.value.state_initializations == 1 && !run_packet(program_fd, drop_packet, sizeof(drop_packet), XDP_DROP, cpu, &result, exchange_map) &&
        result.value.decision == 0 && result.value.state_initializations == 1 &&
        !run_packet(program_fd, sample_packet, 32, XDP_DROP, cpu, &result, exchange_map) && result.value.decision == 0 &&
        result.value.state_initializations == 1;

    // run_packet pins this thread; restore the complete mask for concurrency.
    sched_setaffinity(0, sizeof(allowed), &allowed);
    if (pass && run_concurrent_packets(program_fd, &allowed)) {
        pass = 0;
    }

    if (pass && lua_xdp_load_script(object, control, argv[2])) {
        pass = 0;
    }
    if (pass) {
        unsigned char udp_packet[42];
        memcpy(udp_packet, sample_packet, sizeof(udp_packet));
        udp_packet[16] = 0;
        udp_packet[17] = 0x1c;
        udp_packet[23] = 17;
        udp_packet[34] = 0x14;
        udp_packet[35] = 0xe9;
        udp_packet[36] = 0;
        udp_packet[37] = 0x35;

        unsigned char ip_packet[34];
        memcpy(ip_packet, sample_packet, sizeof(ip_packet));
        ip_packet[16] = 0;
        ip_packet[17] = 0x14;
        ip_packet[23] = 1;

        unsigned char prefix_packet[LUA_XDP_PACKET_CAPACITY + 1] = {0};
        memcpy(prefix_packet, sample_packet, 12);
        prefix_packet[12] = 0x86;
        prefix_packet[13] = 0xdd;

        pass = !run_observer_packet(
                   program_fd, sample_packet, sizeof(sample_packet), "TCP 192.0.2.1:51515 > 198.51.100.2:443\n", cpu, &result, exchange_map, exchange_map
               ) &&
            !run_observer_packet(
                program_fd, udp_packet, sizeof(udp_packet), "UDP 192.0.2.1:5353 > 198.51.100.2:53\n", cpu, &result, exchange_map, exchange_map
            ) &&
            !run_observer_packet(program_fd, ip_packet, sizeof(ip_packet), "IP 192.0.2.1 > 198.51.100.2 proto=1\n", cpu, &result, exchange_map, exchange_map) &&
            !run_observer_packet(program_fd, sample_packet, 14, "TRUNC ipv4 len=14\n", cpu, &result, exchange_map, exchange_map) &&
            !run_observer_packet(program_fd, prefix_packet, sizeof(prefix_packet), "ETH type=0x86dd len=2048\n", cpu, &result, exchange_map, exchange_map) &&
            result.value.state_initializations == 2;
    }

    if (pass && load_text_script(object, control, "error(\"expected Lua XDP error\")\n")) {
        pass = 0;
    }
    if (pass &&
        (run_error_packet(program_fd, sample_packet, sizeof(sample_packet), cpu, "expected Lua XDP error", exchange_map) ||
            run_error_packet(program_fd, sample_packet, sizeof(sample_packet), cpu, "Lua state is unavailable; reload the script", exchange_map))) {
        pass = 0;
    }
    if (pass && !load_text_script(object, control, "local =\n")) {
        fprintf(stderr, "invalid Lua XDP reload unexpectedly succeeded\n");
        pass = 0;
    }
    if (pass && run_error_packet(program_fd, sample_packet, sizeof(sample_packet), cpu, "Lua state is unavailable; reload the script", exchange_map)) {
        pass = 0;
    }
    if (pass && lua_xdp_load_script(object, control, argv[2])) {
        pass = 0;
    }
    if (pass &&
        (run_observer_packet(
             program_fd, sample_packet, sizeof(sample_packet), "TCP 192.0.2.1:51515 > 198.51.100.2:443\n", cpu, &result, exchange_map, exchange_map
         ) ||
            result.value.state_initializations != 4)) {
        pass = 0;
    }

    printf(pass ? "LUA-XDP-PASS\n" : "LUA-XDP-FAIL\n");
    lua_xdp__destroy(skeleton);
    return pass ? 0 : 1;
}
