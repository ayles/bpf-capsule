// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bpf_capsule_host.h"

#include "../../tests/support/capsule_test.h"
#include "workload.h"
#include "overhead_ctrl.h"

oh_u8 oh_input[OH_INPUT_BYTES];

struct loaded {
    const char* label;
    struct bpf_object* object;
    struct oh_control* control;
    uint8_t* input;
    int run_fd;
    int empty_fd;
    int capsule_empty_fd;
    uint32_t jited_bytes;
    uint64_t capsule_memory_bytes;
    double load_ms;
};

static unsigned int selected_fibers = 1;

static double elapsed_ns(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec);
}

static void* map_memory(struct bpf_object* object, const char* name) {
    size_t size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(object, name);
    void* memory = map ? bpf_map__initial_value(map, &size) : NULL;
    if (!memory) {
        fprintf(stderr, "missing mmapable global-data map %s\n", name);
        exit(1);
    }
    return memory;
}

static int program_fd(struct bpf_object* object, const char* name) {
    struct bpf_program* program = bpf_object__find_program_by_name(object, name);
    int fd = program ? bpf_program__fd(program) : -1;
    if (fd < 0) {
        fprintf(stderr, "missing program %s\n", name);
        exit(1);
    }
    return fd;
}

static struct loaded load_object(const char* label, const char* path) {
    struct timespec begin, end;
    struct loaded loaded = {.label = label};
    clock_gettime(CLOCK_MONOTONIC, &begin);
    loaded.object = bpf_object__open_file(path, NULL);
    int managed = loaded.object && bpf_object__find_map_by_name(loaded.object, ".rodata.bpfconfig");
    const struct bpf_capsule_config config = {
        .fiber_count = selected_fibers,
        .heap_bytes = 4ull << 20,
    };
    if (!loaded.object || (managed && bpf_capsule_configure(loaded.object, config))) {
        fprintf(stderr, "%s: cannot open/configure %s\n", label, path);
        exit(1);
    }
    if (managed) {
        for (unsigned int index = 0;; ++index) {
            struct bpf_map* region = __bpf_capsule_memory_region(loaded.object, index);
            if (!region) {
                break;
            }
            loaded.capsule_memory_bytes += (uint64_t)bpf_map__value_size(region) * bpf_map__max_entries(region);
        }
        struct bpf_map* overflow = bpf_object__find_map_by_name(loaded.object, "bpf_heap_array");
        if (overflow) {
            loaded.capsule_memory_bytes += (uint64_t)bpf_map__value_size(overflow) * bpf_map__max_entries(overflow);
        }
    }
    int load_error = managed ? capsule_test_load_object(loaded.object) || bpf_capsule_finish_initialization(loaded.object) : bpf_object__load(loaded.object);
    if (load_error) {
        fprintf(stderr, "%s: cannot open/load %s\n", label, path);
        exit(1);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    loaded.load_ms = elapsed_ns(begin, end) / 1e6;
    loaded.control = map_memory(loaded.object, ".data.ohctrl");
    loaded.input = map_memory(loaded.object, ".data.ohinput");
    loaded.run_fd = program_fd(loaded.object, "overhead_run");
    loaded.empty_fd = program_fd(loaded.object, "overhead_empty");
    loaded.capsule_empty_fd = program_fd(loaded.object, "overhead_capsule_empty");

    struct bpf_prog_info info = {};
    uint32_t size = sizeof(info);
    if (!bpf_obj_get_info_by_fd(loaded.run_fd, &info, &size)) {
        loaded.jited_bytes = info.jited_prog_len;
    }
    return loaded;
}

static void make_packets(uint8_t* input) {
    uint32_t random = 0x12345678;
    for (uint32_t packet = 0; packet < OH_PACKET_COUNT; packet++) {
        uint8_t* p = input + packet * OH_PACKET_BYTES;
        for (uint32_t i = 0; i < OH_PACKET_BYTES; i++) {
            random = random * 1664525u + 1013904223u;
            p[i] = (uint8_t)(random >> 24);
        }

        uint32_t ip = (packet % 5 == 0) ? 18 : 14;
        p[12] = (packet % 5 == 0) ? 0x81 : 0x08;
        p[13] = (packet % 5 == 0) ? 0x00 : 0x00;
        if (ip == 18) {
            p[14] = 0;
            p[15] = (uint8_t)packet;
            p[16] = 0x08;
            p[17] = 0x00;
        }
        uint32_t ihl = (packet % 7 == 0) ? 24 : 20;
        p[ip] = (uint8_t)(0x40 | (ihl / 4));
        p[ip + 1] = 0;
        uint32_t total = OH_PACKET_BYTES - ip;
        p[ip + 2] = (uint8_t)(total >> 8);
        p[ip + 3] = (uint8_t)total;
        p[ip + 6] = p[ip + 7] = 0;
        p[ip + 9] = (packet & 1) ? 6 : 17;
        p[ip + 12] = 10;
        p[ip + 13] = (uint8_t)(packet >> 8);
        p[ip + 14] = (uint8_t)packet;
        p[ip + 15] = 1;
        p[ip + 16] = 192;
        p[ip + 17] = 0;
        p[ip + 18] = 2;
        p[ip + 19] = (uint8_t)(1 + packet);

        uint32_t l4 = ip + ihl;
        uint32_t sport = 10000 + packet;
        uint32_t ports[] = {53, 80, 443, 8443, 9000};
        uint32_t dport = ports[packet % 5];
        p[l4] = (uint8_t)(sport >> 8);
        p[l4 + 1] = (uint8_t)sport;
        p[l4 + 2] = (uint8_t)(dport >> 8);
        p[l4 + 3] = (uint8_t)dport;
        if (p[ip + 9] == 6) {
            p[l4 + 12] = 7u << 4; // 28-byte TCP header
            p[l4 + 13] = 0x18;
            p[l4 + 20] = 1;
            p[l4 + 21] = 2;
            p[l4 + 22] = 4;
            p[l4 + 23] = 5;
            p[l4 + 24] = 0xb4;
            p[l4 + 25] = 3;
            p[l4 + 26] = 3;
            p[l4 + 27] = 7;
        }
    }
}

static void run_once(int fd) {
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    if (capsule_test_run(fd, &options)) {
        fprintf(stderr, "BPF_PROG_TEST_RUN fd=%d: %s\n", fd, strerror(errno));
        exit(1);
    }
}

static double run_wall_ns(int fd, int repeat) {
    double best = 1e100;
    for (int trial = 0; trial < 5; trial++) {
        struct timespec begin, end;
        clock_gettime(CLOCK_MONOTONIC, &begin);
        for (int i = 0; i < repeat; i++) {
            run_once(fd);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double average = elapsed_ns(begin, end) / repeat;
        if (average < best) {
            best = average;
        }
    }
    return best;
}

static int correct(const struct oh_control* got, const struct oh_result* want) {
    return got->digest == want->digest && got->accepted == want->accepted && got->parsed == want->parsed && got->capsule.status == CAPSULE_OK;
}

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: %s DIRECT.o TRANSFORMED.o [PORTABLE.o]\n", argv[0]);
        return 1;
    }

    struct oh_result reference;
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    if (online > 0) {
        selected_fibers = (unsigned int)online;
    }
    if (selected_fibers > OH_COMPARISON_MAX_FIBERS) {
        selected_fibers = OH_COMPARISON_MAX_FIBERS;
    }
    make_packets(oh_input);
    oh_workload(&reference);

    struct loaded direct = load_object("direct", argv[1]);
    struct loaded transformed = load_object(argc == 4 ? "exact" : "transformed", argv[2]);
    struct loaded portable = {};
    if (argc == 4) {
        portable = load_object("portable", argv[3]);
    }
    memcpy(direct.input, oh_input, sizeof(oh_input));
    memcpy(transformed.input, oh_input, sizeof(oh_input));
    if (argc == 4) {
        memcpy(portable.input, oh_input, sizeof(oh_input));
    }

    run_once(direct.run_fd);
    run_once(transformed.run_fd);
    if (argc == 4) {
        run_once(portable.run_fd);
    }
    if (!correct(direct.control, &reference) || !correct(transformed.control, &reference) || (argc == 4 && !correct(portable.control, &reference))) {
        fprintf(
            stderr,
            "mismatch: native=%llx/%u/%u direct=%llx/%u/%u "
            "transformed=%llx/%u/%u status=%u code=%lld\n",
            reference.digest, reference.accepted, reference.parsed, direct.control->digest, direct.control->accepted, direct.control->parsed,
            transformed.control->digest, transformed.control->accepted, transformed.control->parsed, transformed.control->capsule.status,
            (long long)transformed.control->capsule.code
        );
        return 1;
    }

    struct timespec begin, end;
    struct oh_result native_result;
    volatile uint64_t sink = 0;
    const int native_repeats = 20000;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    for (int i = 0; i < native_repeats; i++) {
        __asm__ volatile("" : : "r"(oh_input) : "memory");
        oh_workload(&native_result);
        sink ^= native_result.digest;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double native_ns = elapsed_ns(begin, end) / native_repeats;

    const int bpf_repeats = 2000;
    double direct_empty = run_wall_ns(direct.empty_fd, bpf_repeats);
    double direct_ns = run_wall_ns(direct.run_fd, bpf_repeats);
    double transformed_empty = run_wall_ns(transformed.empty_fd, bpf_repeats);
    double transformed_capsule_empty = run_wall_ns(transformed.capsule_empty_fd, bpf_repeats);
    double transformed_ns = run_wall_ns(transformed.run_fd, bpf_repeats);
    double direct_net = direct_ns > direct_empty ? direct_ns - direct_empty : direct_ns;
    double transformed_net = transformed_ns > transformed_empty ? transformed_ns - transformed_empty : transformed_ns;
    double portable_empty = 0;
    double portable_capsule_empty = 0;
    double portable_ns = 0;
    double portable_net = 0;
    if (argc == 4) {
        portable_empty = run_wall_ns(portable.empty_fd, bpf_repeats);
        portable_capsule_empty = run_wall_ns(portable.capsule_empty_fd, bpf_repeats);
        portable_ns = run_wall_ns(portable.run_fd, bpf_repeats);
        portable_net = portable_ns > portable_empty ? portable_ns - portable_empty : portable_ns;
    }

    printf("OVERHEAD-PASS digest=%016llx accepted=%u packets=%u sink=%llx\n", reference.digest, reference.accepted, reference.parsed, sink);
    printf("native:      %.0f ns\n", native_ns);
    printf("direct BPF:  %.0f ns raw, %.0f ns empty, %.0f ns net; %.2fx native\n", direct_ns, direct_empty, direct_net, direct_net / native_ns);
    printf(
        "transformed: %.0f ns raw, %.0f ns empty, %.0f ns net; %.2fx native, %.2fx direct\n", transformed_ns, transformed_empty, transformed_net,
        transformed_net / native_ns, transformed_net / direct_net
    );
    printf(
        "capsule call: %.0f ns raw, %.0f ns over native empty\n", transformed_capsule_empty,
        transformed_capsule_empty > transformed_empty ? transformed_capsule_empty - transformed_empty : transformed_capsule_empty
    );
    printf(
        "load/JIT: direct %.1f ms (%u JIT bytes), transformed %.1f ms (%u JIT bytes)\n", direct.load_ms, direct.jited_bytes, transformed.load_ms,
        transformed.jited_bytes
    );

    if (argc == 4) {
        double ratio = portable_net / transformed_net;
        printf(
            "fiber cap: lower(max=64,count=%u)=%.0f ns portable(max=512,count=%u)=%.0f ns ratio=%.3fx\n", selected_fibers, transformed_net, selected_fibers,
            portable_net, ratio
        );
        printf(
            "fiber-cap load/JIT: lower(max=64) %.1f ms (%u bytes), portable(max=512) %.1f ms (%u bytes)\n", transformed.load_ms, transformed.jited_bytes,
            portable.load_ms, portable.jited_bytes
        );
        printf(
            "fiber-cap capsule call: lower(max=64) %.0f ns, portable(max=512) %.0f ns, ratio %.3fx\n", transformed_capsule_empty, portable_capsule_empty,
            portable_capsule_empty / transformed_capsule_empty
        );
        printf(
            "fiber-cap backing: lower(max=64) %.1f MiB, portable(max=512) %.1f MiB\n", transformed.capsule_memory_bytes / (1024.0 * 1024.0),
            portable.capsule_memory_bytes / (1024.0 * 1024.0)
        );
    }

    bpf_object__close(direct.object);
    bpf_object__close(transformed.object);
    if (portable.object) {
        bpf_object__close(portable.object);
    }
    return 0;
}
