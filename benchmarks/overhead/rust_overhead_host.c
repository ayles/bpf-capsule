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
#include "overhead_ctrl.h"

#define PACKET_COUNT 16u
#define PACKET_BYTES 128u
#define INPUT_BYTES (PACKET_COUNT * PACKET_BYTES)

unsigned char rust_oh_input[INPUT_BYTES];
extern uint64_t rust_oh_workload(void);
void rust_oh_abort(void) {
    abort();
}
void rust_eh_personality(void) {
}

struct loaded {
    struct bpf_object* object;
    struct rust_oh_control* control;
    uint8_t* input;
    int run_fd;
    int empty_fd;
    uint32_t jited_bytes;
    double load_ms;
};

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
    struct loaded loaded = {};
    clock_gettime(CLOCK_MONOTONIC, &begin);
    loaded.object = bpf_object__open_file(path, NULL);
    int managed = loaded.object && bpf_object__find_map_by_name(loaded.object, ".rodata.bpfconfig");
    const struct bpf_capsule_config config = {
        .fiber_count = 1,
        .heap_bytes = 4ull << 20,
    };
    if (!loaded.object || (managed && bpf_capsule_configure(loaded.object, config))) {
        fprintf(stderr, "%s: cannot open/configure %s\n", label, path);
        exit(1);
    }
    int load_error = managed ? capsule_test_load_object(loaded.object) || bpf_capsule_finish_initialization(loaded.object) : bpf_object__load(loaded.object);
    if (load_error) {
        fprintf(stderr, "%s: cannot open/load %s\n", label, path);
        exit(1);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    loaded.load_ms = elapsed_ns(begin, end) / 1e6;
    loaded.control = map_memory(loaded.object, ".data.rohctrl");
    loaded.input = map_memory(loaded.object, ".data.rohinput");
    loaded.run_fd = program_fd(loaded.object, "rust_overhead_run");
    loaded.empty_fd = program_fd(loaded.object, "rust_overhead_empty");

    struct bpf_prog_info info = {};
    uint32_t size = sizeof(info);
    if (!bpf_obj_get_info_by_fd(loaded.run_fd, &info, &size)) {
        loaded.jited_bytes = info.jited_prog_len;
    }
    return loaded;
}

static void make_packets(uint8_t* input) {
    uint32_t random = 0x12345678;
    for (uint32_t packet = 0; packet < PACKET_COUNT; packet++) {
        uint8_t* p = input + packet * PACKET_BYTES;
        for (uint32_t i = 0; i < PACKET_BYTES; i++) {
            random = random * 1664525u + 1013904223u;
            p[i] = (uint8_t)(random >> 24);
        }

        uint32_t ip = packet % 5 == 0 ? 18 : 14;
        p[12] = packet % 5 == 0 ? 0x81 : 0x08;
        p[13] = 0;
        if (ip == 18) {
            p[14] = 0;
            p[15] = (uint8_t)packet;
            p[16] = 0x08;
            p[17] = 0;
        }
        uint32_t ihl = packet % 7 == 0 ? 24 : 20;
        p[ip] = (uint8_t)(0x40 | ihl / 4);
        p[ip + 1] = 0;
        uint32_t total = PACKET_BYTES - ip;
        p[ip + 2] = (uint8_t)(total >> 8);
        p[ip + 3] = (uint8_t)total;
        p[ip + 6] = p[ip + 7] = 0;
        p[ip + 9] = packet & 1 ? 6 : 17;
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
        static const uint32_t ports[] = {53, 80, 443, 8443, 9000};
        uint32_t dport = ports[packet % 5];
        p[l4] = (uint8_t)(sport >> 8);
        p[l4 + 1] = (uint8_t)sport;
        p[l4 + 2] = (uint8_t)(dport >> 8);
        p[l4 + 3] = (uint8_t)dport;
        if (p[ip + 9] == 6) {
            p[l4 + 12] = 7u << 4;
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

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s DIRECT.o TRANSFORMED.o\n", argv[0]);
        return 1;
    }

    make_packets(rust_oh_input);
    uint64_t reference = rust_oh_workload();
    struct loaded direct = load_object("direct", argv[1]);
    struct loaded transformed = load_object("transformed", argv[2]);
    memcpy(direct.input, rust_oh_input, sizeof(rust_oh_input));
    memcpy(transformed.input, rust_oh_input, sizeof(rust_oh_input));

    run_once(direct.run_fd);
    run_once(transformed.run_fd);
    if (direct.control->digest != reference || direct.control->capsule.status != CAPSULE_OK || transformed.control->digest != reference ||
        transformed.control->capsule.status != CAPSULE_OK) {
        fprintf(
            stderr,
            "mismatch: native=%016llx direct=%016llx/%u/%lld "
            "transformed=%016llx/%u/%lld\n",
            (uint64_t)reference, (uint64_t)direct.control->digest, direct.control->capsule.status, (long long)direct.control->capsule.code,
            (uint64_t)transformed.control->digest, transformed.control->capsule.status, (long long)transformed.control->capsule.code
        );
        return 1;
    }

    const int native_repeats = 20000;
    volatile uint64_t sink = 0;
    struct timespec begin, end;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    for (int i = 0; i < native_repeats; i++) {
        __asm__ volatile("" : : "r"(rust_oh_input) : "memory");
        sink ^= rust_oh_workload();
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double native_ns = elapsed_ns(begin, end) / native_repeats;

    const int bpf_repeats = 2000;
    double direct_empty = run_wall_ns(direct.empty_fd, bpf_repeats);
    double direct_ns = run_wall_ns(direct.run_fd, bpf_repeats);
    double transformed_empty = run_wall_ns(transformed.empty_fd, bpf_repeats);
    double transformed_ns = run_wall_ns(transformed.run_fd, bpf_repeats);
    double direct_net = direct_ns > direct_empty ? direct_ns - direct_empty : direct_ns;
    double transformed_net = transformed_ns > transformed_empty ? transformed_ns - transformed_empty : transformed_ns;

    printf("RUST-OVERHEAD-PASS digest=%016llx sink=%llx\n", (uint64_t)reference, (uint64_t)sink);
    printf("native Rust:      %.0f ns\n", native_ns);
    printf("direct Rust BPF:  %.0f ns raw, %.0f ns empty, %.0f ns net; %.2fx native\n", direct_ns, direct_empty, direct_net, direct_net / native_ns);
    printf(
        "transformed Rust: %.0f ns raw, %.0f ns empty, %.0f ns net; "
        "%.2fx native, %.2fx direct\n",
        transformed_ns, transformed_empty, transformed_net, transformed_net / native_ns, transformed_net / direct_net
    );
    printf(
        "load/JIT: direct %.1f ms (%u JIT bytes), transformed %.1f ms "
        "(%u JIT bytes)\n",
        direct.load_ms, direct.jited_bytes, transformed.load_ms, transformed.jited_bytes
    );

    bpf_object__close(direct.object);
    bpf_object__close(transformed.object);
    return 0;
}
