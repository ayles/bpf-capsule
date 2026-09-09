// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run one SQL script against an in-memory database in the kernel, or the same
// runner natively with --native, reporting the execution time of both.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "sqlite_runner.h"
#include "sqlite.skel.h"

enum {
    SQLITE_OUTPUT_BYTES = 1u << 20,
    SQLITE_ERROR_BYTES = 64u << 10,
    SQLITE_HEAP_BYTES = 8u << 20,
};

// The number of continuations a run may use; unlimited unless the environment
// caps it, so a regression in the drive budget can be turned into a failure.
// The kernel's own per-program counters, summed over the object: a wall clock
// around the syscall would also count the syscall path and this loop, which
// the native run does not pay. Run-time statistics must be enabled first.
static int kernel_run_time(struct bpf_object* object, uint64_t* nanoseconds, uint64_t* invocations) {
    uint64_t total_nanoseconds = 0;
    uint64_t total_invocations = 0;
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        int fd = bpf_program__fd(program);
        if (fd < 0) {
            continue;
        }
        struct bpf_prog_info info = {0};
        unsigned int length = sizeof(info);
        if (bpf_prog_get_info_by_fd(fd, &info, &length)) {
            return -1;
        }
        total_nanoseconds += info.run_time_ns;
        total_invocations += info.run_cnt;
    }
    *nanoseconds = total_nanoseconds;
    *invocations = total_invocations;
    return 0;
}

static int read_max_drains(unsigned long* result) {
    const char* text = getenv("BPF_CAPSULE_MAX_DRAINS");
    *result = ULONG_MAX;
    if (!text || !*text) {
        return 0;
    }
    char* end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (text[0] < '0' || text[0] > '9' || errno || !end || *end) {
        fprintf(stderr, "BPF_CAPSULE_MAX_DRAINS must be a non-negative integer\n");
        return -1;
    }
    *result = value;
    return 0;
}

// Reads a whole file, NUL-terminated: sqlite3_exec wants a terminated script.
static char* read_file(const char* path, size_t* size) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return NULL;
    }
    size_t capacity = 64u << 10;
    size_t used = 0;
    char* data = malloc(capacity + 1);
    while (data) {
        if (used == capacity) {
            capacity *= 2;
            char* grown = realloc(data, capacity + 1);
            if (!grown) {
                free(data);
                data = NULL;
                break;
            }
            data = grown;
        }
        size_t got = fread(data + used, 1, capacity - used, file);
        used += got;
        if (!got) {
            if (ferror(file)) {
                free(data);
                data = NULL;
            } else {
                data[used] = '\0';
                *size = used;
            }
            break;
        }
    }
    fclose(file);
    return data;
}

static double milliseconds_since(const struct timespec* start, clockid_t clock) {
    struct timespec now;
    clock_gettime(clock, &now);
    return (double)(now.tv_sec - start->tv_sec) * 1e3 + (double)(now.tv_nsec - start->tv_nsec) / 1e6;
}

// Report the result rows, or the SQLite error and exit status 1.
static int publish(const struct sqlite_buffer* output, const struct sqlite_buffer* error, int rc, const char* engine) {
    if (rc) {
        size_t error_size = error->size < error->capacity ? error->size : error->capacity;
        if (error_size) {
            fwrite(error->address, 1, error_size, stderr);
            fputc('\n', stderr);
        }
        fprintf(stderr, "SQLite error %d\n", rc);
        return 1;
    }
    if (output->size > output->capacity) {
        fprintf(stderr, "SQLite output requires %zu bytes; the %s buffer holds %zu\n", output->size, engine, output->capacity);
        return 1;
    }
    if (output->size) {
        fwrite(output->address, 1, output->size, stdout);
    }
    return 0;
}

static int run_native(char* script, size_t script_size) {
    struct sqlite_buffer script_buffer = {script, script_size + 1, script_size};
    struct sqlite_buffer output = {malloc(SQLITE_OUTPUT_BYTES), SQLITE_OUTPUT_BYTES, 0};
    struct sqlite_buffer error = {malloc(SQLITE_ERROR_BYTES), SQLITE_ERROR_BYTES, 0};
    if (!output.address || !error.address) {
        perror("allocate sqlite buffers");
        free(output.address);
        free(error.address);
        return 1;
    }
    struct timespec start;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    int rc = sqlite_runner_run(&script_buffer, &output, &error);
    double cpu_ms = milliseconds_since(&start, CLOCK_PROCESS_CPUTIME_ID);
    int result = publish(&output, &error, rc, "native");
    if (!rc) {
        fprintf(stderr, "native execution: %.3f ms\n", cpu_ms);
    }
    free(output.address);
    free(error.address);
    return result;
}

static int run_capsule(char* script, size_t script_size, unsigned long max_drains) {
    if (script_size >= UINT32_MAX) {
        fprintf(stderr, "the script is too large for Capsule memory\n");
        return 1;
    }
    int result = 1;
    int stats_fd = -1;
    struct sqlite* skeleton = sqlite__open();
    struct bpf_capsule capsule = {0};
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = (uint64_t)script_size + SQLITE_OUTPUT_BYTES + SQLITE_ERROR_BYTES + SQLITE_HEAP_BYTES,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "cannot configure/load Capsule SQLite: %s\n", strerror(errno));
        goto cleanup;
    }
    stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);

    volatile struct sqlite_bpf_ctrl* control = &skeleton->data_sctrl->sctrl;
    control->script.address = bpf_capsule_malloc(&capsule, script_size + 1);
    control->script.capacity = script_size + 1;
    control->script.size = script_size;
    control->output.address = bpf_capsule_malloc(&capsule, SQLITE_OUTPUT_BYTES);
    control->output.capacity = SQLITE_OUTPUT_BYTES;
    control->error.address = bpf_capsule_malloc(&capsule, SQLITE_ERROR_BYTES);
    control->error.capacity = SQLITE_ERROR_BYTES;
    if (!control->script.address || !control->output.address || !control->error.address) {
        perror("allocate sqlite buffers");
        goto cleanup;
    }
    memcpy(control->script.address, script, script_size + 1);

    int run_fd = bpf_program__fd(skeleton->progs.sqlite_run);
    int drain_fd = bpf_program__fd(skeleton->progs.sqlite_drain);
    if (run_fd < 0 || drain_fd < 0) {
        fprintf(stderr, "BPF object is missing a SQLite program\n");
        goto cleanup;
    }
    uint64_t kernel_before = 0, invocations_before = 0;
    int stats_failed = stats_fd < 0 || kernel_run_time(skeleton->obj, &kernel_before, &invocations_before);
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    if (bpf_prog_test_run_opts(run_fd, &options)) {
        perror("run");
        goto cleanup;
    }
    unsigned long drains = 0;
    while (control->capsule.status == CAPSULE_PENDING) {
        if (drains == max_drains) {
            fprintf(stderr, "computation is still pending after %lu drains; set BPF_CAPSULE_MAX_DRAINS to permit more\n", drains);
            goto cleanup;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            perror("drain");
            goto cleanup;
        }
        drains++;
    }
    uint64_t kernel_after = 0, invocations_after = 0;
    stats_failed = stats_failed || kernel_run_time(skeleton->obj, &kernel_after, &invocations_after);
    if (control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
        fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
        goto cleanup;
    }
    if (control->capsule.status != CAPSULE_OK && control->capsule.status != CAPSULE_EXITED) {
        fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        goto cleanup;
    }
    struct sqlite_buffer output = {control->output.address, control->output.capacity, control->output.size};
    struct sqlite_buffer error = {control->error.address, control->error.capacity, control->error.size};
    int rc = control->capsule.status == CAPSULE_EXITED ? (control->sqlite_rc ? control->sqlite_rc : 1) : 0;
    result = publish(&output, &error, rc, "Capsule");
    if (rc) {
        goto cleanup;
    }
    if (!stats_failed) {
        fprintf(stderr, "kernel execution: %.3f ms over %llu invocations\n", (double)(kernel_after - kernel_before) / 1e6,
            (unsigned long long)(invocations_after - invocations_before));
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);

cleanup:
    if (stats_fd >= 0) {
        close(stats_fd);
    }
    if (skeleton) {
        (void)bpf_capsule_release(&capsule);
        sqlite__destroy(skeleton);
    }
    return result;
}

int main(int argc, char** argv) {
    int native = argc >= 2 && !strcmp(argv[1], "--native");
    if (argc != 2 + native) {
        fprintf(stderr, "usage: sqlite [--native] SCRIPT.sql\n");
        return 2;
    }
    unsigned long max_drains = 0;
    if (read_max_drains(&max_drains)) {
        return 2;
    }
    const char* path = argv[1 + native];
    size_t script_size = 0;
    char* script = read_file(path, &script_size);
    if (!script) {
        fprintf(stderr, "cannot read %s: %s\n", path, strerror(errno));
        return 1;
    }
    int result = native ? run_native(script, script_size) : run_capsule(script, script_size, max_drains);
    free(script);
    return result;
}
