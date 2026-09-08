// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"
#include "python_ctrl.h"
#include "python.skel.h"

#define PYTHON_OUTPUT_CAPACITY (1u << 20)
#define PYTHON_HEAP_BYTES (128u << 20)

struct file_contents {
    unsigned char* data;
    size_t size;
};

static int read_file(const char* path, int terminate, struct file_contents* contents) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return -1;
    }
    if (fseek(file, 0, SEEK_END)) {
        goto error;
    }
    long end = ftell(file);
    if (end < 0 || (unsigned long)end > SIZE_MAX - (size_t)terminate) {
        errno = end < 0 ? errno : EOVERFLOW;
        goto error;
    }
    if (fseek(file, 0, SEEK_SET)) {
        goto error;
    }
    contents->size = (size_t)end;
    contents->data = malloc(contents->size + (size_t)terminate);
    if (!contents->data) {
        goto error;
    }
    if (fread(contents->data, 1, contents->size, file) != contents->size) {
        errno = ferror(file) && errno ? errno : EIO;
        free(contents->data);
        contents->data = NULL;
        goto error;
    }
    if (terminate) {
        contents->data[contents->size] = 0;
    }
    fclose(file);
    return 0;

error:
    {
        int saved_errno = errno;
        fclose(file);
        errno = saved_errno;
        return -1;
    }
}

static int stdlib_path(const char* argv0, char path[PATH_MAX]) {
    char executable[PATH_MAX];
    ssize_t size = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (size < 0) {
        if (strlen(argv0) >= sizeof(executable)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        strcpy(executable, argv0);
    } else {
        executable[size] = 0;
    }
    char* bin = strrchr(executable, '/');
    if (!bin) {
        errno = ENOENT;
        return -1;
    }
    *bin = 0;
    char* prefix = strrchr(executable, '/');
    if (!prefix) {
        errno = ENOENT;
        return -1;
    }
    *prefix = 0;
    int written = snprintf(path, PATH_MAX, "%s/share/bpf-capsule/python/stdlib.pack", executable);
    if (written < 0 || written >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int run_program(struct bpf_program* program) {
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    return bpf_prog_test_run_opts(bpf_program__fd(program), &options);
}

static int realtime_offset_ns(int64_t* result) {
    struct timespec realtime;
    struct timespec monotonic;
    if (clock_gettime(CLOCK_REALTIME, &realtime) || clock_gettime(CLOCK_MONOTONIC, &monotonic)) {
        return -1;
    }
    *result = ((int64_t)realtime.tv_sec - (int64_t)monotonic.tv_sec) * 1000000000ll + realtime.tv_nsec - monotonic.tv_nsec;
    return 0;
}

static int read_max_drains(unsigned long* result) {
    const char* text = getenv("BPF_CAPSULE_MAX_DRAINS");
    *result = 0;
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

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: python SCRIPT\n");
        return 2;
    }

    char library_path[PATH_MAX];
    struct file_contents script = {0};
    struct file_contents stdlib = {0};
    if (stdlib_path(argv[0], library_path) || read_file(argv[1], 1, &script) || read_file(library_path, 0, &stdlib)) {
        fprintf(stderr, "cannot read Python inputs: %s\n", strerror(errno));
        return 1;
    }
    if (stdlib.size > SIZE_MAX - script.size - 1 - PYTHON_OUTPUT_CAPACITY) {
        fprintf(stderr, "Python inputs are too large\n");
        free(stdlib.data);
        free(script.data);
        return 1;
    }
    size_t staging_bytes = stdlib.size + script.size + 1 + PYTHON_OUTPUT_CAPACITY;
    if (staging_bytes > UINT64_MAX - PYTHON_HEAP_BYTES) {
        fprintf(stderr, "Python heap is too large\n");
        free(stdlib.data);
        free(script.data);
        return 1;
    }

    int result = 1;
    struct python* skeleton = python__open();
    struct bpf_capsule capsule = {0};
    struct bpf_object* object = skeleton ? skeleton->obj : NULL;
    if (!object) {
        fprintf(stderr, "cannot open Python BPF object\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(&capsule, object, (struct bpf_capsule_config){.fiber_count = 1, .heap_bytes = (uint64_t)PYTHON_HEAP_BYTES + staging_bytes}) ||
        bpf_object__load_skeleton(skeleton->skeleton)) {
        fprintf(stderr, "cannot configure/load Python: %s\n", strerror(errno));
        goto cleanup;
    }
    if (bpf_capsule_attach_freplace(&capsule, skeleton->skeleton->data, skeleton->skeleton->data_sz) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "cannot attach/initialize Python: %s\n", strerror(errno));
        goto cleanup;
    }
    struct bpf_program* start = bpf_object__find_program_by_name(object, "python_start");
    struct bpf_program* drain = bpf_object__find_program_by_name(object, "python_drain");
    if (!start || !drain) {
        fprintf(stderr, "Python entry programs are missing\n");
        goto cleanup;
    }

    volatile struct python_ctrl* control = &skeleton->data_python->python_control;
    int64_t realtime_offset;
    if (realtime_offset_ns(&realtime_offset)) {
        fprintf(stderr, "cannot read host clocks: %s\n", strerror(errno));
        goto cleanup;
    }
    control->realtime_offset_ns = realtime_offset;
    uint32_t hash_seed;
    if (getentropy(&hash_seed, sizeof(hash_seed))) {
        fprintf(stderr, "cannot obtain Python hash seed: %s\n", strerror(errno));
        goto cleanup;
    }
    control->hash_seed = hash_seed;
    control->stdlib_image = bpf_capsule_malloc(&capsule, stdlib.size);
    control->stdlib_size = stdlib.size;
    control->script = bpf_capsule_malloc(&capsule, script.size + 1);
    control->output = bpf_capsule_malloc(&capsule, PYTHON_OUTPUT_CAPACITY);
    control->output_capacity = PYTHON_OUTPUT_CAPACITY;
    if (!control->stdlib_image || !control->script || !control->output) {
        fprintf(stderr, "cannot allocate Python inputs: %s\n", strerror(errno));
        goto cleanup;
    }
    memcpy((void*)control->stdlib_image, stdlib.data, stdlib.size);
    memcpy((void*)control->script, script.data, script.size + 1);

    unsigned long max_drains;
    if (read_max_drains(&max_drains) || run_program(start)) {
        fprintf(stderr, "cannot start Python: %s\n", strerror(errno));
        goto cleanup;
    }
    unsigned long drains = 0;
    while (control->execution.status == CAPSULE_PENDING) {
        if (drains == max_drains) {
            fprintf(stderr, "Python is still pending after %lu drains; set BPF_CAPSULE_MAX_DRAINS to permit more\n", drains);
            goto cleanup;
        }
        if (run_program(drain)) {
            fprintf(stderr, "cannot continue Python: %s\n", strerror(errno));
            goto cleanup;
        }
        ++drains;
    }
    size_t output_size = control->output_size < control->output_capacity ? control->output_size : control->output_capacity;
    if (output_size) {
        fwrite((const void*)control->output, 1, output_size, stdout);
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);
    if (control->execution.status != CAPSULE_OK) {
        fprintf(stderr, "Python failed: status=%u code=%lld error=%s\n", control->execution.status, (long long)control->execution.code,
            (const char*)control->error);
        goto cleanup;
    }
    result = 0;

cleanup:
    (void)bpf_capsule_release(&capsule);
    python__destroy(skeleton);
    free(stdlib.data);
    free(script.data);
    return result;
}
