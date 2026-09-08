// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Attach one CPython packet observer per Capsule fiber and print its events.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"
#include "python_xdp_ctrl.h"
#include "python_xdp.skel.h"

#define PYTHON_HEAP_BYTES_PER_FIBER (32u << 20)

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
    int written = snprintf(path, PATH_MAX, "%s/share/bpf-capsule/python-xdp/stdlib.pack", executable);
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

static int configure_capsule(struct bpf_capsule* capsule, struct bpf_object* object, size_t input_bytes) {
    int count = libbpf_num_possible_cpus();
    if (count < 1) {
        errno = count < 0 ? -count : EINVAL;
        return -1;
    }
    if ((uint64_t)count > (UINT64_MAX - input_bytes) / PYTHON_HEAP_BYTES_PER_FIBER) {
        errno = EOVERFLOW;
        return -1;
    }
    return bpf_capsule_configure(capsule, object,
        (struct bpf_capsule_config){
            .fiber_count = (unsigned int)count,
            .heap_bytes = (uint64_t)count * PYTHON_HEAP_BYTES_PER_FIBER + input_bytes,
        });
}

static int read_max_drains(unsigned long fallback, unsigned long* result) {
    const char* text = getenv("BPF_CAPSULE_MAX_DRAINS");
    *result = fallback;
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

static int initialize_python(struct bpf_object* object, volatile struct python_xdp_ctrl* control, unsigned long* completed_drains) {
    struct bpf_program* initialize = bpf_object__find_program_by_name(object, "python_xdp_initialize");
    struct bpf_program* drain = bpf_object__find_program_by_name(object, "python_xdp_initialize_drain");
    if (!initialize || !drain) {
        errno = ENOENT;
        return -1;
    }
    int possible_cpus = libbpf_num_possible_cpus();
    if (possible_cpus < 1) {
        errno = possible_cpus < 0 ? -possible_cpus : EINVAL;
        return -1;
    }
    // Initialization creates one interpreter per fiber. A continuation per
    // possible CPU is a deliberately finite default; larger experiments may
    // raise it through BPF_CAPSULE_MAX_DRAINS.
    unsigned long default_drains = (unsigned long)possible_cpus;
    unsigned long max_drains;
    if (read_max_drains(default_drains, &max_drains) || run_program(initialize)) {
        return -1;
    }
    unsigned long drains = 0;
    while (control->initialization.status == CAPSULE_PENDING) {
        if (drains == max_drains) {
            fprintf(stderr, "initialization is still pending after %lu drains; set BPF_CAPSULE_MAX_DRAINS to permit more\n", drains);
            errno = ETIMEDOUT;
            return -1;
        }
        if (run_program(drain)) {
            return -1;
        }
        ++drains;
    }
    if (control->initialization.status != CAPSULE_OK) {
        fprintf(stderr, "Python initialization stopped: status=%u code=%lld error=%s\n", control->initialization.status,
            (long long)control->initialization.code, (const char*)control->error);
        errno = EPROTO;
        return -1;
    }
    *completed_drains = drains;
    return 0;
}

static volatile sig_atomic_t stop_requested;
static unsigned long event_limit;
static unsigned long events_seen;

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int print_event(void* context, void* data, size_t size) {
    (void)context;
    fwrite(data, 1, size, stdout);
    fflush(stdout);
    if (event_limit && ++events_seen >= event_limit) {
        stop_requested = 1;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: python-xdp OBSERVER INTERFACE [EVENTS]\n");
        return 2;
    }
    if (argc == 4) {
        char* end = NULL;
        errno = 0;
        event_limit = strtoul(argv[3], &end, 10);
        if (errno || *end || !event_limit) {
            fprintf(stderr, "EVENTS must be a positive integer\n");
            return 2;
        }
    }
    unsigned int ifindex = if_nametoindex(argv[2]);
    if (!ifindex) {
        fprintf(stderr, "unknown interface: %s\n", argv[2]);
        return 1;
    }

    char library_path[PATH_MAX];
    struct file_contents script = {0};
    struct file_contents stdlib = {0};
    if (stdlib_path(argv[0], library_path) || read_file(argv[1], 1, &script) || read_file(library_path, 0, &stdlib)) {
        fprintf(stderr, "cannot read Python XDP inputs: %s\n", strerror(errno));
        return 1;
    }
    if (stdlib.size > SIZE_MAX - script.size - 1) {
        fprintf(stderr, "Python XDP inputs are too large\n");
        free(stdlib.data);
        free(script.data);
        return 1;
    }

    int result = 1;
    int poll_error = 0;
    int stats_fd = -1;
    struct python_xdp* skeleton = python_xdp__open();
    struct bpf_capsule capsule = {0};
    struct ring_buffer* ring = NULL;
    struct bpf_link* link = NULL;
    struct bpf_object* object = skeleton ? skeleton->obj : NULL;
    if (!object) {
        fprintf(stderr, "cannot open Python XDP object\n");
        goto cleanup;
    }
    volatile struct python_xdp_ctrl* control = &skeleton->data_python_xdp->python_xdp_control;
    size_t input_bytes = stdlib.size + script.size + 1;
    if (configure_capsule(&capsule, object, input_bytes)) {
        fprintf(stderr, "cannot configure Python XDP observer: %s\n", strerror(errno));
        goto cleanup;
    }
    if (bpf_object__load_skeleton(skeleton->skeleton)) {
        fprintf(stderr, "cannot load Python XDP observer: %s\n", strerror(errno));
        goto cleanup;
    }
    if (bpf_capsule_attach_freplace(&capsule, skeleton->skeleton->data, skeleton->skeleton->data_sz)) {
        fprintf(stderr, "cannot attach Python XDP freplace programs: %s\n", strerror(errno));
        goto cleanup;
    }
    if (bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "cannot initialize Python XDP memory: %s\n", strerror(errno));
        goto cleanup;
    }
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
    if (!control->stdlib_image || !control->script) {
        fprintf(stderr, "cannot allocate Python XDP inputs: %s\n", strerror(errno));
        goto cleanup;
    }
    memcpy((void*)control->stdlib_image, stdlib.data, stdlib.size);
    memcpy((void*)control->script, script.data, script.size + 1);

    unsigned long initialization_drains;
    if (initialize_python(object, control, &initialization_drains)) {
        fprintf(stderr, "cannot initialize Python XDP observer: %s\n", strerror(errno));
        goto cleanup;
    }
    fprintf(stderr, "initialization drains: %lu\n", initialization_drains);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "python_xdp_observe");
    struct bpf_map* events = bpf_object__find_map_by_name(object, "python_xdp_events");
    if (!program || !events) {
        errno = ENOENT;
        fprintf(stderr, "cannot find Python XDP programs and maps\n");
        goto cleanup;
    }
    ring = ring_buffer__new(bpf_map__fd(events), print_event, NULL, NULL);
    if (!ring) {
        fprintf(stderr, "cannot open Python XDP event ring: %s\n", strerror(errno));
        goto cleanup;
    }
    long ring_error = libbpf_get_error(ring);
    if (ring_error) {
        ring = NULL;
        fprintf(stderr, "cannot open Python XDP event ring: %s\n", strerror((int)-ring_error));
        goto cleanup;
    }
    stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (stats_fd < 0) {
        fprintf(stderr, "cannot enable kernel runtime accounting: %s\n", strerror(errno));
    }
    link = bpf_program__attach_xdp(program, ifindex);
    long link_error = libbpf_get_error(link);
    if (link_error) {
        link = NULL;
        fprintf(stderr, "cannot attach Python XDP observer to %s: %s\n", argv[2], strerror((int)-link_error));
        goto cleanup;
    }

    struct sigaction action = {.sa_handler = request_stop};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    fprintf(stderr, "observing live traffic on %s; %s detaches\n", argv[2], event_limit ? "the event count" : "Ctrl-C");
    while (!stop_requested && !__atomic_load_n(&control->faulted, __ATOMIC_ACQUIRE)) {
        poll_error = ring_buffer__poll(ring, 250);
        if (poll_error < 0 && poll_error != -EINTR) {
            fprintf(stderr, "ring-buffer poll failed: %s\n", strerror(-poll_error));
            break;
        }
    }

    bpf_link__destroy(link);
    link = NULL;
    // A fault or signal may stop polling with the last output still queued.
    int drain_error = ring_buffer__consume(ring);
    if (drain_error < 0) {
        fprintf(stderr, "ring-buffer drain failed: %s\n", strerror(-drain_error));
        poll_error = drain_error;
    }

    struct bpf_prog_info info = {0};
    unsigned int info_length = sizeof(info);
    if (stats_fd >= 0 && !bpf_prog_get_info_by_fd(bpf_program__fd(program), &info, &info_length) && info.run_cnt) {
        fprintf(stderr, "kernel execution: avg %llu ns per packet over %llu packets\n", (unsigned long long)(info.run_time_ns / info.run_cnt),
            (unsigned long long)info.run_cnt);
    }
    result = (poll_error < 0 && poll_error != -EINTR) || __atomic_load_n(&control->faulted, __ATOMIC_ACQUIRE);

cleanup:
    if (link) {
        bpf_link__destroy(link);
    }
    if (ring) {
        ring_buffer__free(ring);
    }
    if (stats_fd >= 0) {
        close(stats_fd);
    }
    free(stdlib.data);
    free(script.data);
    (void)bpf_capsule_release(&capsule);
    python_xdp__destroy(skeleton);
    return result;
}
