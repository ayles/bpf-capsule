// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Included by the fp32 and q8 hosts after their upstream runtime and skeleton.

#define LLAMA_HOST_MAX_STEPS 32
#define LLAMA_HOST_MAX_DRAINS 2000000
#define LLAMA_HOST_HEAP_BYTES (4ull << 20)

static uint64_t llama_program_run_time(int program_fd) {
    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    return bpf_prog_get_info_by_fd(program_fd, &info, &info_length) ? 0 : info.run_time_ns;
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s MODEL [steps]\n", LLAMA_HOST_NAME);
        return 1;
    }

    long requested_steps = 16;
    if (argc == 3) {
        char* end = NULL;
        requested_steps = strtol(argv[2], &end, 10);
        if (!end || *end || requested_steps < 1) {
            fprintf(stderr, "steps must be a positive integer\n");
            return 1;
        }
    }
    int steps = requested_steps > LLAMA_HOST_MAX_STEPS ? LLAMA_HOST_MAX_STEPS : (int)requested_steps;

    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        perror(argv[1]);
        return 1;
    }
    if (fseek(file, 0, SEEK_END)) {
        perror("model size");
        fclose(file);
        return 1;
    }
    long model_size = ftell(file);
    if (model_size < 0) {
        perror("model size");
        fclose(file);
        return 1;
    }
    rewind(file);
    unsigned char* model = malloc((size_t)model_size);
    if (!model) {
        fprintf(stderr, "out of memory for %ld-byte model\n", model_size);
        fclose(file);
        return 1;
    }
    if (fread(model, 1, (size_t)model_size, file) != (size_t)model_size) {
        fprintf(stderr, "short read\n");
        fclose(file);
        free(model);
        return 1;
    }
    fclose(file);
    if (llama_prepare_model(model, model_size, &steps)) {
        free(model);
        return 1;
    }

    LLAMA_SKELETON_TYPE* skeleton = LLAMA_SKELETON_OPEN();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        free(model);
        return 1;
    }
    uint64_t model_bytes = (uint64_t)model_size;
    if (model_bytes > UINT64_MAX - 15u) {
        fprintf(stderr, "model is too large for Capsule memory\n");
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    uint64_t reserved_bytes = (model_bytes + 15u) & ~15ull;
    if (reserved_bytes > UINT64_MAX - LLAMA_HOST_HEAP_BYTES) {
        fprintf(stderr, "model is too large for Capsule memory\n");
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = reserved_bytes + LLAMA_HOST_HEAP_BYTES,
        .reserved_bytes = model_bytes,
    };
    if (bpf_capsule_configure(skeleton->obj, capsule_config) || bpf_object__load_skeleton(skeleton->skeleton) ||
        bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "load failed\n");
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    struct bpf_object* object = skeleton->obj;
    volatile struct llama2_bpf_ctrl* control = LLAMA_CONTROL(skeleton);
    int* kernel_tokens = LLAMA_TOKENS(skeleton);
    if ((size_t)steps > sizeof(LLAMA_TOKENS(skeleton)) / sizeof(*kernel_tokens)) {
        fprintf(stderr, "steps exceed the %s token buffer\n", LLAMA_HOST_NAME);
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    int drain_fd = bpf_program__fd(LLAMA_DRAIN_PROGRAM(skeleton));
    int run_fd = bpf_program__fd(LLAMA_RUN_PROGRAM(skeleton));
    if (drain_fd < 0 || run_fd < 0) {
        fprintf(stderr, "missing %s BPF program\n", LLAMA_HOST_NAME);
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};

    struct bpf_capsule_memory memory;
    if (bpf_capsule_memory(object, &memory)) {
        fprintf(stderr, "cannot map Capsule memory: %s\n", strerror(errno));
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    uint64_t model_address = bpf_capsule_memory_reserved_start(&memory);
    if (bpf_capsule_memory_write(&memory, model_address, model, (size_t)model_size)) {
        fprintf(stderr, "cannot stage model: %s\n", strerror(errno));
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    control->model_address = model_address;
    control->steps = (uint64_t)steps;

    // Kernel-side BPF runtime accounting: with stats enabled, run_time_ns
    // accumulates each program's real execution nanoseconds — never syscall
    // wall time. The host memory copy above is outside the interval.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    uint64_t kernel_before = llama_program_run_time(run_fd) + llama_program_run_time(drain_fd);
    int run_error = bpf_prog_test_run_opts(run_fd, &options);
    unsigned long run_drains = 0;
    while (!run_error && control->capsule.status == CAPSULE_PENDING) {
        if (run_drains == LLAMA_HOST_MAX_DRAINS) {
            fprintf(stderr, "gave up after %lu drains: computation still pending\n", run_drains);
            errno = ETIMEDOUT;
            run_error = -1;
            break;
        }
        run_error = bpf_prog_test_run_opts(drain_fd, &options);
        if (!run_error) {
            run_drains++;
        }
    }
    if (run_error || control->capsule.status != CAPSULE_OK) {
        if (!run_error && control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
            fprintf(stderr, "run failed: capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
        } else if (!run_error && control->capsule.status == CAPSULE_EXITED) {
            fprintf(stderr, "run failed: guest exited with code %lld\n", (long long)control->capsule.code);
        } else {
            fprintf(
                stderr, "run failed: %s; capsule status=%s\n", run_error ? strerror(errno) : "managed computation did not return",
                bpf_capsule_status_string(control->capsule.status)
            );
        }
        LLAMA_SKELETON_DESTROY(skeleton);
        free(model);
        return 1;
    }
    uint64_t kernel_ns = llama_program_run_time(run_fd) + llama_program_run_time(drain_fd) - kernel_before;
    if (stats_fd >= 0) {
        close(stats_fd);
    }

    // Thread CPU time is the native analog of the kernel's run_time_ns.
    struct timespec begin;
    struct timespec end;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begin);
    Transformer transformer;
    llama_initialize_native(&transformer, model);
    Config* config = &transformer.config;
    int host_tokens[LLAMA_HOST_MAX_STEPS];
    uint64_t host_sum = 0;
    int token = 1;
    for (int position = 0; position < steps; ++position) {
        float* logits = forward(&transformer, token, position);
        token = sample_argmax(logits, config->vocab_size);
        host_tokens[position] = token;
        host_sum = host_sum * 1000003ull + (uint64_t)(unsigned int)token;
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
    uint64_t native_ns = (uint64_t)(end.tv_sec - begin.tv_sec) * 1000000000ull + (uint64_t)(end.tv_nsec - begin.tv_nsec);

    printf("tokens:");
    for (int index = 0; index < steps; ++index) {
        printf(" %d", kernel_tokens[index]);
    }
    printf("\n");
    if (stats_fd >= 0) {
        fprintf(
            stderr, "kernel execution: %llu ns, native execution: %llu ns for %d tokens\n", (unsigned long long)kernel_ns, (unsigned long long)native_ns, steps
        );
    } else {
        fprintf(stderr, "native execution: %llu ns for %d tokens\n", (unsigned long long)native_ns, steps);
    }
    fprintf(stderr, "continuation drains: %lu\n", run_drains);

    // The same weights through the same argmax sampler must pick the same
    // token IDs; any divergence is a compiler bug, not noise.
    int pass = control->status == LLAMA2_STAGE_COMPLETE && control->capsule.status == CAPSULE_OK && control->tok_sum == host_sum &&
        !memcmp(kernel_tokens, host_tokens, (size_t)steps * sizeof(*host_tokens));
    if (!pass) {
        fprintf(
            stderr, "kernel and native disagree: kernel status=%llu tok_sum=%llx, native tok_sum=%llx\n", (unsigned long long)control->status,
            (unsigned long long)control->tok_sum, (unsigned long long)host_sum
        );
        fprintf(stderr, "tokens native:");
        for (int index = 0; index < steps; ++index) {
            fprintf(stderr, " %d", host_tokens[index]);
        }
        fprintf(stderr, "\n");
    }
    LLAMA_SKELETON_DESTROY(skeleton);
    free(model);
    return pass ? 0 : 1;
}

#undef LLAMA_HOST_MAX_STEPS
#undef LLAMA_HOST_MAX_DRAINS
#undef LLAMA_HOST_HEAP_BYTES
