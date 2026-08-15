// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Float llama2.c: stage one checkpoint and compare kernel/native token IDs.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "llama2_ctrl.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-variable"
#define main llama2_unused_main
#include "run.c"
#undef main
#pragma GCC diagnostic pop

#include "llama2.skel.h"

static int llama_prepare_model(const unsigned char* model, long size, int* steps) {
    if (size < (long)sizeof(Config)) {
        fprintf(stderr, "model too short\n");
        return -1;
    }
    Config config;
    memcpy(&config, model, sizeof(config));
    if (config.seq_len < 1) {
        fprintf(stderr, "model has an invalid context length\n");
        return -1;
    }
    if (*steps > config.seq_len) {
        *steps = config.seq_len;
    }
    return 0;
}

static void llama_initialize_native(Transformer* transformer, unsigned char* model) {
    Config* config = &transformer->config;
    memcpy(config, model, sizeof(*config));
    int shared = config->vocab_size > 0;
    config->vocab_size = abs(config->vocab_size);
    memory_map_weights(&transformer->weights, config, (float*)(model + sizeof(*config)), shared);
    malloc_run_state(&transformer->state, config);
}

#define LLAMA_HOST_NAME "llama2"
#define LLAMA_SKELETON_TYPE struct llama2
#define LLAMA_SKELETON_OPEN llama2__open
#define LLAMA_SKELETON_DESTROY llama2__destroy
#define LLAMA_CONTROL(skeleton) (&(skeleton)->data_lctrl->lctrl)
#define LLAMA_TOKENS(skeleton) ((skeleton)->bss_ltokens->ltokens)
#define LLAMA_DRAIN_PROGRAM(skeleton) ((skeleton)->progs.llama2_drain)
#define LLAMA_RUN_PROGRAM(skeleton) ((skeleton)->progs.llama2_run)

#include "llama2_host_impl.h"
