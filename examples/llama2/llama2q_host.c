// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Quantized llama2.c: stage one v2 checkpoint and compare kernel/native IDs.

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
#include "runq.c"
#undef main
#pragma GCC diagnostic pop

#include "llama2q.skel.h"

static int llama_prepare_model(const unsigned char* model, long size, int* steps) {
    if (size < 256) {
        fprintf(stderr, "model too short for a v2 header\n");
        return -1;
    }
    Config config;
    memcpy(&config, model + 8, sizeof(config));
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
    memcpy(config, model + 8, sizeof(*config));
    unsigned char shared = model[8 + sizeof(*config)];
    int group_size;
    memcpy(&group_size, model + 9 + sizeof(*config), sizeof(group_size));
    GS = group_size;
    memory_map_weights(&transformer->weights, config, model + 256, shared);
    malloc_run_state(&transformer->state, config);
}

#define LLAMA_HOST_NAME "llama2q"
#define LLAMA_SKELETON_TYPE struct llama2q
#define LLAMA_SKELETON_OPEN llama2q__open
#define LLAMA_SKELETON_DESTROY llama2q__destroy
#define LLAMA_CONTROL(skeleton) (&(skeleton)->data_qctrl->qctrl)
#define LLAMA_TOKENS(skeleton) ((skeleton)->bss_qtokens->qtokens)
#define LLAMA_DRAIN_PROGRAM(skeleton) ((skeleton)->progs.llama2q_drain)
#define LLAMA_RUN_PROGRAM(skeleton) ((skeleton)->progs.llama2q_run)

#include "llama2_host_impl.h"
