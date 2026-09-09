// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Transformer inference in the kernel: stock llama2.c's Q8 runner reads a
// quantized checkpoint directly from Capsule memory and generates text with
// its own tokenizer and sampler.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "llama2_ctrl.h"

// The guest uses upstream's model, tokenizer and sampler, not its file-backed
// loaders. Declare the tokenizer's libc dependency so the complete upstream
// translation unit parses; internalization removes that unused path.
extern int sscanf(const char*, const char*, ...);

// runq.c's main() wants argv and a clock; the rest of the file is the model.
#define main llama2_unused_main
#include "runq.c"
#undef main

struct llama2_bpf_ctrl qctrl SEC(".data.qctrl");
#define LLAMA2_CONTROL qctrl
#include "llama2_runner.h"

SEC("syscall")
int llama2q_drain(void) {
    qctrl.capsule = capsule_continue_void(qctrl.capsule.continuation);
    return 0;
}

static void llama2q_run_body(void) {
    qctrl.output_size = 0;
    if (!qctrl.model || qctrl.model_size < 256 || !qctrl.tokenizer || !qctrl.output || !qctrl.output_capacity) {
        capsule_exit(1);
    }
    const unsigned char* qmodel_image = qctrl.model;

    // Version 2 checkpoints put magic, version, config, the shared-classifier
    // flag and the group size in a 256-byte header; the group size is global
    // because every quantized tensor is read against it.
    uint32_t magic = 0, version = 0;
    memcpy(&magic, qmodel_image, sizeof(magic));
    memcpy(&version, qmodel_image + sizeof(magic), sizeof(version));
    if (magic != 0x616b3432 || version != 2) {
        capsule_exit(2);
    }
    Transformer t = {0};
    Config* p = &t.config;
    memcpy(p, qmodel_image + 8, sizeof(*p));
    unsigned char shared_classifier = qmodel_image[8 + sizeof(Config)];
    int group_size = 0;
    memcpy(&group_size, qmodel_image + 9 + sizeof(Config), sizeof(group_size));
    if (p->dim <= 0 || (p->dim & 1) || p->hidden_dim <= 0 || p->n_layers <= 0 || p->n_heads <= 0 || p->n_kv_heads <= 0 || p->n_heads % p->n_kv_heads ||
        p->dim % p->n_heads || ((p->dim / p->n_heads) & 1) || p->vocab_size <= 1 || p->seq_len <= 0 || shared_classifier > 1 || group_size <= 0 ||
        p->dim % group_size || p->hidden_dim % group_size) {
        capsule_exit(2);
    }
    GS = group_size;

    // Upstream advances the pointer variable but never mutates the checkpoint.
    memory_map_weights(&t.weights, p, (void*)(qmodel_image + 256), shared_classifier);
    malloc_run_state(&t.state, p);
    llama2_generate(&t);
    free_run_state(&t.state);
    free(t.weights.q_tokens);
    free(t.weights.token_embedding_table);
    free(t.weights.wq);
    free(t.weights.wk);
    free(t.weights.wv);
    free(t.weights.wo);
    free(t.weights.w1);
    free(t.weights.w2);
    free(t.weights.w3);
    if (t.weights.wcls != t.weights.q_tokens) {
        free(t.weights.wcls);
    }
}

SEC("syscall")
int llama2q_run(void) {
    qctrl.capsule = capsule_call_void(llama2q_run_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
