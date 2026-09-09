// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Transformer inference in the kernel: stock llama2.c reads weights directly
// from Capsule memory, runs its floating-point model through soft-float, and
// generates text with its own tokenizer and sampler.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <limits.h>

#include "bpf_capsule.h"
#include "llama2_ctrl.h"

// The guest uses upstream's model, tokenizer and sampler, not its file-backed
// loaders. Declare the tokenizer's libc dependency so the complete upstream
// translation unit parses; internalization removes that unused path.
extern int sscanf(const char*, const char*, ...);

// run.c's main() wants argv and a clock; the rest of the file is the model.
#define main llama2_unused_main
#include "run.c"
#undef main

struct llama2_bpf_ctrl lctrl SEC(".data.lctrl");
#define LLAMA2_CONTROL lctrl
#include "llama2_runner.h"

SEC("syscall")
int llama2_drain(void) {
    lctrl.capsule = capsule_continue_void(lctrl.capsule.continuation);
    return 0;
}

static void llama2_run_body(void) {
    lctrl.output_size = 0;
    if (!lctrl.model || lctrl.model_size < sizeof(Config) || !lctrl.tokenizer || !lctrl.output || !lctrl.output_capacity) {
        capsule_exit(1);
    }
    const unsigned char* model_image = lctrl.model;

    Transformer t = {0};
    Config* p = &t.config;
    memcpy(p, model_image, sizeof(*p));
    if (p->dim <= 0 || (p->dim & 1) || p->hidden_dim <= 0 || p->n_layers <= 0 || p->n_heads <= 0 || p->n_kv_heads <= 0 || p->n_heads % p->n_kv_heads ||
        p->dim % p->n_heads || ((p->dim / p->n_heads) & 1) || p->vocab_size == INT_MIN || p->seq_len <= 0) {
        capsule_exit(2);
    }
    int shared_weights = p->vocab_size > 0;
    p->vocab_size = p->vocab_size < 0 ? -p->vocab_size : p->vocab_size;
    if (p->vocab_size <= 1) {
        capsule_exit(2);
    }

    float* weights_ptr = (float*)(model_image + sizeof(Config));
    memory_map_weights(&t.weights, p, weights_ptr, shared_weights);
    malloc_run_state(&t.state, p);
    llama2_generate(&t);
    free_run_state(&t.state);
}

SEC("syscall")
int llama2_run(void) {
    lctrl.capsule = capsule_call_void(llama2_run_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
