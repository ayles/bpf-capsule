// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Transformer inference in the kernel: stock llama2.c reads weights directly
// from Capsule memory and runs its floating-point model through soft-float.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <limits.h>

#include "bpf_capsule.h"
#include "llama2_ctrl.h"

// The guest uses upstream's model and argmax code, not its file-backed
// tokenizer. Declare the tokenizer's libc dependency so the complete upstream
// translation unit parses; internalization removes that unused path.
extern int sscanf(const char*, const char*, ...);

// run.c's main() wants argv and a clock; the rest of the file is the model.
#define main llama2_unused_main
#include "run.c"
#undef main

struct llama2_bpf_ctrl lctrl SEC(".data.lctrl");

SEC("syscall")
int llama2_drain(void) {
    lctrl.capsule = capsule_continue_void(lctrl.capsule.continuation);
    return 0;
}

static void llama2_run_body(void) {
    lctrl.generated_tokens = 0;
    if (!lctrl.model || lctrl.model_size < sizeof(Config) || !lctrl.requested_tokens) {
        return;
    }
    const unsigned char* model_image = lctrl.model;

    Transformer t = {0};
    Config* p = &t.config;
    memcpy(p, model_image, sizeof(*p));
    if (p->dim <= 0 || (p->dim & 1) || p->hidden_dim <= 0 || p->n_layers <= 0 || p->n_heads <= 0 || p->n_kv_heads <= 0 || p->n_heads % p->n_kv_heads ||
        p->dim % p->n_heads || ((p->dim / p->n_heads) & 1) || p->vocab_size == INT_MIN || p->seq_len <= 0) {
        return;
    }
    int shared_weights = p->vocab_size > 0;
    p->vocab_size = p->vocab_size < 0 ? -p->vocab_size : p->vocab_size;
    if (p->vocab_size <= 1) {
        return;
    }

    float* weights_ptr = (float*)(model_image + sizeof(Config));
    memory_map_weights(&t.weights, p, weights_ptr, shared_weights);
    malloc_run_state(&t.state, p);

    // Greedy decoding from the BOS token: no sampler state, so the ids are a
    // pure function of the weights and the arithmetic.
    int token = 1;
    int steps = (int)lctrl.requested_tokens;
    if (steps > LLAMA2_MAX_TOKENS) {
        steps = LLAMA2_MAX_TOKENS;
    }
    // The KV caches are seq_len entries deep; past that, positions wrap into
    // garbage. The host clamps the same way, so both sides agree on count.
    if (steps > p->seq_len) {
        steps = p->seq_len;
    }
    for (int pos = 0; pos < steps; pos++) {
        float* logits = forward(&t, token, pos);
        token = sample_argmax(logits, p->vocab_size);
        // Keep the mask in emitted BPF so the verifier can see the map bound
        // after the managed loop has been lowered into continuations.
        int at = pos;
        asm volatile("" : "+r"(at));
        lctrl.tokens[at & (LLAMA2_MAX_TOKENS - 1)] = token;
    }
    free_run_state(&t.state);
    lctrl.generated_tokens = (unsigned int)steps;
}

SEC("syscall")
int llama2_run(void) {
    lctrl.capsule = capsule_call_void(llama2_run_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
