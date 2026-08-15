// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Transformer inference in the kernel — llama2.c, unmodified, through the
// same pipeline.
//
// This is the first program whose whole point is floating point, so it is
// what bpf-soft-float exists for: every multiply-accumulate in every matmul,
// the softmax, the RMS norms and the rotary embeddings all become integer
// work. The host reserves the exact model image in Capsule memory, the
// weights point straight into that image as they would with mmap, and the
// kernel greedily samples token IDs that the host compares against the same
// code compiled natively.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "llama2_ctrl.h"

#include <stdint.h>

// run.c's main() wants argv and a clock; the rest of the file is the model.
#define main llama2_unused_main
#include "run.c"
#undef main

struct llama2_bpf_ctrl lctrl SEC(".data.lctrl");

#define LLAMA_MAX_STEPS 32

int ltokens[LLAMA_MAX_STEPS] SEC(".bss.ltokens");

SEC("syscall")
int llama2_drain() {
    lctrl.capsule = capsule_continue_void(lctrl.capsule.continuation);
    return 0;
}

static void llama2_run_body(void) {
    lctrl.status = LLAMA2_STAGE_STARTED;
    unsigned char* model_image = capsule_memory_pointer(unsigned char, lctrl.model_address);

    Transformer t;
    Config* p = &t.config;
    for (unsigned i = 0; i < sizeof(Config); i++) {
        ((char*)p)[i] = (char)model_image[i];
    }
    int shared_weights = p->vocab_size > 0 ? 1 : 0;
    p->vocab_size = p->vocab_size < 0 ? -p->vocab_size : p->vocab_size;
    lctrl.status = LLAMA2_STAGE_CONFIGURED;

    float* weights_ptr = (float*)(model_image + sizeof(Config));
    memory_map_weights(&t.weights, p, weights_ptr, shared_weights);
    lctrl.status = LLAMA2_STAGE_WEIGHTS_READY;

    malloc_run_state(&t.state, p);
    lctrl.status = LLAMA2_STAGE_STATE_READY;

    // Greedy decoding from the BOS token: no sampler state, so the ids are a
    // pure function of the weights and the arithmetic.
    int token = 1;
    uint64_t sum = 0;
    int steps = (int)lctrl.steps;
    if (steps > LLAMA_MAX_STEPS) {
        steps = LLAMA_MAX_STEPS;
    }
    // The KV caches are seq_len entries deep; past that, positions wrap into
    // garbage. The host clamps the same way, so both sides agree on count.
    if (steps > p->seq_len) {
        steps = p->seq_len;
    }
    for (int pos = 0; pos < steps; pos++) {
        float* logits = forward(&t, token, pos);
        token = sample_argmax(logits, p->vocab_size);
        int at = pos;
        asm volatile("" : "+r"(at));
        ltokens[at & (LLAMA_MAX_STEPS - 1)] = token;
        sum = sum * 1000003ull + (uint64_t)(unsigned)token;
    }
    lctrl.tok_sum = sum;
    lctrl.status = LLAMA2_STAGE_COMPLETE;
}

SEC("syscall")
int llama2_run() {
    lctrl.capsule = capsule_call_void(llama2_run_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
