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
#include "runq.c"
#undef main

struct llama2_bpf_ctrl qctrl SEC(".data.qctrl");

#define QMAX_STEPS 32

int qtokens[QMAX_STEPS] SEC(".bss.qtokens");

SEC("syscall")
int llama2q_drain() {
    qctrl.capsule = capsule_continue_void(qctrl.capsule.continuation);
    return 0;
}

static void llama2q_run_body(void) {
    qctrl.status = LLAMA2_STAGE_STARTED;
    unsigned char* qmodel_image = capsule_memory_pointer(unsigned char, qctrl.model_address);

    // Version 2 checkpoints put magic, version, config, the shared-classifier
    // flag and the group size in a 256-byte header; the group size is global
    // because every quantized tensor is read against it.
    Transformer t;
    Config* p = &t.config;
    for (unsigned i = 0; i < sizeof(Config); i++) {
        ((char*)p)[i] = (char)qmodel_image[8 + i];
    }
    unsigned char shared_classifier = qmodel_image[8 + sizeof(Config)];
    int group_size;
    for (unsigned i = 0; i < sizeof(int); i++) {
        ((char*)&group_size)[i] = (char)qmodel_image[9 + sizeof(Config) + i];
    }
    GS = group_size;
    qctrl.status = LLAMA2_STAGE_CONFIGURED;

    memory_map_weights(&t.weights, p, qmodel_image + 256, shared_classifier);
    qctrl.status = LLAMA2_STAGE_WEIGHTS_READY;

    malloc_run_state(&t.state, p);
    qctrl.status = LLAMA2_STAGE_STATE_READY;

    // Greedy decoding from the BOS token: no sampler state, so the ids are a
    // pure function of the weights and the arithmetic.
    int token = 1;
    uint64_t sum = 0;
    int steps = (int)qctrl.steps;
    if (steps > QMAX_STEPS) {
        steps = QMAX_STEPS;
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
        qtokens[at & (QMAX_STEPS - 1)] = token;
        sum = sum * 1000003ull + (uint64_t)(unsigned)token;
    }
    qctrl.tok_sum = sum;
    qctrl.status = LLAMA2_STAGE_COMPLETE;
}

SEC("syscall")
int llama2q_run() {
    qctrl.capsule = capsule_call_void(llama2q_run_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
