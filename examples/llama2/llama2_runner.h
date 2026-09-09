// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The guest half shared by the floating-point and the quantized runner: the
// tokenizer loaded from the staged bytes, generation through upstream's
// generate(), and its stdout collected in the output buffer. Include after
// run.c or runq.c and after the control block is defined.
#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// generate() prints through printf; the C library's stdout reaches write().
// Standard output lands in the buffer, standard error is dropped: its only
// content is upstream's tokens-per-second line, meaningless without a clock.
ssize_t write(int fd, const void* data, size_t size) {
    if (fd == STDERR_FILENO) {
        return (ssize_t)size;
    }
    if (fd != STDOUT_FILENO) {
        errno = EBADF;
        return -1;
    }
    size_t begin = LLAMA2_CONTROL.output_size;
    size_t available = begin < LLAMA2_CONTROL.output_capacity ? LLAMA2_CONTROL.output_capacity - begin : 0;
    size_t copied = size < available ? size : available;
    memcpy(LLAMA2_CONTROL.output + begin, data, copied);
    LLAMA2_CONTROL.output_size += size;
    return (ssize_t)size;
}

// build_tokenizer() as written in run.c, reading the same file format from
// memory instead of a path. Returns 0, or -1 for a truncated image.
static int llama2_build_tokenizer(Tokenizer* t, const unsigned char* image, size_t size, int vocab_size) {
    t->vocab_size = vocab_size;
    t->vocab = (char**)malloc(vocab_size * sizeof(char*));
    t->vocab_scores = (float*)malloc(vocab_size * sizeof(float));
    t->sorted_vocab = NULL; // initialized lazily
    if (!t->vocab || !t->vocab_scores) {
        return -1;
    }
    for (int i = 0; i < 256; i++) {
        t->byte_pieces[i * 2] = (unsigned char)i;
        t->byte_pieces[i * 2 + 1] = '\0';
    }
    size_t cursor = 0;
    if (size < sizeof(int)) {
        return -1;
    }
    memcpy(&t->max_token_length, image, sizeof(int));
    cursor += sizeof(int);
    for (int i = 0; i < vocab_size; i++) {
        int len;
        if (size - cursor < sizeof(float) + sizeof(int)) {
            return -1;
        }
        memcpy(t->vocab_scores + i, image + cursor, sizeof(float));
        cursor += sizeof(float);
        memcpy(&len, image + cursor, sizeof(int));
        cursor += sizeof(int);
        if (len < 0 || (size_t)len > size - cursor) {
            return -1;
        }
        t->vocab[i] = (char*)malloc(len + 1);
        if (!t->vocab[i]) {
            return -1;
        }
        memcpy(t->vocab[i], image + cursor, (size_t)len);
        t->vocab[i][len] = '\0';
        cursor += (size_t)len;
    }
    return 0;
}

// The prompt lives in the control map, which managed code may not point
// into across a suspension; generate() receives a copy in Capsule memory.
static char llama2_prompt[LLAMA2_PROMPT_MAX];

// run.c's main() after the transformer is built: the tokenizer, the sampler,
// and generate() with the staged prompt.
static void llama2_generate(Transformer* transformer) {
    LLAMA2_CONTROL.output_size = 0;
    for (size_t i = 0; i < LLAMA2_PROMPT_MAX; i++) {
        llama2_prompt[i] = LLAMA2_CONTROL.prompt[i];
    }
    int steps = LLAMA2_CONTROL.steps;
    if (steps == 0 || steps > transformer->config.seq_len) {
        steps = transformer->config.seq_len;
    }
    Tokenizer tokenizer;
    if (llama2_build_tokenizer(&tokenizer, LLAMA2_CONTROL.tokenizer, LLAMA2_CONTROL.tokenizer_size, transformer->config.vocab_size)) {
        capsule_exit(3);
    }
    Sampler sampler;
    build_sampler(&sampler, transformer->config.vocab_size, LLAMA2_CONTROL.temperature, LLAMA2_CONTROL.topp, LLAMA2_CONTROL.seed);
    generate(transformer, &tokenizer, &sampler, LLAMA2_CONTROL.has_prompt ? llama2_prompt : NULL, steps);
    free_sampler(&sampler);
    free_tokenizer(&tokenizer);
}
