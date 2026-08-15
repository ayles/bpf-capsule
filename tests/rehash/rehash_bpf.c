// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "rehash_test.h"
#include <stdio.h>

struct resize_state {
    unsigned int size;
    unsigned int calls;
};

volatile struct rehash_test_result rehash_output SEC(".data.rehash");

extern void* malloc(unsigned long size);
extern void free(void* pointer);

// Any managed call may return to the capsule loop before its caller resumes.
// Touch another field so the call is observable without changing `size`.
__attribute__((noinline)) static void observe_resize(struct resize_state* state, unsigned int old_size, unsigned int new_size) {
    (void)old_size;
    (void)new_size;
    state->calls++;
}

typedef void (*observe_function)(struct resize_state*, unsigned int, unsigned int);
static observe_function volatile selected_observer = observe_resize;

__attribute__((noinline)) static struct resize_state* resize_allocation(struct resize_state* state) {
    return state;
}

typedef struct resize_state* (*resize_function)(struct resize_state*);
static resize_function volatile selected_resize = resize_allocation;

__attribute__((noinline)) static struct resize_state* next_state(struct resize_state* state) {
    if (!state->size) {
        return 0;
    }

    unsigned int old_size = state->size;
    struct resize_state* resized = selected_resize(state);
    if (!resized) {
        return 0;
    }
    unsigned int new_size = old_size + 1;
    state->size = new_size;

    // `old_size` is an SSA snapshot of mutable memory. It must survive the
    // managed call; reloading state->size here observes the later store and
    // silently turns a growth into a no-op. Lua's string-table resize exposed
    // exactly this lowering bug.
    if (new_size > old_size) {
        selected_observer(resized, old_size, new_size);
        rehash_output.grew++;
    }
    rehash_output.old_size = old_size;
    rehash_output.new_size = state->size;
    state->size = old_size - 1;
    return resized;
}

typedef struct resize_state* (*next_function)(struct resize_state*);
static next_function volatile selected_next = next_state;
static volatile unsigned int empty_demotion_visits;

__attribute__((noinline)) static int probe_cursor(const char* cursor) {
    FILE* file = fopen(cursor, "r");
    if (!file) {
        return 0;
    }
    fclose(file);
    return 1;
}

// Reproduce the precondition that originally made this bug module-size and
// layout dependent. A loop-carried PHI crosses two managed calls; demoting it
// can make a second queued demotion use-empty. LLVM then legitimately returns
// no spill slot for that second value.
__attribute__((noinline)) static unsigned int exercise_empty_demotion(struct resize_state* state) {
    empty_demotion_visits = 0;
    struct resize_state* cursor = selected_next(state);
    while (cursor) {
        // O2 proves the freestanding probe false but retains its externally
        // visible fopen call. The now-unused filename PHI is the shape that
        // exposed the spill-slot bookkeeping bug in Lua's searchpath.
        if (probe_cursor((const char*)cursor)) {
            empty_demotion_visits += 1000;
        }
        empty_demotion_visits++;
        cursor = selected_next(state);
    }
    return empty_demotion_visits;
}

typedef unsigned int (*exercise_function)(struct resize_state*);
static exercise_function volatile selected_exercise = exercise_empty_demotion;

__attribute__((noinline)) static void resize_state(void) {
    struct resize_state* state = malloc(sizeof(*state));
    if (!state) {
        rehash_output.failures = 1;
        return;
    }

    state->size = 2;
    state->calls = 0;
    rehash_output.poison_calls = selected_exercise(state);
    rehash_output.calls = state->calls;
    free(state);
}

SEC("syscall")
int rehash_test_run(void) {
    rehash_output.capsule = capsule_call_void(resize_state);
    return 0;
}

SEC("syscall")
int rehash_test_continue(void) {
    rehash_output.capsule = capsule_continue_void(rehash_output.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
