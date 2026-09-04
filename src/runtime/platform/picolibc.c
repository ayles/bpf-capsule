// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Picolibc platform state that belongs to a Capsule fiber.
#include "bpf_capsule.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

// A continuation belongs to a Capsule fiber, not to the CPU on which one
// physical step happens to execute. Keep errno with that fiber so concurrent
// calls and cross-CPU resumes cannot observe each other's library failures.
static int fs_errno[BPF_CAPSULE_MAX_FIBERS];

int* __bpf_capsule_errno_location(void) {
    unsigned int fiber = capsule_fiber_index();
    if (fiber >= BPF_CAPSULE_MAX_FIBERS) {
        __bpf_capsule_exit(CAPSULE_ERROR_TRAP);
    }
    return &fs_errno[fiber];
}

// A Capsule has neither a process nor signals: termination ends the current
// fiber. Picolibc supplies exit(), including its atexit handling, and reaches
// this primitive through _exit().
__attribute__((noreturn)) void abort(void) {
    capsule_exit(134);
}

__attribute__((noreturn)) void _exit(int code) {
    capsule_exit(code);
}
