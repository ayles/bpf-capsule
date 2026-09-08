// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Picolibc termination hooks: a Capsule has no process to end.
#include "bpf_capsule.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

// A Capsule has neither a process nor signals: termination ends the current
// fiber. Picolibc supplies exit(), including its atexit handling, and reaches
// this primitive through _exit().
__attribute__((noreturn)) void abort(void) {
    capsule_exit(134);
}

__attribute__((noreturn)) void _exit(int code) {
    capsule_exit(code);
}
