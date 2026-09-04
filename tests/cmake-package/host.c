// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Links the host library and the generated skeleton; the contract builds this
// program and never runs it.
#include <bpf_capsule_host.h>

#include "smoke.h"

#include "smoke.skel.h"

int main(void) {
    struct smoke* skeleton = smoke__open();
    if (!skeleton) {
        return 1;
    }
    struct bpf_capsule capsule = {0};
    int status = bpf_capsule_release(&capsule);
    smoke__destroy(skeleton);
    return status;
}
