// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf_capsule_host.h>

int main(void) {
    struct bpf_capsule capsule = {0};
    return bpf_capsule_release(&capsule);
}
