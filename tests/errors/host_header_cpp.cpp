// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <cstring>
#include <cstdio>
#include <type_traits>

#include "bpf_capsule_host.h"

static_assert(std::is_standard_layout_v<capsule_result>);
static_assert(sizeof(capsule_result) == 24);
static_assert(sizeof(bpf_capsule_config) == 24);

int main() {
    bpf_capsule_config config{};
    config.fiber_count = 1;
    config.heap_bytes = 2u * 1024u * 1024u;
    if (std::strcmp(bpf_capsule_status_string(CAPSULE_PENDING), "pending") || config.reserved_bytes != 0) {
        return 1;
    }
    std::puts("HOST-HEADER-CPP-PASS");
    return 0;
}
