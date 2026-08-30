// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

struct sqlite_bpf_ctrl {
    uint64_t rows;
    uint64_t checksum;
    int sqlite_rc;
    struct capsule_result capsule;
};
